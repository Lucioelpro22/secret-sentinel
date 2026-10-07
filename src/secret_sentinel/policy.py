"""Explicit bounded JSON policies and expiring, exact finding suppressions."""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import NoReturn, cast

from .file_reader import read_scan_file
from .models import ScanConfig, ScanReport, Severity, SuppressedFinding
from .redaction import sanitize_metadata
from .rules import RULES


class PolicyError(ValueError):
    """A policy was unreadable, malformed, unsafe, or expired."""


@dataclass(frozen=True, slots=True)
class Suppression:
    rule_id: str
    path: str
    fingerprint: str
    reason: str
    expires: str
    line: int | None = None


@dataclass(frozen=True, slots=True)
class Policy:
    config: ScanConfig
    fail_on: Severity
    suppressions: tuple[Suppression, ...]


def _reject() -> NoReturn:
    raise PolicyError("policy is invalid or cannot be safely read")


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _reject()
        result[key] = value
    return result


def _keys(value: object, allowed: set[str], required: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) - allowed or required - set(value):
        _reject()
    return cast(dict[str, object], value)


def _positive(value: object) -> int:
    if type(value) is not int or value <= 0:
        _reject()
    return cast(int, value)


def _path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or any(char in value for char in "\\*?[]:")
        or any(part in {"", ".", ".."} for part in value.split("/"))
        or any(unicodedata.category(char).startswith("C") for char in value)
        or sanitize_metadata(value) != value
    ):
        _reject()
    return cast(str, value)


def _suppression(value: object, today: date) -> Suppression:
    required = {"rule_id", "path", "fingerprint", "reason", "expires"}
    item = _keys(value, required | {"line"}, required)
    rule = item["rule_id"]
    if not isinstance(rule, str) or rule not in {
        *(entry.rule_id for entry in RULES),
        "generic-secret-assignment",
    }:
        _reject()
    path = _path(item["path"])
    fingerprint = item["fingerprint"]
    if (
        not isinstance(fingerprint, str)
        or re.fullmatch(r"[0-9a-f]{16}", fingerprint) is None
    ):
        _reject()
    reason = item["reason"]
    if (
        not isinstance(reason, str)
        or not 10 <= len(reason.strip()) <= 500
        or any(unicodedata.category(char).startswith("C") for char in reason)
    ):
        _reject()
    expiry = item["expires"]
    if (
        not isinstance(expiry, str)
        or re.fullmatch(r"\d{4}-\d{2}-\d{2}", expiry) is None
    ):
        _reject()
    if date.fromisoformat(cast(str, expiry)) <= today:
        _reject()
    line = _positive(item["line"]) if "line" in item else None
    return Suppression(
        cast(str, rule),
        path,
        cast(str, fingerprint),
        sanitize_metadata(cast(str, reason).strip()),
        cast(str, expiry),
        line,
    )


def _append_unique(entries: list[Suppression], candidate: Suppression) -> None:
    for existing in entries:
        if (existing.path, existing.rule_id, existing.fingerprint) == (
            candidate.path,
            candidate.rule_id,
            candidate.fingerprint,
        ) and (
            existing.line is None
            or candidate.line is None
            or existing.line == candidate.line
        ):
            _reject()
    entries.append(candidate)


def load_policy(path: Path, *, today: date | None = None) -> Policy:
    """Read only an explicitly selected policy; every failure has a safe message."""
    try:
        parent = path.parent.resolve()
        raw = read_scan_file(parent, Path(path.name), 64 * 1024)
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object,
            parse_constant=lambda _: _reject(),
        )
        document = _keys(
            value, {"version", "scan", "fail_on", "suppressions"}, {"version"}
        )
        if type(document["version"]) is not int or document["version"] != 1:
            _reject()
        scan = _keys(
            document.get("scan", {}),
            {
                "max_file_bytes",
                "max_total_bytes",
                "max_findings_per_file",
                "max_line_length",
                "include_hidden",
                "excluded_dirs",
                "excluded_extensions",
            },
            set(),
        )
        defaults = ScanConfig()
        settings: dict[str, object] = {}
        for key, entry in scan.items():
            if key.startswith("excluded_"):
                if not isinstance(entry, list) or any(
                    type(name) is not str for name in entry
                ):
                    _reject()
                settings[key] = getattr(defaults, key) | frozenset(entry)
            else:
                settings[key] = entry
        config = ScanConfig(**settings)  # type: ignore[arg-type]
        threshold = document.get("fail_on", "high")
        if not isinstance(threshold, str) or threshold not in {
            "low",
            "medium",
            "high",
            "critical",
        }:
            _reject()
        entries = document.get("suppressions", [])
        if not isinstance(entries, list) or len(entries) > 100:
            _reject()
        current = today or datetime.now(UTC).date()
        suppressions: list[Suppression] = []
        for entry in entries:
            suppression = _suppression(entry, current)
            _append_unique(suppressions, suppression)
        return Policy(config, cast(Severity, threshold), tuple(suppressions))
    except (OSError, ValueError, TypeError, RecursionError, RuntimeError):
        raise PolicyError("policy is invalid or cannot be safely read") from None


def apply_policy(
    report: ScanReport, policy: Policy, *, today: date | None = None
) -> None:
    """Keep suppressed evidence visible without changing scan completeness."""
    # Validate all entries before mutating the report, including a policy kept
    # in memory beyond its expiry or one constructed directly through the API.
    current = today or datetime.now(UTC).date()
    try:
        if type(policy.config) is not ScanConfig:
            _reject()
        ScanConfig(**asdict(policy.config))
        if policy.fail_on not in {"low", "medium", "high", "critical"}:
            _reject()
        if type(policy.suppressions) is not tuple or len(policy.suppressions) > 100:
            _reject()
        validated: list[Suppression] = []
        for entry in policy.suppressions:
            fields: dict[str, object] = {
                "rule_id": entry.rule_id,
                "path": entry.path,
                "fingerprint": entry.fingerprint,
                "reason": entry.reason,
                "expires": entry.expires,
            }
            if entry.line is not None:
                fields["line"] = entry.line
            parsed = _suppression(fields, current)
            _append_unique(validated, parsed)
    except (ValueError, TypeError, AttributeError, RecursionError):
        raise PolicyError("policy is invalid or cannot be safely read") from None
    remaining = []
    for finding in report.findings:
        suppression = next(
            (
                entry
                for entry in validated
                if (
                    entry.path == finding.path
                    and entry.rule_id == finding.rule_id
                    and entry.fingerprint == finding.fingerprint
                    and (entry.line is None or entry.line == finding.line)
                )
            ),
            None,
        )
        if suppression is None:
            remaining.append(finding)
        else:
            report.suppressed_findings.append(
                SuppressedFinding(finding, suppression.reason, suppression.expires)
            )
    report.findings[:] = remaining
