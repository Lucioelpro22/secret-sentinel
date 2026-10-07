"""Trusted, offline adapter for the Secret Sentinel composite action."""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import cast

# -I prevents repository-controlled PYTHONPATH/site imports. Never install or
# execute the scanned checkout: imports come only from the pinned action tree.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from secret_sentinel.models import ScanConfig, ScanReport
from secret_sentinel.scanner import Scanner


def boolean(name: str) -> bool:
    value = os.environ[name]
    if value not in {"true", "false"}:
        raise ValueError("invalid boolean")
    return value == "true"


def target_path() -> Path:
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
    value = os.environ["INPUT_PATH"]
    if not value or any(ord(char) < 32 for char in value):
        raise ValueError("invalid path")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("invalid path")
    target = workspace.joinpath(relative)
    # Reject symlinks in every requested component, even links back inside the
    # checkout; descendant reads also use the scanner's no-follow descriptors.
    current = workspace
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("invalid path")
    resolved = target.resolve(strict=True)
    if not resolved.is_relative_to(workspace) or not resolved.is_dir():
        raise ValueError("invalid path")
    return resolved


def public_report(report: ScanReport) -> dict[str, object]:
    """Allowlist metadata; arbitrary filenames and warning text stay private."""
    paths = {
        path: f"file-{index}"
        for index, path in enumerate(dict.fromkeys(f.path for f in report.findings), 1)
    }
    findings = [
        {
            "path_id": paths[finding.path],
            "line": finding.line,
            "column": finding.column,
            "rule_id": finding.rule_id,
            "category": finding.category,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "evidence": "[REDACTED]",
        }
        for finding in report.findings
    ]
    return {
        "schema_version": "action-1",
        "complete": report.complete,
        "files_scanned": report.files_scanned,
        "bytes_scanned": report.bytes_scanned,
        "files_skipped": report.files_skipped,
        "finding_count": len(findings),
        "credential_count": sum(f.category == "secret" for f in report.findings),
        "configuration_count": sum(
            f.category == "configuration" for f in report.findings
        ),
        "warning_count": len(report.warnings),
        "findings": findings,
    }


def markdown(report: dict[str, object]) -> str:
    lines = [
        "# Secret Sentinel report",
        "",
        f"- Findings: {report['finding_count']}",
        f"- Complete: {str(report['complete']).lower()}",
        f"- Files scanned: {report['files_scanned']}",
        f"- Warnings: {report['warning_count']}",
        "",
        "Paths are opaque identifiers; use a local CLI scan to locate findings.",
        "",
        "| Path ID | Line | Rule | Category | Severity |",
        "|---|---:|---|---|---|",
    ]
    for finding in cast(list[dict[str, object]], report["findings"]):
        lines.append(
            f"| {finding['path_id']} | {finding['line']} | "
            f"{finding['rule_id']} | {finding['category']} | {finding['severity']} |"
        )
    return "\n".join(lines) + "\n"


def write_private(path: Path, content: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(content)


def scan() -> int:
    if os.environ.get("RUNNER_OS") != "Linux" or sys.version_info < (3, 11):
        raise ValueError("unsupported runner")
    target = target_path()
    threshold = os.environ["INPUT_FAIL_ON"]
    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    if threshold not in rank:
        raise ValueError("invalid severity")
    boolean("INPUT_FAIL_ON_FINDINGS")
    boolean("INPUT_FAIL_ON_INCOMPLETE")
    include_hidden = boolean("INPUT_INCLUDE_HIDDEN")
    artifact = os.environ["INPUT_ARTIFACT_NAME"]
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", artifact) is None:
        raise ValueError("invalid artifact name")
    retention = os.environ["INPUT_RETENTION_DAYS"]
    if retention not in {str(number) for number in range(1, 8)}:
        raise ValueError("invalid retention")
    temporary = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
    if not temporary.is_dir() or temporary.is_relative_to(workspace):
        raise ValueError("invalid temporary directory")
    output_path = Path(os.environ["GITHUB_OUTPUT"])
    report = Scanner(ScanConfig(include_hidden=include_hidden)).scan(
        target, resolve_target=False
    )
    exceeded = any(rank[f.severity] >= rank[threshold] for f in report.findings)
    code = 2 if not report.complete else int(exceeded)
    rendered = public_report(report)
    directory = Path(tempfile.mkdtemp(prefix="secret-sentinel-", dir=temporary))
    write_private(
        directory / "secret-sentinel.json", json.dumps(rendered, indent=2) + "\n"
    )
    write_private(directory / "secret-sentinel.md", markdown(rendered))
    outputs = {
        "reports-dir": str(directory),
        "finding-count": str(rendered["finding_count"]),
        "credential-count": str(rendered["credential_count"]),
        "configuration-count": str(rendered["configuration_count"]),
        "complete": str(report.complete).lower(),
        "scan-exit-code": str(code),
        "threshold-exceeded": str(exceeded).lower(),
        "artifact-name": artifact,
        "retention-days": retention,
    }
    # Runner-owned paths must also be single-line before writing output commands.
    if any("\n" in value or "\r" in value for value in outputs.values()):
        raise ValueError("invalid output")
    with output_path.open("a", encoding="utf-8", newline="\n") as output:
        output.write("".join(f"{key}={value}\n" for key, value in outputs.items()))
    print("Secret Sentinel scan finished; redacted artifact prepared.")
    return 0


def gate() -> int:
    code = os.environ["SCAN_EXIT_CODE"]
    if code not in {"0", "1", "2"}:
        raise ValueError("invalid scan status")
    findings = boolean("INPUT_FAIL_ON_FINDINGS")
    incomplete = boolean("INPUT_FAIL_ON_INCOMPLETE")
    exceeded = boolean("THRESHOLD_EXCEEDED")
    result = 2 if code == "2" and incomplete else int(exceeded and findings)
    if result:
        print("Secret Sentinel policy gate failed; review the redacted artifact.")
    return result


def main() -> int:
    try:
        if sys.argv[1:] == ["scan"]:
            return scan()
        if sys.argv[1:] == ["gate"]:
            return gate()
        raise ValueError("invalid stage")
    except Exception:  # noqa: BLE001 - errors must never reveal scanned metadata
        # A traceback can include attacker-controlled filenames or data. Any
        # unexpected adapter/scanner failure is a fixed, fail-closed status.
        print("Secret Sentinel action could not complete safely.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
