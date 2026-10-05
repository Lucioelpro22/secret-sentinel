"""Safe local scanner. It never performs network requests or writes input files."""

from __future__ import annotations

import math
import os
from pathlib import Path
from typing import Literal

from .models import Finding, ScanConfig, ScanReport, Severity
from .redaction import fingerprint, redact
from .rules import ASSIGNMENT, BASE64ISH, PLACEHOLDER, RULES


class Scanner:
    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()

    def scan(self, target: str | os.PathLike[str]) -> ScanReport:
        root = Path(target)
        try:
            root = root.resolve()
        except (OSError, RuntimeError):
            report = ScanReport(root=str(root))
            report.mark_incomplete("target cannot be resolved")
            return report
        report = ScanReport(root=str(root))
        paths = [root] if root.is_file() else self._iter_files(root, report)
        total = 0
        for path in paths:
            if total >= self.config.max_total_bytes:
                report.mark_incomplete(
                    "scan byte limit reached; remaining files skipped"
                )
                break
            try:
                size = path.stat().st_size
                if size == 0:
                    report.files_skipped += 1
                    continue
                if size > self.config.max_file_bytes:
                    report.files_skipped += 1
                    report.mark_incomplete("file byte limit exceeded; file skipped")
                    continue
                if total + size > self.config.max_total_bytes:
                    report.files_skipped += 1
                    report.mark_incomplete("scan byte limit exceeded; file skipped")
                    continue
                raw = path.read_bytes()
            except (OSError, ValueError):
                report.files_skipped += 1
                report.mark_incomplete("file could not be read; file skipped")
                continue
            if b"\x00" in raw:
                report.files_skipped += 1
                continue
            total += len(raw)
            report.bytes_scanned = total
            report.files_scanned += 1
            rel = self._display_path(path, root)
            self._scan_text(raw.decode("utf-8", errors="replace"), rel, report)
        return report

    def _iter_files(self, root: Path, report: ScanReport) -> list[Path]:
        if not root.exists() or not root.is_dir():
            report.mark_incomplete("target is not a readable file or directory")
            return []
        result: list[Path] = []

        def on_walk_error(error: OSError) -> None:
            report.mark_incomplete("directory could not be read; subtree skipped")

        for current, dirs, files in os.walk(
            root, followlinks=self.config.follow_symlinks, onerror=on_walk_error
        ):
            dirs.sort()
            files.sort()
            dirs[:] = [
                d
                for d in dirs
                if d not in self.config.excluded_dirs
                and (self.config.include_hidden or not d.startswith("."))
            ]
            for filename in files:
                if not self.config.include_hidden and filename.startswith("."):
                    continue
                path = Path(current) / filename
                if path.suffix.lower() in self.config.excluded_extensions:
                    continue
                if not self.config.follow_symlinks and path.is_symlink():
                    continue
                result.append(path)
        return result

    @staticmethod
    def _display_path(path: Path, root: Path) -> str:
        try:
            return str(path.relative_to(root)) if root.is_dir() else path.name
        except ValueError:
            return path.name

    def _scan_text(self, text: str, display_path: str, report: ScanReport) -> None:
        seen: set[tuple[int, str]] = set()
        for line_number, original in enumerate(text.splitlines(), 1):
            if len(seen) >= self.config.max_findings_per_file:
                report.mark_incomplete("per-file finding limit reached; text skipped")
                return
            if len(original) > self.config.max_line_length:
                report.mark_incomplete("line length limit exceeded; text truncated")
            line = original[: self.config.max_line_length]
            for rule in RULES:
                for match in rule.pattern.finditer(line):
                    self._add(
                        report,
                        seen,
                        display_path,
                        line_number,
                        match.start() + 1,
                        rule.rule_id,
                        rule.description,
                        rule.severity,
                        match.group(0),
                        rule.confidence,
                    )
            assignment = ASSIGNMENT.search(line)
            if assignment and self._looks_secret(assignment.group(1)):
                value = assignment.group(1)
                self._add(
                    report,
                    seen,
                    display_path,
                    line_number,
                    assignment.start(1) + 1,
                    "generic-secret-assignment",
                    "Credential-like assignment",
                    "medium",
                    value,
                    "medium",
                )

    @staticmethod
    def _looks_secret(value: str) -> bool:
        lowered = value.lower()
        if (
            PLACEHOLDER.fullmatch(value)
            or any(
                marker in lowered
                for marker in ("example", "sample", "dummy", "changeme", "placeholder")
            )
            or len(value) < 16
        ):
            return False
        if not BASE64ISH.fullmatch(value):
            return False
        unique = len(set(value))
        if unique < 8 or value.lower() in {"a" * len(value), "0" * len(value)}:
            return False
        entropy = -sum(
            (value.count(char) / len(value)) * math.log2(value.count(char) / len(value))
            for char in set(value)
        )
        return entropy >= 3.2

    def _add(
        self,
        report: ScanReport,
        seen: set[tuple[int, str]],
        path: str,
        line: int,
        column: int,
        rule_id: str,
        description: str,
        severity: Severity,
        value: str,
        confidence: Literal["high", "medium"],
    ) -> None:
        key = (line, rule_id)
        if key in seen:
            return
        if len(seen) >= self.config.max_findings_per_file:
            report.mark_incomplete("per-file finding limit reached; text skipped")
            return
        seen.add(key)
        report.findings.append(
            Finding(
                path,
                line,
                column,
                rule_id,
                description,
                severity,
                redact(value),
                fingerprint(value),
                confidence,
            )
        )
