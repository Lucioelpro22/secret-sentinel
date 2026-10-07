"""Safe local scanner. It never performs network requests or writes input files."""

from __future__ import annotations

import math
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Literal

from .file_reader import FileLimitExceeded, open_scan_root, read_scan_file
from .models import Finding, ScanConfig, ScanReport, Severity
from .redaction import fingerprint, redact
from .rules import ASSIGNMENT, BASE64ISH, PLACEHOLDER, RULES


class Scanner:
    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()
        if self.config.follow_symlinks:
            raise ValueError("following symlinks is not supported by safe scans")

    def scan(self, target: str | os.PathLike[str]) -> ScanReport:
        root = Path(target)
        try:
            root = root.resolve()
        except (OSError, RuntimeError):
            report = ScanReport(root=str(root))
            report.mark_incomplete("target cannot be resolved")
            return report
        report = ScanReport(root=str(root))
        is_file = root.is_file()
        if not is_file and not root.is_dir():
            report.mark_incomplete("target is not a readable file or directory")
            return report
        anchor = root.parent if is_file else root
        try:
            with open_scan_root(anchor) as descriptor:
                paths = iter([root]) if is_file else self._iter_files(root, report)
                self._scan_files(paths, anchor, descriptor, is_file, report)
        except OSError:
            report.mark_incomplete("safe target reads are unavailable; scan skipped")
        return report

    def _scan_files(
        self,
        paths: Iterator[Path],
        anchor: Path,
        descriptor: int,
        is_file: bool,
        report: ScanReport,
    ) -> None:
        total = 0
        for path in paths:
            if total >= self.config.max_total_bytes:
                report.mark_incomplete(
                    "scan byte limit reached; remaining files skipped"
                )
                break
            limit = min(self.config.max_file_bytes, self.config.max_total_bytes - total)
            try:
                raw = read_scan_file(descriptor, path.relative_to(anchor), limit)
            except FileLimitExceeded as error:
                total += min(error.consumed, self.config.max_total_bytes - total)
                report.bytes_scanned = total
                report.files_skipped += 1
                report.mark_incomplete("file or scan byte limit exceeded; file skipped")
                continue
            except (OSError, ValueError):
                report.files_skipped += 1
                report.mark_incomplete("file could not be read; file skipped")
                continue
            total += len(raw)
            report.bytes_scanned = total
            if not raw or b"\x00" in raw:
                report.files_skipped += 1
                continue
            report.files_scanned += 1
            rel = path.name if is_file else str(path.relative_to(anchor))
            self._scan_text(raw.decode("utf-8", errors="replace"), rel, report)

    def _iter_files(self, root: Path, report: ScanReport) -> Iterator[Path]:
        if not root.exists() or not root.is_dir():
            report.mark_incomplete("target is not a readable file or directory")
            return

        def on_walk_error(error: OSError) -> None:
            report.mark_incomplete("directory could not be read; subtree skipped")

        for current, dirs, files in os.walk(
            root, followlinks=False, onerror=on_walk_error
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
                if any(
                    filename.lower().endswith(extension.lower())
                    for extension in self.config.excluded_extensions
                ):
                    continue
                if path.is_symlink():
                    continue
                yield path

    @staticmethod
    def _display_path(path: Path, root: Path) -> str:
        try:
            return str(path.relative_to(root)) if root.is_dir() else path.name
        except ValueError:
            return path.name

    def _scan_text(self, text: str, display_path: str, report: ScanReport) -> None:
        seen: set[tuple[int, str, str]] = set()
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
            for assignment in ASSIGNMENT.finditer(line):
                if not self._looks_secret(assignment.group(1)):
                    continue
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
        if PLACEHOLDER.fullmatch(value) or len(value) < 16:
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
        seen: set[tuple[int, str, str]],
        path: str,
        line: int,
        column: int,
        rule_id: str,
        description: str,
        severity: Severity,
        value: str,
        confidence: Literal["high", "medium"],
    ) -> None:
        key = (line, rule_id, fingerprint(value))
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
