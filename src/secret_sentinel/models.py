"""Public data models for secret-sentinel.

Models deliberately contain only redacted evidence.  A finding must never
carry the matched secret, even transiently in a serialized report.
"""

from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """Resource and policy limits for an offline scan."""

    max_file_bytes: int = 2_000_000
    max_total_bytes: int = 50_000_000
    max_findings_per_file: int = 100
    max_line_length: int = 20_000
    include_hidden: bool = False
    follow_symlinks: bool = False
    excluded_dirs: frozenset[str] = frozenset(
        {".git", ".hg", ".svn", ".venv", "node_modules"}
    )
    excluded_extensions: frozenset[str] = frozenset(
        {
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".webp",
            ".pdf",
            ".zip",
            ".gz",
            ".sqlite",
            ".db",
        }
    )


@dataclass(frozen=True, slots=True)
class Finding:
    path: str
    line: int
    column: int
    rule_id: str
    description: str
    severity: Severity
    redacted_match: str
    fingerprint: str
    confidence: Literal["high", "medium"]

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "rule_id": self.rule_id,
            "description": self.description,
            "severity": self.severity,
            "redacted_match": self.redacted_match,
            "fingerprint": self.fingerprint,
            "confidence": self.confidence,
        }


@dataclass(slots=True)
class ScanReport:
    root: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    bytes_scanned: int = 0
    files_skipped: int = 0
    warnings: list[str] = field(default_factory=list)
    complete: bool = True

    def mark_incomplete(self, warning: str) -> None:
        """Record omitted in-scope input without exposing exception contents."""
        self.complete = False
        if warning not in self.warnings:
            self.warnings.append(warning)

    @property
    def secret_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "1",
            "complete": self.complete,
            "root": self.root,
            "files_scanned": self.files_scanned,
            "bytes_scanned": self.bytes_scanned,
            "files_skipped": self.files_skipped,
            "secret_count": self.secret_count,
            "findings": [finding.to_dict() for finding in self.findings],
            "warnings": list(self.warnings),
        }
