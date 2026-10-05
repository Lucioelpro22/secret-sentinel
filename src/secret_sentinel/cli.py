"""Small CLI adapter; all scanning remains local and read-only."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .models import ScanConfig, ScanReport
from .scanner import Scanner


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret-sentinel", description="Offline, redacted secret detection"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan a file or directory without modifying it")
    scan.add_argument("target", type=Path)
    scan.add_argument("--format", choices=("json", "markdown", "text"), default="text")
    scan.add_argument(
        "--output", type=Path, help="write the redacted report to this path"
    )
    scan.add_argument(
        "--fail-on", choices=("low", "medium", "high", "critical"), default="high"
    )
    scan.add_argument("--include-hidden", action="store_true")
    return parser


def _render(report: ScanReport, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n"
    finding_count = len(report.findings)
    if output_format == "markdown":
        lines = [
            "# Secret Sentinel report\n",
            f"- Files scanned: {report.files_scanned}",
            f"- Findings: {finding_count}",
            f"- Scan complete: {report.complete}",
            "",
            "| Path | Line | Rule | Severity | Evidence |",
            "|---|---:|---|---|---|",
        ]
        for finding in report.findings:
            lines.append(
                f"| `{finding.path}` | {finding.line} | `{finding.rule_id}` | {finding.severity} | `{finding.redacted_match}` |"
            )
        lines.extend(f"\nWarning: {warning}" for warning in report.warnings)
        return "\n".join(lines) + "\n"
    lines = [
        f"Scanned {report.files_scanned} files; {finding_count} finding(s).",
        f"Scan complete: {report.complete}.",
    ]
    lines.extend(
        f"{f.path}:{f.line}:{f.column} {f.severity} {f.rule_id} {f.redacted_match}"
        for f in report.findings
    )
    lines.extend(f"Warning: {warning}" for warning in report.warnings)
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    report = Scanner(ScanConfig(include_hidden=args.include_hidden)).scan(args.target)
    rendered = _render(report, args.format)
    if args.output:
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(rendered)
    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    threshold = rank[args.fail_on]
    if not report.complete:
        return 2
    return 1 if any(rank[f.severity] >= threshold for f in report.findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
