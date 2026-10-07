"""Small CLI adapter; all scanning remains local and read-only."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .models import ScanConfig, ScanReport
from .scanner import Scanner


def _markdown_cell(value: str) -> str:
    return "".join(
        f"&#{ord(char)};" if char in "&<>|`\\*_[]()!" else char for char in value
    )


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
    scan.add_argument(
        "--exclude-dir",
        action="append",
        default=[],
        help="exclude a directory name (repeatable; adds to defaults)",
    )
    scan.add_argument(
        "--exclude-extension",
        action="append",
        default=[],
        help="exclude a suffix such as .log (repeatable; adds to defaults)",
    )
    scan.add_argument("--max-file-bytes", type=int, default=2_000_000)
    scan.add_argument("--max-total-bytes", type=int, default=50_000_000)
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
                f"| {_markdown_cell(finding.path)} | {finding.line} | `{finding.rule_id}` | {finding.severity} | `{_markdown_cell(finding.redacted_match)}` |"
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
    parser = _parser()
    args = parser.parse_args(argv)
    defaults = ScanConfig()
    try:
        config = ScanConfig(
            include_hidden=args.include_hidden,
            excluded_dirs=defaults.excluded_dirs | frozenset(args.exclude_dir),
            excluded_extensions=defaults.excluded_extensions
            | frozenset(args.exclude_extension),
            max_file_bytes=args.max_file_bytes,
            max_total_bytes=args.max_total_bytes,
        )
    except ValueError:
        parser.exit(
            2,
            "Invalid scan configuration; use positive byte limits, directory names and dotted extensions.\n",
        )
    report = Scanner(config).scan(args.target)
    rendered = _render(report, args.format)
    if args.output:
        try:
            descriptor = os.open(
                args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
                output.write(rendered)
        except OSError:
            sys.stderr.write("Report could not be written.\n")
            return 2
    else:
        sys.stdout.write(rendered)
    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    threshold = rank[args.fail_on]
    if not report.complete:
        return 2
    return 1 if any(rank[f.severity] >= threshold for f in report.findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
