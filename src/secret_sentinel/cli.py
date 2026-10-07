"""Small CLI adapter; all scanning remains local and read-only."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import replace
from pathlib import Path

from .models import ScanConfig, ScanReport
from .policy import PolicyError, apply_policy, load_policy
from .scanner import Scanner


def _markdown_cell(value: str) -> str:
    return "".join(
        f"&#{ord(char)};" if char in "&<>|`\\*_[]()!" else char for char in value
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret-sentinel", description="Offline, redacted credential and configuration checks"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan a file or directory without modifying it")
    scan.add_argument("target", type=Path)
    scan.add_argument("--format", choices=("json", "markdown", "text"), default="text")
    scan.add_argument(
        "--output", type=Path, help="write the redacted report to this path"
    )
    scan.add_argument(
        "--fail-on", choices=("low", "medium", "high", "critical"), default=None
    )
    scan.add_argument(
        "--policy", type=Path, help="load an explicit versioned JSON policy"
    )
    scan.add_argument("--include-hidden", action="store_true", default=None)
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
    scan.add_argument("--max-file-bytes", type=int, default=None)
    scan.add_argument("--max-total-bytes", type=int, default=None)
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
            f"- Suppressed findings: {len(report.suppressed_findings)}",
            f"- Scan complete: {report.complete}",
            "",
            "| Path | Line | Rule | Category | Severity | Evidence |",
            "|---|---:|---|---|---|---|",
        ]
        for finding in report.findings:
            lines.append(
                f"| {_markdown_cell(finding.path)} | {finding.line} | `{finding.rule_id}` | {finding.category} | {finding.severity} | `{_markdown_cell(finding.redacted_match)}` |"
            )
        if report.suppressed_findings:
            lines.extend(
                [
                    "",
                    "## Reviewed suppressions",
                    "",
                    "| Path | Line | Rule | Evidence | Reason | Expires (UTC) |",
                    "|---|---:|---|---|---|---|",
                ]
            )
            for item in report.suppressed_findings:
                finding = item.finding
                lines.append(
                    f"| {_markdown_cell(finding.path)} | {finding.line} | `{finding.rule_id}` | {_markdown_cell(finding.redacted_match)} | {_markdown_cell(item.reason)} | {item.expires} |"
                )
        lines.extend(f"\nWarning: {warning}" for warning in report.warnings)
        return "\n".join(lines) + "\n"
    lines = [
        f"Scanned {report.files_scanned} files; {finding_count} finding(s).",
        f"Scan complete: {report.complete}.",
        f"Suppressed findings: {len(report.suppressed_findings)}.",
    ]
    lines.extend(
        f"{f.path}:{f.line}:{f.column} {f.severity} {f.category} {f.rule_id} {f.redacted_match}"
        for f in report.findings
    )
    lines.extend(
        f"Suppressed: {item.finding.path}:{item.finding.line} {item.finding.rule_id} {item.finding.redacted_match}; reason={item.reason}; expires={item.expires} (UTC)"
        for item in report.suppressed_findings
    )
    lines.extend(f"Warning: {warning}" for warning in report.warnings)
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        policy = load_policy(args.policy) if args.policy else None
        defaults = policy.config if policy else ScanConfig()
        config = replace(
            defaults,
            include_hidden=defaults.include_hidden
            if args.include_hidden is None
            else args.include_hidden,
            excluded_dirs=defaults.excluded_dirs | frozenset(args.exclude_dir),
            excluded_extensions=defaults.excluded_extensions
            | frozenset(args.exclude_extension),
            max_file_bytes=defaults.max_file_bytes
            if args.max_file_bytes is None
            else args.max_file_bytes,
            max_total_bytes=defaults.max_total_bytes
            if args.max_total_bytes is None
            else args.max_total_bytes,
        )
    except PolicyError:
        parser.exit(2, "Policy could not be loaded or validated.\n")
    except ValueError:
        parser.exit(
            2,
            "Invalid scan configuration; use positive byte limits, directory names and dotted extensions.\n",
        )
    fail_on = args.fail_on or (policy.fail_on if policy else "high")
    report = Scanner(config).scan(args.target)
    if policy:
        try:
            apply_policy(report, policy)
        except PolicyError:
            parser.exit(2, "Policy could not be loaded or validated.\n")
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
    threshold = rank[fail_on]
    if not report.complete:
        return 2
    return 1 if any(rank[f.severity] >= threshold for f in report.findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
