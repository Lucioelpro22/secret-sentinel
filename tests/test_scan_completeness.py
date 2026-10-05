from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from secret_sentinel import ScanConfig, Scanner
from secret_sentinel.cli import main

TOKEN = "ghp_SYNTHETICPROBE1234567890"


def test_finding_cap_is_independent_for_each_file(tmp_path) -> None:
    (tmp_path / "a.txt").write_text(f"{TOKEN}\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text(f"harmless\n{TOKEN}\n", encoding="utf-8")
    report = Scanner(ScanConfig(max_findings_per_file=1)).scan(tmp_path)
    assert [(f.path, f.line) for f in report.findings] == [("a.txt", 1), ("b.txt", 2)]
    assert report.complete


def test_truncated_file_does_not_stop_later_files(tmp_path) -> None:
    (tmp_path / "a.txt").write_text(f"{TOKEN}\n{TOKEN}\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text(f"harmless\n{TOKEN}\n", encoding="utf-8")
    report = Scanner(ScanConfig(max_findings_per_file=1)).scan(tmp_path)
    assert [f.path for f in report.findings] == ["a.txt", "b.txt"]
    assert not report.complete
    assert len(report.warnings) == 1


def test_single_line_finding_cap_reports_omitted_rule(tmp_path) -> None:
    target = tmp_path / "a.txt"
    target.write_text(f"{TOKEN} AKIA1234567890ABCDEF\n", encoding="utf-8")
    report = Scanner(ScanConfig(max_findings_per_file=1)).scan(target)
    assert report.secret_count == 1
    assert not report.complete
    assert TOKEN not in str(report.to_dict())


def test_duplicate_matches_do_not_consume_finding_budget(tmp_path) -> None:
    target = tmp_path / "a.txt"
    target.write_text(f"{TOKEN} {TOKEN}\n", encoding="utf-8")
    report = Scanner(ScanConfig(max_findings_per_file=1)).scan(target)
    assert report.secret_count == 1
    assert report.complete


@pytest.mark.parametrize("output_format", ["json", "markdown", "text"])
def test_missing_target_is_never_clean_in_any_format(tmp_path, capsys, output_format):
    assert main(["scan", str(tmp_path / "missing"), "--format", output_format]) == 2
    output = capsys.readouterr().out
    assert "target is not a readable file or directory" in output
    if output_format == "json":
        assert json.loads(output)["complete"] is False
    else:
        assert "Scan complete: False" in output


def test_unreadable_file_reports_failure_without_exception_content(
    tmp_path, monkeypatch
):
    target = tmp_path / "config.txt"
    target.write_text("harmless", encoding="utf-8")

    def denied(self):
        raise PermissionError(TOKEN)

    monkeypatch.setattr(Path, "read_bytes", denied)
    report = Scanner().scan(target)
    assert not report.complete
    assert report.files_skipped == 1
    assert TOKEN not in str(report.to_dict())


def test_unreadable_subtree_reports_incomplete(tmp_path, monkeypatch):
    def denied_walk(root, *, followlinks, onerror):
        onerror(PermissionError(TOKEN))
        return iter([])

    monkeypatch.setattr(os, "walk", denied_walk)
    report = Scanner().scan(tmp_path)
    assert not report.complete
    assert "directory could not be read; subtree skipped" in report.warnings
    assert TOKEN not in str(report.to_dict())


def test_unresolvable_target_reports_incomplete(tmp_path, monkeypatch):
    def cannot_resolve(self):
        raise RuntimeError(TOKEN)

    monkeypatch.setattr(Path, "resolve", cannot_resolve)
    report = Scanner().scan(tmp_path)
    assert not report.complete
    assert report.warnings == ["target cannot be resolved"]


@pytest.mark.parametrize(
    "config",
    [
        ScanConfig(max_file_bytes=2),
        ScanConfig(max_total_bytes=2),
        ScanConfig(max_line_length=2),
    ],
)
def test_resource_truncation_is_explicit(tmp_path, config):
    target = tmp_path / "a.txt"
    target.write_text(f"{TOKEN}\n", encoding="utf-8")
    report = Scanner(config).scan(target)
    assert not report.complete
    assert report.warnings
    assert TOKEN not in str(report.to_dict())


def test_total_byte_boundary_reports_remaining_input(tmp_path):
    (tmp_path / "a.txt").write_text("safe", encoding="utf-8")
    (tmp_path / "b.txt").write_text(TOKEN, encoding="utf-8")
    report = Scanner(ScanConfig(max_total_bytes=4)).scan(tmp_path)
    assert report.bytes_scanned == 4
    assert not report.complete


def test_expected_exclusions_and_empty_inputs_remain_complete(tmp_path, capsys):
    (tmp_path / ".env").write_text(TOKEN, encoding="utf-8")
    (tmp_path / "empty.txt").write_text("", encoding="utf-8")
    (tmp_path / "binary.bin").write_bytes(b"\x00")
    report = Scanner().scan(tmp_path)
    assert report.complete
    assert report.warnings == []
    assert main(["scan", str(tmp_path)]) == 0
    assert "Scan complete: True" in capsys.readouterr().out


def test_incomplete_scan_takes_precedence_over_severity_threshold(tmp_path, capsys):
    (tmp_path / "config.txt").write_text(f"{TOKEN}\n" + "x" * 20_001, encoding="utf-8")
    assert main(["scan", str(tmp_path), "--fail-on", "critical"]) == 2
    output = capsys.readouterr().out
    assert "github-token" in output
    assert "line length limit" in output
    assert TOKEN not in output
