from __future__ import annotations

import pytest

from secret_sentinel import Finding, ScanConfig, Scanner, ScanReport
from secret_sentinel.cli import _render
from secret_sentinel.redaction import sanitize_metadata

TOKEN = "ghp_SYNTHETICPROBE1234567890"


@pytest.mark.parametrize("output_format", ["json", "markdown", "text"])
def test_token_in_filename_is_redacted_in_every_report(tmp_path, output_format):
    target = tmp_path / TOKEN
    target.write_text(TOKEN, encoding="utf-8")
    report = Scanner().scan(target)
    assert TOKEN not in report.root
    assert TOKEN not in report.findings[0].path
    assert TOKEN not in _render(report, output_format)
    assert report.secret_count == 1


def test_metadata_preserves_normal_paths_and_escapes_terminal_controls():
    assert sanitize_metadata("src/config.env") == "src/config.env"
    hostile = "prefix\x1b[31m\n\r\t\x7f\u202esuffix"
    report = ScanReport(hostile)
    finding = Finding(
        hostile, 1, 1, "rule", "description", "high", "safe", "id", "high"
    )
    assert finding.path == report.root
    assert all(char not in report.root for char in "\x1b\n\r\t\x7f\u202e")
    assert "\\u001b" in report.root
    assert "\\u202e" in report.root


@pytest.mark.parametrize(
    "name",
    ["max_file_bytes", "max_total_bytes", "max_findings_per_file", "max_line_length"],
)
@pytest.mark.parametrize("value", [0, -1, True, 1.5, "secret-input", None])
def test_invalid_limits_fail_without_echoing_values(name, value):
    with pytest.raises(ValueError, match="^scan limits must be positive integers$"):
        ScanConfig(**{name: value})


@pytest.mark.parametrize("value", [1, "true", None])
def test_hidden_policy_must_be_boolean(value):
    with pytest.raises(ValueError, match="^include_hidden must be a boolean$"):
        ScanConfig(include_hidden=value)


@pytest.mark.parametrize("value", [True, 0, None, "false"])
def test_following_symlinks_is_rejected(value):
    with pytest.raises(ValueError, match="^following symbolic links is unsupported$"):
        ScanConfig(follow_symlinks=value)


@pytest.mark.parametrize("name", ["excluded_dirs", "excluded_extensions"])
@pytest.mark.parametrize(
    "value",
    [
        [],
        {".git"},
        frozenset({"../escape"}),
        frozenset({""}),
        frozenset({".."}),
        frozenset({"a\\b"}),
        frozenset({"a\n"}),
        frozenset({1}),
    ],
)
def test_invalid_exclusions_fail_closed(name, value):
    with pytest.raises(ValueError):
        ScanConfig(**{name: value})


def test_extensions_require_dot_and_valid_settings_are_preserved():
    with pytest.raises(ValueError):
        ScanConfig(excluded_extensions=frozenset({"txt"}))
    config = ScanConfig(
        include_hidden=True,
        excluded_dirs=frozenset({".git", "build"}),
        excluded_extensions=frozenset({".env", ".tar.gz"}),
    )
    assert config.include_hidden
    assert config.excluded_dirs == frozenset({".git", "build"})
