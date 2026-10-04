from __future__ import annotations

import json

from secret_sentinel.cli import main


def test_cli_json_is_redacted_and_returns_failure_for_high_finding(
    tmp_path, capsys
) -> None:
    secret = "AKIA1234567890ABCDEF"
    (tmp_path / "settings.env").write_text(
        f"AWS_ACCESS_KEY={secret}\n", encoding="utf-8"
    )

    exit_code = main(["scan", str(tmp_path), "--format", "json"])

    captured = capsys.readouterr()
    assert exit_code == 1
    payload = json.loads(captured.out)
    assert payload["secret_count"] == 1
    assert secret not in captured.out
    assert "aws-access-key" in captured.out
    assert captured.err == ""


def test_cli_fail_on_threshold_allows_lower_severity_finding(tmp_path, capsys) -> None:
    # A generic assignment is medium severity, so a high threshold is clean.
    (tmp_path / "settings.env").write_text(
        'password="q7R3vN8mK2pL9xD4sF6hJ1wC"\n', encoding="utf-8"
    )
    exit_code = main(["scan", str(tmp_path), "--format", "text", "--fail-on", "high"])
    output = capsys.readouterr().out
    assert exit_code == 0
    assert "generic-secret-assignment" in output
    assert "q7R3vN8mK2pL9xD4sF6hJ1wC" not in output


def test_cli_writes_requested_format_to_output(tmp_path, capsys) -> None:
    target = tmp_path / "config.env"
    target.write_text("AWS=AKIA1234567890ABCDEF\n", encoding="utf-8")
    destination = tmp_path / "report.md"

    assert (
        main(
            ["scan", str(target), "--format", "markdown", "--output", str(destination)]
        )
        == 1
    )
    assert capsys.readouterr().out == ""
    report = destination.read_text(encoding="utf-8")
    assert report.startswith("# Secret Sentinel report")
    assert "aws-access-key" in report
    assert "AKIA1234567890ABCDEF" not in report
