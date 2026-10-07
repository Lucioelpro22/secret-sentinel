import json

import pytest

from secret_sentinel.cli import main

TOKEN = "ghp_SYNTHETICPROBE1234567890"


def test_cli_additive_exclusions_and_hidden_scope(tmp_path, capsys):
    (tmp_path / ".env").write_text(TOKEN)
    (tmp_path / "generated").mkdir()
    (tmp_path / "generated" / "x.txt").write_text(TOKEN)
    (tmp_path / "x.log").write_text(TOKEN)
    assert (
        main(
            [
                "scan",
                str(tmp_path),
                "--include-hidden",
                "--exclude-dir",
                "generated",
                "--exclude-extension",
                ".log",
                "--format",
                "json",
            ]
        )
        == 1
    )
    report = json.loads(capsys.readouterr().out)
    assert report["complete"]
    assert [f["path"] for f in report["findings"]] == [".env"]


@pytest.mark.parametrize(
    "option,value",
    [
        ("--max-file-bytes", "0"),
        ("--max-total-bytes", "-1"),
        ("--exclude-dir", "../outside"),
        ("--exclude-extension", "txt"),
    ],
)
def test_cli_rejects_invalid_scope(tmp_path, capsys, option, value):
    with pytest.raises(SystemExit) as error:
        main(["scan", str(tmp_path), option, value])
    assert error.value.code == 2
    assert capsys.readouterr().out == ""


def test_cli_resource_limits_mark_incomplete(tmp_path, capsys):
    (tmp_path / "a.txt").write_text("x" * 20)
    assert (
        main(["scan", str(tmp_path), "--max-file-bytes", "10", "--format", "json"]) == 2
    )
    assert json.loads(capsys.readouterr().out)["complete"] is False


def test_report_write_error_has_safe_message(tmp_path, capsys):
    target = tmp_path / "a.txt"
    target.write_text("safe")
    assert (
        main(["scan", str(target), "--output", str(tmp_path / TOKEN / "missing.json")])
        == 2
    )
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "Report could not be written.\n"


def test_markdown_filename_cannot_inject_table_or_html(tmp_path, capsys):
    (tmp_path / "x|`<script>.txt").write_text(TOKEN)
    assert main(["scan", str(tmp_path), "--format", "markdown"]) == 1
    output = capsys.readouterr().out
    assert "x&#124;&#96;&#60;script&#62;.txt" in output
    assert "<script>" not in output


def test_cli_compound_and_uppercase_suffix_exclusions(tmp_path, capsys):
    (tmp_path / "x.tar.gz").write_text(TOKEN)
    (tmp_path / "x.LOG").write_text(TOKEN)
    assert (
        main(
            [
                "scan",
                str(tmp_path),
                "--exclude-extension",
                ".tar.gz",
                "--exclude-extension",
                ".LOG",
                "--format",
                "json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["files_scanned"] == 0


@pytest.mark.parametrize("symbolic", [False, True])
def test_output_never_overwrites_existing_input(tmp_path, capsys, symbolic):
    target = tmp_path / "a.txt"
    target.write_text(TOKEN)
    output = tmp_path / "report.json"
    if symbolic:
        output.symlink_to(target)
    else:
        output = target
    assert main(["scan", str(target), "--output", str(output)]) == 2
    assert target.read_text() == TOKEN
    assert capsys.readouterr().err == "Report could not be written.\n"


def test_markdown_filename_cannot_embed_link(tmp_path, capsys):
    (tmp_path / "![image](external).txt").write_text(TOKEN)
    assert main(["scan", str(tmp_path), "--format", "markdown"]) == 1
    output = capsys.readouterr().out
    assert "![image](" not in output
    assert "&#33;&#91;image&#93;&#40;external&#41;.txt" in output
