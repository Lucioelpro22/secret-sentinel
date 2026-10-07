import json

import pytest

from secret_sentinel.cli import main
from secret_sentinel.redaction import fingerprint

TOKEN = "ghp_SYNTHETICPROBE1234567890"


def policy_file(tmp_path, **changes):
    policy = {
        "version": 1,
        "scan": {"include_hidden": True},
        "fail_on": "high",
        "suppressions": [
            {
                "rule_id": "github-token",
                "path": ".env",
                "fingerprint": fingerprint(TOKEN),
                "reason": "Reviewed synthetic fixture",
                "expires": "2099-01-01",
            }
        ],
    }
    policy.update(changes)
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy))
    return path


@pytest.mark.parametrize("format", ["json", "text", "markdown"])
def test_suppressed_evidence_remains_visible_in_all_reports(tmp_path, capsys, format):
    (tmp_path / ".env").write_text(TOKEN)
    path = policy_file(tmp_path)
    assert main(["scan", str(tmp_path), "--policy", str(path), "--format", format]) == 0
    output = capsys.readouterr().out
    assert TOKEN not in output
    assert "Reviewed synthetic fixture" in output
    assert "2099-01-01" in output
    if format == "json":
        data = json.loads(output)
        assert data["suppressed_count"] == 1
        assert data["secret_count"] == 0
        assert data["complete"]
    else:
        assert "Suppressed findings: 1" in output


def test_incomplete_scan_still_fails_with_valid_suppression(tmp_path, capsys):
    (tmp_path / ".env").write_text(TOKEN)
    (tmp_path / "oversize.txt").write_text("x" * 101)
    path = policy_file(tmp_path, scan={"include_hidden": True, "max_file_bytes": 100})
    # Scan a separate directory so the policy itself does not consume this small budget.
    scope = tmp_path / "scope"
    scope.mkdir()
    (tmp_path / ".env").rename(scope / ".env")
    (tmp_path / "oversize.txt").rename(scope / "oversize.txt")
    assert main(["scan", str(scope), "--policy", str(path), "--format", "json"]) == 2
    data = json.loads(capsys.readouterr().out)
    assert data["suppressed_count"] == 1
    assert not data["complete"]


def test_invalid_policy_never_renders_raw_content_or_writes_report(tmp_path, capsys):
    path = tmp_path / "policy.json"
    path.write_text('{"version":1,"unexpected":"' + TOKEN + '"}')
    output = tmp_path / "report.json"
    with pytest.raises(SystemExit) as error:
        main(["scan", str(tmp_path), "--policy", str(path), "--output", str(output)])
    assert error.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "Policy could not be loaded or validated.\n"
    assert not output.exists()


def test_cli_threshold_and_limits_override_policy(tmp_path, capsys):
    target = tmp_path / "config.env"
    target.write_text('password="q7R3vN8mK2pL9xD4sF6hJ1wC"')
    path = policy_file(
        tmp_path, fail_on="low", scan={"max_file_bytes": 1}, suppressions=[]
    )
    assert (
        main(
            [
                "scan",
                str(target),
                "--policy",
                str(path),
                "--fail-on",
                "high",
                "--max-file-bytes",
                "100",
                "--format",
                "json",
            ]
        )
        == 0
    )
    data = json.loads(capsys.readouterr().out)
    assert data["secret_count"] == 1
    assert data["complete"]


def test_policy_is_never_automatically_loaded(tmp_path, capsys):
    (tmp_path / "policy.json").write_text("invalid")
    assert main(["scan", str(tmp_path), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["complete"]
