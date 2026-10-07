import json

import pytest

from secret_sentinel import ScanConfig, Scanner
from secret_sentinel.cli import main

TOKEN = "ghp_SYNTHETICPROBE1234567890"


def test_configuration_and_credentials_are_distinguishable(tmp_path):
    (tmp_path / "settings.env").write_text(f"DEBUG=true\nTOKEN={TOKEN}\n")
    report = Scanner().scan(tmp_path)
    data = report.to_dict()
    assert data["complete"]
    assert data["finding_count"] == 2
    assert data["configuration_count"] == 1
    assert data["credential_count"] == 1
    assert data["secret_count"] == 2  # legacy total preserved for existing consumers
    assert {f.category for f in report.findings} == {"configuration", "secret"}
    assert TOKEN not in str(data)


def test_configuration_obeys_shared_budget_and_completeness(tmp_path):
    (tmp_path / "settings.env").write_text(f"TOKEN={TOKEN}\nDEBUG=true\n")
    report = Scanner(ScanConfig(max_findings_per_file=1)).scan(tmp_path)
    assert not report.complete
    assert report.secret_count == 1


@pytest.mark.parametrize("format", ["text", "markdown", "json"])
def test_configuration_cli_reports_without_raw_arguments(tmp_path, capsys, format):
    target = tmp_path / "client.py"
    target.write_text(
        f'requests.get("https://private.invalid/{TOKEN}", verify=False)\n'
    )
    assert main(["scan", str(target), "--format", format]) == 1
    output = capsys.readouterr().out
    assert "config-tls-verification-disabled" in output
    assert TOKEN not in output
    assert "private.invalid" not in output


def test_configuration_suppression_is_exact_and_visible(tmp_path, capsys):
    target = tmp_path / "settings.env"
    target.write_text("DEBUG=true\n")
    report = Scanner().scan(target)
    finding = report.findings[0]
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "version": 1,
                "fail_on": "low",
                "suppressions": [
                    {
                        "rule_id": finding.rule_id,
                        "path": target.name,
                        "fingerprint": finding.fingerprint,
                        "reason": "Reviewed development-only configuration",
                        "expires": "2099-01-01",
                    }
                ],
            }
        )
    )
    assert main(["scan", str(target), "--policy", str(policy), "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["configuration_count"] == 0
    assert data["suppressed_count"] == 1
    assert data["suppressed_findings"][0]["finding"]["category"] == "configuration"
    target.write_text("DEBUG=true\nNODE_TLS_REJECT_UNAUTHORIZED=0\n")
    assert main(["scan", str(target), "--policy", str(policy), "--format", "json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["configuration_count"] == 1


def test_hidden_env_needs_explicit_scope(tmp_path):
    (tmp_path / ".env").write_text("NODE_TLS_REJECT_UNAUTHORIZED=0\n")
    assert Scanner().scan(tmp_path).secret_count == 0
    assert Scanner(ScanConfig(include_hidden=True)).scan(tmp_path).secret_count == 1


def test_multiline_python_documentation_does_not_trigger_configuration(tmp_path):
    target = tmp_path / "settings.py"
    target.write_text(
        '"""Example\nDEBUG=True\nrequests.get("anything", verify=False)\n'
        + TOKEN
        + '\n"""\nDEBUG=True\n'
    )
    report = Scanner().scan(target)
    assert report.complete
    assert [(f.rule_id, f.line) for f in report.findings] == [
        ("github-token", 4),
        ("config-debug-enabled", 6),
    ]
    assert TOKEN not in str(report.to_dict())
