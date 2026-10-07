"""Synthetic detector corpus: occurrence coverage and conservative placeholders."""

import json

import pytest

from secret_sentinel import Scanner


@pytest.mark.parametrize(
    "text,rule_id,expected",
    [
        (
            'password="q7R3vN8mK2pL9xD4sF6hJ1wC" token="z8T4bQ9nL3rM0yE5uG7kP2vD"',
            "generic-secret-assignment",
            2,
        ),
        (
            'password="${PASSWORD_VARIABLE}" token="q7R3vN8mK2pL9xD4sF6hJ1wC"',
            "generic-secret-assignment",
            1,
        ),
        (
            "AKIA1234567890ABCDEF AKIAFEDCBA0987654321",
            "aws-access-key",
            2,
        ),
        (
            "AKIA1234567890ABCDEF AKIA1234567890ABCDEF",
            "aws-access-key",
            1,
        ),
        (
            'password="q7R3vN8mK2pL9xD4sF6hJ1wC" token="q7R3vN8mK2pL9xD4sF6hJ1wC"',
            "generic-secret-assignment",
            1,
        ),
    ],
)
def test_distinct_occurrences_on_same_line(tmp_path, text, rule_id, expected):
    target = tmp_path / "synthetic.env"
    target.write_text(text + "\n", encoding="utf-8")
    report = Scanner().scan(target)
    findings = [finding for finding in report.findings if finding.rule_id == rule_id]
    assert report.complete
    assert len(findings) == expected
    assert len({finding.fingerprint for finding in findings}) == expected
    assert [finding.column for finding in findings] == sorted(
        finding.column for finding in findings
    )


@pytest.mark.parametrize(
    "marker", ["example", "sample", "dummy", "changeme", "placeholder"]
)
def test_substrings_do_not_suppress_credential_like_values(tmp_path, marker):
    value = "q7R3vN8mK2pL9xD4" + marker + "sF6hJ1wC"
    target = tmp_path / "synthetic.env"
    target.write_text(f'password="{value}"\n', encoding="utf-8")
    report = Scanner().scan(target)
    assert report.complete
    assert [finding.rule_id for finding in report.findings] == [
        "generic-secret-assignment"
    ]
    assert value not in json.dumps(report.to_dict())


@pytest.mark.parametrize(
    "value",
    [
        "your_long_example_key",
        "${A_LONG_SECRET_VARIABLE}",
        "<replace_this_secret_value>",
    ],
)
def test_exact_structural_placeholders_are_ignored(tmp_path, value):
    target = tmp_path / "synthetic.env"
    target.write_text(f'password="{value}"\n', encoding="utf-8")
    report = Scanner().scan(target)
    assert report.complete
    assert report.findings == []


def test_high_confidence_provider_value_with_example_substring_is_detected(tmp_path):
    value = "ghp_example1234567890abcdefghijklmnop"
    target = tmp_path / "synthetic.env"
    target.write_text(f'TOKEN="{value}"\n', encoding="utf-8")
    report = Scanner().scan(target)
    assert any(finding.rule_id == "github-token" for finding in report.findings)
    assert value not in json.dumps(report.to_dict())


def test_unicode_context_and_crlf_preserve_locations_and_redaction(tmp_path):
    first = "AKIA1234567890ABCDEF"
    second = "AKIAFEDCBA0987654321"
    target = tmp_path / "synthetic.env"
    target.write_bytes(
        f"# configuración\r\nclave={first}\r\nclave={second}\r\n".encode()
    )
    report = Scanner().scan(target)
    assert report.complete
    assert [(finding.line, finding.column) for finding in report.findings] == [
        (2, 7),
        (3, 7),
    ]
    serialized = json.dumps(report.to_dict())
    assert first not in serialized
    assert second not in serialized
