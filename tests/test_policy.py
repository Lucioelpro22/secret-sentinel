"""Explicit policy validation and suppression lifecycle regression cases."""

import json
from datetime import date

import pytest

from secret_sentinel import Scanner
from secret_sentinel.policy import PolicyError, apply_policy, load_policy

TODAY = date(2026, 10, 7)


def write_policy(tmp_path, document):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def suppression(**overrides):
    value = {
        "rule_id": "aws-access-key",
        "path": "fixture.env",
        "fingerprint": "0123456789abcdef",
        "reason": "Reviewed synthetic test fixture",
        "expires": "2026-11-01",
    }
    value.update(overrides)
    return value


def test_defaults_and_additive_scope(tmp_path):
    policy = load_policy(
        write_policy(
            tmp_path,
            {
                "version": 1,
                "scan": {
                    "include_hidden": True,
                    "excluded_dirs": ["build"],
                    "excluded_extensions": [".map"],
                    "max_file_bytes": 100,
                },
                "fail_on": "medium",
            },
        ),
        today=TODAY,
    )
    assert policy.config.include_hidden
    assert policy.config.max_file_bytes == 100
    assert {"build", ".git"} <= policy.config.excluded_dirs
    assert {".map", ".png"} <= policy.config.excluded_extensions
    assert policy.fail_on == "medium"
    assert policy.suppressions == ()


@pytest.mark.parametrize(
    "document",
    [
        [],
        {},
        {"version": True},
        {"version": 2},
        {"version": 1, "extra": 0},
        {"version": 1, "scan": []},
        {"version": 1, "scan": {"follow_symlinks": False}},
        {"version": 1, "scan": {"max_file_bytes": True}},
        {"version": 1, "scan": {"max_total_bytes": 0}},
        {"version": 1, "scan": {"include_hidden": 1}},
        {"version": 1, "scan": {"excluded_dirs": "build"}},
        {"version": 1, "scan": {"excluded_dirs": ["../build"]}},
        {"version": 1, "scan": {"excluded_extensions": ["zip"]}},
        {"version": 1, "fail_on": "all"},
        {"version": 1, "suppressions": {}},
        {"version": 1, "suppressions": [suppression()] * 101},
    ],
)
def test_malformed_policy_fails_closed(tmp_path, document):
    with pytest.raises(PolicyError, match="policy is invalid or cannot be safely read"):
        load_policy(write_policy(tmp_path, document), today=TODAY)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"version":1,"version":1}',
        b'{"version":1,"scan":{"max_file_bytes":NaN}}',
        b'{"version":1,"scan":{"max_file_bytes":Infinity}}',
        b"\xff",
        b"{",
        b"[" * 1200 + b"]" * 1200,
        b" " * 65537,
    ],
)
def test_raw_malformed_or_oversized_input_has_safe_error(tmp_path, raw):
    path = tmp_path / "policy.json"
    path.write_bytes(raw)
    with pytest.raises(PolicyError) as error:
        load_policy(path, today=TODAY)
    assert str(error.value) == "policy is invalid or cannot be safely read"


@pytest.mark.parametrize(
    "overrides",
    [
        {"rule_id": "unknown"},
        {"fingerprint": "bad"},
        {"reason": "short"},
        {"reason": "x" * 501},
        {"reason": "bad\nreviewed reason"},
        {"expires": "2026-10-07"},
        {"expires": "2026-10-06"},
        {"expires": "2026-02-30"},
        {"expires": "2026-11-1"},
        {"line": True},
        {"line": 0},
        {"path": "/fixture.env"},
        {"path": "../fixture.env"},
        {"path": "./fixture.env"},
        {"path": "a//fixture.env"},
        {"path": "a\\fixture.env"},
        {"path": "*.env"},
        {"path": "a\u202eb.env"},
        {"path": "AKIA1234567890ABCDEF.env"},
    ],
)
def test_invalid_suppressions_are_rejected(tmp_path, overrides):
    with pytest.raises(PolicyError):
        load_policy(
            write_policy(
                tmp_path, {"version": 1, "suppressions": [suppression(**overrides)]}
            ),
            today=TODAY,
        )


def test_duplicate_or_overlapping_suppressions_are_rejected(tmp_path):
    for second in (suppression(), suppression(line=3)):
        with pytest.raises(PolicyError):
            load_policy(
                write_policy(
                    tmp_path, {"version": 1, "suppressions": [suppression(), second]}
                ),
                today=TODAY,
            )


def test_suppression_requires_every_exact_identity_and_preserves_incomplete(tmp_path):
    target = tmp_path / "fixture.env"
    target.write_text("AKIA1234567890ABCDEF\nAKIAFEDCBA0987654321\n", encoding="utf-8")
    report = Scanner().scan(target)
    report.mark_incomplete("synthetic coverage failure")
    finding = report.findings[0]
    policy = load_policy(
        write_policy(
            tmp_path,
            {
                "version": 1,
                "suppressions": [suppression(fingerprint=finding.fingerprint, line=1)],
            },
        ),
        today=TODAY,
    )
    apply_policy(report, policy, today=TODAY)
    assert not report.complete
    assert len(report.findings) == 1
    assert report.findings[0].line == 2
    assert len(report.suppressed_findings) == 1
    assert report.suppressed_findings[0].finding == finding
    assert report.suppressed_findings[0].expires == "2026-11-01"
    apply_policy(report, policy, today=TODAY)
    assert len(report.suppressed_findings) == 1


def test_reason_credentials_are_redacted(tmp_path):
    secret = "ghp_1234567890abcdefghijklmnop"
    policy = load_policy(
        write_policy(
            tmp_path,
            {
                "version": 1,
                "suppressions": [
                    suppression(reason="Reviewed synthetic fixture " + secret)
                ],
            },
        ),
        today=TODAY,
    )
    assert secret not in policy.suppressions[0].reason


def test_missing_symlink_and_nonregular_policy_fail_closed(tmp_path):
    with pytest.raises(PolicyError):
        load_policy(tmp_path / "missing.json", today=TODAY)
    target = write_policy(tmp_path, {"version": 1})
    link = tmp_path / "link.json"
    link.symlink_to(target)
    for path in (link, tmp_path):
        with pytest.raises(PolicyError):
            load_policy(path, today=TODAY)


def test_loaded_policy_expiry_is_rechecked_before_mutation(tmp_path):
    target = tmp_path / "fixture.env"
    target.write_text("AKIA1234567890ABCDEF", encoding="utf-8")
    report = Scanner().scan(target)
    policy = load_policy(
        write_policy(
            tmp_path,
            {
                "version": 1,
                "suppressions": [
                    suppression(fingerprint=report.findings[0].fingerprint)
                ],
            },
        ),
        today=TODAY,
    )
    before = report.to_dict()
    with pytest.raises(PolicyError):
        apply_policy(report, policy, today=date(2026, 11, 1))
    assert report.to_dict() == before


def test_direct_policy_constructor_cannot_bypass_validation(tmp_path):
    from secret_sentinel.models import ScanConfig
    from secret_sentinel.policy import Policy, Suppression

    report = Scanner().scan(tmp_path)
    for invalid in ("../fixture.env", "AKIA1234567890ABCDEF.env"):
        policy = Policy(
            ScanConfig(),
            "high",
            (
                Suppression(
                    "aws-access-key",
                    invalid,
                    "0123456789abcdef",
                    "Reviewed synthetic fixture",
                    "2026-11-01",
                ),
            ),
        )
        with pytest.raises(PolicyError):
            apply_policy(report, policy, today=TODAY)
    assert report.suppressed_findings == []


@pytest.mark.parametrize("changes", [{"rule_id": "unknown"}, {"fingerprint": "bad"}])
def test_direct_invalid_suppression_identifiers_fail(tmp_path, changes):
    from secret_sentinel.models import ScanConfig
    from secret_sentinel.policy import Policy, Suppression

    entry = Suppression(**suppression(**changes))
    with pytest.raises(PolicyError):
        apply_policy(
            Scanner().scan(tmp_path),
            Policy(ScanConfig(), "high", (entry,)),
            today=TODAY,
        )


def test_direct_invalid_policy_config_fails(tmp_path):
    from secret_sentinel.policy import Policy

    with pytest.raises(PolicyError):
        apply_policy(Scanner().scan(tmp_path), Policy(None, "high", ()), today=TODAY)
