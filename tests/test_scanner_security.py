from __future__ import annotations

from secret_sentinel import ScanConfig, Scanner


def test_detects_all_high_confidence_provider_patterns(tmp_path) -> None:
    (tmp_path / "secrets.env").write_text(
        """AWS=AKIA1234567890ABCDEF
GH=ghp_1234567890abcdefghijklmnop
SLACK=xoxb-1234567890-abcdef
STRIPE=sk_live_1234567890abcdef
GOOGLE=AIza12345678901234567890123456789012345
DB=postgres://user:password@db.internal/app
""",
        encoding="utf-8",
    )
    report = Scanner().scan(tmp_path)
    assert {finding.rule_id for finding in report.findings} >= {
        "aws-access-key",
        "github-token",
        "slack-token",
        "stripe-secret",
        "google-api-key",
        "database-url",
    }


def test_detects_private_key_and_jwt_without_serializing_raw_values(tmp_path) -> None:
    private_key = "-----BEGIN PRIVATE KEY-----"
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepayload123"
    (tmp_path / "config.txt").write_text(
        f"{private_key}\nTOKEN={jwt}\n", encoding="utf-8"
    )
    report = Scanner().scan(tmp_path)
    assert {finding.rule_id for finding in report.findings} >= {"private-key", "jwt"}
    serialized = str(report.to_dict())
    assert private_key not in serialized
    assert jwt not in serialized


def test_generic_secret_detects_entropy_but_rejects_placeholders_and_low_entropy(
    tmp_path,
) -> None:
    (tmp_path / "config.yml").write_text(
        'password: "q7R3vN8mK2pL9xD4sF6hJ1wC"\n'
        'token: "aaaaaaaaaaaaaaaaaaaa"\n'
        'secret: "${SECRET_VALUE}"\n',
        encoding="utf-8",
    )
    report = Scanner().scan(tmp_path)
    generic = [
        finding
        for finding in report.findings
        if finding.rule_id == "generic-secret-assignment"
    ]
    assert len(generic) == 1
    assert generic[0].line == 1


def test_scan_is_repeatable_and_findings_are_ordered(tmp_path) -> None:
    (tmp_path / "z.env").write_text("A=AKIA1234567890ABCDEF\n", encoding="utf-8")
    (tmp_path / "a.env").write_text("B=sk_live_1234567890abcdef\n", encoding="utf-8")
    first = Scanner().scan(tmp_path).to_dict()
    second = Scanner().scan(tmp_path).to_dict()
    assert first == second


def test_limits_bound_total_bytes_and_findings_per_file(tmp_path) -> None:
    (tmp_path / "one.txt").write_text("AKIA1234567890ABCDEF\n" * 3, encoding="utf-8")
    (tmp_path / "two.txt").write_text("AKIA1234567890ABCDEF\n", encoding="utf-8")
    limited = Scanner(ScanConfig(max_total_bytes=10)).scan(tmp_path)
    assert limited.bytes_scanned <= 10
    assert limited.files_skipped >= 1

    capped = Scanner(ScanConfig(max_findings_per_file=1)).scan(tmp_path / "one.txt")
    assert capped.secret_count == 1


def test_ignores_hidden_excluded_and_binary_files(tmp_path) -> None:
    (tmp_path / ".env").write_text("A=AKIA1234567890ABCDEF", encoding="utf-8")
    excluded = tmp_path / ".git"
    excluded.mkdir()
    (excluded / "config").write_text("A=AKIA1234567890ABCDEF", encoding="utf-8")
    (tmp_path / "image.bin").write_bytes(b"\x00AKIA1234567890ABCDEF")
    report = Scanner().scan(tmp_path)
    assert report.secret_count == 0
    assert report.files_scanned == 0
    assert report.files_skipped == 1


def test_does_not_follow_symlink_by_default(tmp_path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.env").write_text("A=AKIA1234567890ABCDEF", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    link = root / "linked"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        return
    report = Scanner().scan(root)
    assert report.secret_count == 0
    assert all(finding.path != "../outside/secret.env" for finding in report.findings)
