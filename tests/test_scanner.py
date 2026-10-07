from secret_sentinel import ScanConfig, Scanner


def test_detects_and_redacts_high_confidence_secret(tmp_path):
    path = tmp_path / "config.py"
    secret = "AKIA1234567890ABCDEF"
    path.write_text(f'AWS_ACCESS_KEY = "{secret}"\n', encoding="utf-8")
    report = Scanner().scan(tmp_path)
    assert report.secret_count == 1
    finding = report.findings[0]
    assert finding.rule_id == "aws-access-key"
    assert secret not in str(report.to_dict())
    assert finding.fingerprint != secret


def test_ignores_common_placeholders_and_binary(tmp_path):
    (tmp_path / "example.env").write_text(
        'API_KEY="change-me-now"\nTOKEN="${TOKEN}"\n', encoding="utf-8"
    )
    (tmp_path / "image.bin").write_bytes(b"\x00AKIA1234567890ABCDEF")
    report = Scanner().scan(tmp_path)
    assert report.secret_count == 0
    assert report.files_skipped == 1


def test_generic_assignment_requires_entropy_without_substring_suppression(tmp_path):
    (tmp_path / "config.yml").write_text(
        'password: "aaaaaaaaaaaaaaaaaaaa"\nsecret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n',
        encoding="utf-8",
    )
    report = Scanner().scan(tmp_path)
    generic = [f for f in report.findings if f.rule_id == "generic-secret-assignment"]
    assert len(generic) == 1
    assert generic[0].line == 2


def test_resource_limits_are_enforced(tmp_path):
    (tmp_path / "large.txt").write_text("x" * 100, encoding="utf-8")
    report = Scanner(ScanConfig(max_file_bytes=10)).scan(tmp_path)
    assert report.files_scanned == 0
    assert report.files_skipped == 1
