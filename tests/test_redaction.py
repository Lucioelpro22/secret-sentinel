from secret_sentinel.redaction import fingerprint, redact


def test_fingerprint_is_stable_but_namespaced() -> None:
    value = "ghp_example_token_value_1234567890"
    assert fingerprint(value) == fingerprint(value)
    assert fingerprint(value) != fingerprint(value, namespace="other-scanner")


def test_fingerprint_does_not_include_candidate() -> None:
    value = "super-secret-value-that-must-not-leak"
    digest = fingerprint(value)
    assert value not in digest
    assert len(digest) == 16
    assert all(char in "0123456789abcdef" for char in digest)


def test_redaction_handles_empty_short_and_long_values() -> None:
    assert redact("") == "[redacted]"
    assert redact("12345678") == "[redacted:8]"
    masked = redact("ghp_abcdefghijklmnop")
    assert masked.startswith("ghp…")
    assert "[redacted:20]" in masked
    assert "abcdefghijklmnop" not in masked
