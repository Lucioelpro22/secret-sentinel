"""One-way, deterministic evidence redaction."""

import hashlib
import hmac


def fingerprint(value: str, *, namespace: str = "secret-sentinel") -> str:
    """Return a non-reversible, stable identifier for a detected value.

    The fixed namespace-derived key keeps duplicate findings correlated while
    avoiding emission of the original value.  This fingerprint is an
    identifier, not a cryptographic guarantee that a low-entropy secret is
    impossible to guess.
    """

    key = hashlib.sha256(namespace.encode("utf-8")).digest()
    return hmac.new(key, value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[
        :16
    ]


def redact(value: str) -> str:
    """Expose only a safe prefix/suffix and length, never the middle."""

    if not value:
        return "[redacted]"
    if len(value) <= 8:
        return f"[redacted:{len(value)}]"
    return f"{value[:3]}…{value[-2:]} [redacted:{len(value)}]"
