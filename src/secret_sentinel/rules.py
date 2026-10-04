"""High-confidence patterns and conservative generic-secret heuristics."""

import re
from dataclasses import dataclass
from typing import Literal

from .models import Severity


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    description: str
    severity: Severity
    pattern: re.Pattern[str]
    confidence: Literal["high", "medium"] = "high"


RULES: tuple[Rule, ...] = (
    Rule(
        "private-key",
        "Private key material",
        "critical",
        re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    ),
    Rule(
        "aws-access-key",
        "AWS access key identifier",
        "high",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    Rule(
        "github-token",
        "GitHub access token",
        "high",
        re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b"
        ),
    ),
    Rule(
        "slack-token",
        "Slack token",
        "high",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,200}\b"),
    ),
    Rule(
        "stripe-secret",
        "Stripe secret key",
        "high",
        re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b"),
    ),
    Rule(
        "google-api-key",
        "Google API key",
        "high",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ),
    Rule(
        "jwt",
        "JSON Web Token",
        "medium",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
        ),
    ),
    Rule(
        "database-url",
        "Credential-bearing database URL",
        "high",
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:@/]+:[^\s@/]+@[^\s]+",
            re.IGNORECASE,
        ),
    ),
)

ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|secret|password|passwd|token|access[_-]?token|private[_-]?key)\b\s*(?:=|:|=>)\s*[\"']([^\"']{12,})[\"']"
)
PLACEHOLDER = re.compile(
    r"(?i)^(?:changeme|change[-_ ]?me|example|sample|dummy|test|fake|placeholder|your[_-].*|<[^>]+>|\$\{[^}]+\}|\{[^}]+\})$"
)
BASE64ISH = re.compile(r"^[A-Za-z0-9+/=_-]+$")
