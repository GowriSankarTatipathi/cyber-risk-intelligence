"""Refuse to store evidence that contains credentials.

Public pages sometimes leak keys. We never keep a working secret, so content
that matches these patterns is rejected before it reaches storage or logs.
The match itself is never included in error messages.
"""

import re

_PATTERNS: dict[str, re.Pattern[bytes]] = {
    "private_key": re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
    "aws_access_key_id": re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github_token": re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
    "slack_token": re.compile(rb"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "stripe_live_key": re.compile(rb"\b[sr]k_live_[A-Za-z0-9]{20,}\b"),
    "google_api_key": re.compile(rb"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "jwt": re.compile(rb"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "url_with_password": re.compile(rb"\b[a-z][a-z0-9+.\-]*://[^\s/:@]+:[^\s/@]+@[^\s/]+", re.IGNORECASE),
    "password_assignment": re.compile(
        rb"""(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token)["']?\s*[:=]\s*["']?[^\s"'<>]{8,}"""
    ),
}


class SecretDetected(ValueError):
    def __init__(self, kinds: list[str]):
        self.kinds = kinds
        super().__init__(f"Evidence rejected: looks like it contains secrets ({', '.join(kinds)})")


def find_secrets(content: bytes) -> list[str]:
    """Names of the secret patterns found in ``content`` (never the values)."""
    return [name for name, pattern in _PATTERNS.items() if pattern.search(content)]
