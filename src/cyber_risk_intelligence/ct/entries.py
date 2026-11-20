"""What a Certificate Transparency search returns, whichever index answered it."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

_HOST_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
DEFAULT_USER_AGENT = "cyber-risk-intelligence/0.1 (passive CT lookup)"


@dataclass
class CtEntry:
    """One certificate as the index reports it.

    crt.sh lists the precertificate and the final certificate as two entries (same issuer and
    serial number); Cert Spotter lists one issuance per certificate (identified by the SHA-256 of
    its to-be-signed part, which the precertificate shares)."""

    entry_id: str  # the index's own id for this entry
    source_ref: str  # a public link to it
    issuer_name: str
    names: list[str]  # valid DNS names (lower-case), wildcards included
    serial_number: str | None = None  # lower-case hex (crt.sh)
    tbs_sha256: str | None = None  # Cert Spotter
    cert_sha256: str | None = None
    issuer_ca_id: int | None = None
    common_name: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    revoked: bool | None = None

    @property
    def key(self) -> tuple[str, str]:
        return ("tbs", self.tbs_sha256) if self.tbs_sha256 else ("serial", f"{self.issuer_name}\x1f{self.serial_number}")


@dataclass
class CtLookupResult:
    source: str  # certspotter / crt.sh
    outcome: str  # answered / no_results / lookup_failed
    request_url: str
    http_status: int | None = None
    message: str | None = None
    content: bytes | None = None
    entries: list[CtEntry] = field(default_factory=list)
    pages: int | None = None
    complete: bool = True  # False when the search stopped before the last page
    deferred: bool = False  # rate limited part-way; the search can pick up where it stopped later


def when(value) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value))  # Python 3.11+ reads a trailing Z
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)  # crt.sh gives UTC without an offset


def clean_name(value: str) -> str | None:
    """A DNS name from a certificate, lower-case, or None for e-mail addresses, IPs and junk."""
    v = (value or "").strip().lower().rstrip(".")
    if not v or "@" in v or " " in v or "/" in v or ":" in v:
        return None
    labels = v.split(".")
    if len(labels) < 2 or labels[-1].isdigit():
        return None
    first = 1 if labels[0] == "*" else 0
    if not all(_HOST_LABEL.match(x) for x in labels[first:]):
        return None
    return v


def names_of(raw: list[str]) -> list[str]:
    return list(dict.fromkeys(n for n in (clean_name(x) for x in raw) if n))
