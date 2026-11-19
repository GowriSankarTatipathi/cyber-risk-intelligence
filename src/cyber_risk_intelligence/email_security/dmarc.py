"""Read DMARC records (RFC 7489) published at ``_dmarc.<domain>``.

Nothing here makes a DNS query or sends a report. Reporting addresses (``rua``,
``ruf``) are recorded as published; we never write to them.

Tags that are left out take the RFC's defaults (alignment ``relaxed``, ``pct=100``,
``sp`` = ``p``). Each parsed value says whether it was published or defaulted,
so "relaxed because the record says so" and "relaxed by default" stay apart.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .spf import txt_value

POLICIES = ("none", "quarantine", "reject")
ALIGNMENT = {"r": "relaxed", "s": "strict"}
KNOWN_TAGS = ("v", "p", "sp", "np", "adkim", "aspf", "pct", "rua", "ruf", "fo", "rf", "ri", "psd", "t")
_DMARC_START = re.compile(r"^\s*v\s*=\s*DMARC1\b", re.IGNORECASE)
_URI = re.compile(r"^(mailto:[^\s,!]+@[^\s,!]+|https?://[^\s,!]+)(![0-9]+[kmgt]?)?$", re.IGNORECASE)

# Second-level labels under which registries sell names (example.co.uk, example.com.mx ...).
_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac", "ne", "or", "gob"}


def organizational_domain(name: str) -> str:
    """A simple approximation of RFC 7489's organizational domain (no full public-suffix list)."""
    labels = name.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_dmarc(value: str) -> bool:
    return bool(_DMARC_START.match(value))


@dataclass
class DmarcRecord:
    text: str
    tags: dict[str, str] = field(default_factory=dict)  # as published, lower-cased names
    problems: list[str] = field(default_factory=list)
    valid: bool = True

    @property
    def policy(self) -> str | None:
        p = self.tags.get("p", "").lower()
        return p if p in POLICIES else None

    @property
    def subdomain_policy(self) -> str | None:
        sp = self.tags.get("sp", "").lower()
        return sp if sp in POLICIES else self.policy

    @property
    def dkim_alignment(self) -> str:
        return ALIGNMENT.get(self.tags.get("adkim", "r").lower(), "relaxed")

    @property
    def spf_alignment(self) -> str:
        return ALIGNMENT.get(self.tags.get("aspf", "r").lower(), "relaxed")

    @property
    def pct(self) -> int:
        try:
            return int(self.tags.get("pct", "100"))
        except ValueError:
            return 100

    @property
    def aggregate_reports(self) -> list[str]:
        return _uris(self.tags.get("rua", ""))

    @property
    def failure_reports(self) -> list[str]:
        return _uris(self.tags.get("ruf", ""))

    @property
    def defaults_used(self) -> list[str]:
        return [t for t in ("sp", "adkim", "aspf", "pct") if t not in self.tags]


def _uris(value: str) -> list[str]:
    return [u.strip() for u in value.split(",") if u.strip()]


def _bad(rec: DmarcRecord, message: str) -> None:
    rec.valid = False
    rec.problems.append(message)


def parse_dmarc(text: str) -> DmarcRecord:
    rec = DmarcRecord(text=text)
    parts = [p.strip() for p in text.split(";")]
    for i, part in enumerate(parts):
        if not part:
            continue
        name, sep, value = part.partition("=")
        name, value = name.strip().lower(), value.strip()
        if not sep or not name:
            _bad(rec, f"malformed tag {part!r} (expected name=value)")
            continue
        if i == 0 and (name != "v" or value.upper() != "DMARC1"):
            _bad(rec, "does not start with v=DMARC1")
        if name in rec.tags:
            _bad(rec, f"tag {name} appears more than once")
            continue
        rec.tags[name] = value
        if name not in KNOWN_TAGS:
            rec.problems.append(f"unknown tag {name} (ignored by receivers)")

    if "p" not in rec.tags:
        _bad(rec, "required tag p is missing")
    elif rec.tags["p"].lower() not in POLICIES:
        _bad(rec, f"p={rec.tags['p']} is not none, quarantine or reject")
    for tag in ("sp", "np"):
        if tag in rec.tags and rec.tags[tag].lower() not in POLICIES:
            _bad(rec, f"{tag}={rec.tags[tag]} is not none, quarantine or reject")
    for tag in ("adkim", "aspf"):
        if tag in rec.tags and rec.tags[tag].lower() not in ALIGNMENT:
            _bad(rec, f"{tag}={rec.tags[tag]} must be r (relaxed) or s (strict)")
    if "pct" in rec.tags and (not rec.tags["pct"].isdigit() or not 0 <= int(rec.tags["pct"]) <= 100):
        _bad(rec, f"pct={rec.tags['pct']} must be a whole number from 0 to 100")
    for tag in ("rua", "ruf"):
        for uri in _uris(rec.tags.get(tag, "")):
            if not _URI.match(uri):
                _bad(rec, f"{tag} destination {uri!r} is not a mailto: or http(s) URI")
    if "ri" in rec.tags and not rec.tags["ri"].isdigit():
        _bad(rec, f"ri={rec.tags['ri']} must be a number of seconds")

    # Valid, but worth knowing.
    if rec.valid:
        if rec.pct < 100 and rec.policy in ("quarantine", "reject"):
            rec.problems.append(f"pct={rec.pct}: the policy applies to only part of failing mail")
        if not rec.aggregate_reports:
            rec.problems.append("no rua: the domain asks for no aggregate reports")
    return rec


@dataclass
class DmarcResult:
    status: str  # present / missing / multiple / invalid
    record: DmarcRecord | None
    records: list[str]


def read_dmarc(answers: list[list[str]]) -> DmarcResult:
    """Find the DMARC record among the TXT records at ``_dmarc.<domain>``."""
    values = [txt_value(a) for a in answers]
    found = [v for v in values if is_dmarc(v)]
    if not found:
        return DmarcResult("missing", None, [])
    if len(found) > 1:
        return DmarcResult("multiple", None, found)
    rec = parse_dmarc(found[0])
    return DmarcResult("present" if rec.valid else "invalid", rec, found)
