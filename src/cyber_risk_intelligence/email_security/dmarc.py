"""Read DMARC records (RFC 7489) published at ``_dmarc.<domain>``.

Nothing here makes a DNS query or sends a report. Reporting addresses (``rua``,
``ruf``) are recorded as published; we never write to them.

Like receivers (RFC 7489 §6.3, §6.6.3), only a record that doesn't start with
``v=DMARC1`` or has no usable ``p`` is ``invalid``. Any other broken tag is
listed in ``problems`` and ignored: its default applies and the policy stands.
(A record with a broken ``p`` but a valid ``rua`` is read as ``p=none``, as the
RFC says.)

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

    policy_fallback: str | None = None  # "none" when p is unusable but rua is valid (RFC 7489 §6.6.3)

    @property
    def policy(self) -> str | None:
        p = self.tags.get("p", "").lower()
        return p if p in POLICIES else self.policy_fallback

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
        v = self.tags.get("pct", "100")
        return int(v) if v.isdigit() and int(v) <= 100 else 100

    @property
    def aggregate_reports(self) -> list[str]:
        return [u for u in _uris(self.tags.get("rua", "")) if _URI.match(u)]

    @property
    def failure_reports(self) -> list[str]:
        return [u for u in _uris(self.tags.get("ruf", "")) if _URI.match(u)]

    @property
    def defaults_used(self) -> list[str]:
        """Tags left out, or published with a value receivers ignore, so their default applies."""
        ok = {
            "sp": lambda v: v.lower() in POLICIES,
            "adkim": lambda v: v.lower() in ALIGNMENT,
            "aspf": lambda v: v.lower() in ALIGNMENT,
            "pct": lambda v: v.isdigit() and int(v) <= 100,
        }
        return [t for t, good in ok.items() if t not in self.tags or not good(self.tags[t])]


def _uris(value: str) -> list[str]:
    return [u.strip() for u in value.split(",") if u.strip()]


def _bad(rec: DmarcRecord, message: str) -> None:
    """A problem that makes receivers discard the whole record."""
    rec.valid = False
    rec.problems.append(message)


def _ignored(rec: DmarcRecord, message: str) -> None:
    """A problem receivers skip over: the tag is ignored and its default applies."""
    rec.problems.append(message + " (ignored by receivers)")


def parse_dmarc(text: str) -> DmarcRecord:
    rec = DmarcRecord(text=text)
    parts = [p.strip() for p in text.split(";")]
    for i, part in enumerate(parts):
        if not part:
            continue
        name, sep, value = part.partition("=")
        name, value = name.strip().lower(), value.strip()
        if i == 0 and (not sep or name != "v" or value.upper() != "DMARC1"):
            _bad(rec, "does not start with v=DMARC1")
            continue
        if not sep or not name:
            _ignored(rec, f"malformed tag {part!r} (expected name=value)")
            continue
        if name in rec.tags:
            _ignored(rec, f"tag {name} appears more than once; the first value is used")
            continue
        rec.tags[name] = value
        if name not in KNOWN_TAGS:
            _ignored(rec, f"unknown tag {name}")

    for tag in ("rua", "ruf"):
        for uri in _uris(rec.tags.get(tag, "")):
            if not _URI.match(uri):
                _ignored(rec, f"{tag} destination {uri!r} is not a mailto: or http(s) URI "
                              "(often a missing ';' between tags)")
    if "p" not in rec.tags or rec.tags["p"].lower() not in POLICIES:
        what = "required tag p is missing" if "p" not in rec.tags else \
            f"p={rec.tags['p']} is not none, quarantine or reject"
        if rec.valid and rec.aggregate_reports:
            rec.policy_fallback = "none"
            rec.problems.append(f"{what}; with a valid rua, receivers treat it as p=none")
        else:
            _bad(rec, what)
    for tag in ("sp", "np"):
        if tag in rec.tags and rec.tags[tag].lower() not in POLICIES:
            _ignored(rec, f"{tag}={rec.tags[tag]} is not none, quarantine or reject")
    for tag in ("adkim", "aspf"):
        if tag in rec.tags and rec.tags[tag].lower() not in ALIGNMENT:
            _ignored(rec, f"{tag}={rec.tags[tag]} must be r (relaxed) or s (strict)")
    if "pct" in rec.tags and (not rec.tags["pct"].isdigit() or not 0 <= int(rec.tags["pct"]) <= 100):
        _ignored(rec, f"pct={rec.tags['pct']} must be a whole number from 0 to 100")
    if "ri" in rec.tags and not rec.tags["ri"].isdigit():
        _ignored(rec, f"ri={rec.tags['ri']} must be a number of seconds")

    # Valid, but worth knowing.
    if rec.valid:
        if rec.pct < 100 and rec.policy in ("quarantine", "reject"):
            rec.problems.append(f"pct={rec.pct}: the policy applies to only part of failing mail")
        if not rec.aggregate_reports:
            rec.problems.append("no usable rua: the domain gets no aggregate reports")
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
