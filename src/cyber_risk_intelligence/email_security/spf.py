"""Read SPF records (RFC 7208) out of a domain's TXT answers.

Nothing here makes a DNS query or sends mail. ``include:`` and ``redirect=``
targets are recorded, not followed, so ``dns_lookup_terms`` counts only the
terms in this record that would cost a lookup; the 10-lookup limit applies to
the whole tree, so a count over 10 here is already a problem and a lower count
is not proof the full tree is under it.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

QUALIFIERS = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
MECHANISMS = ("all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists")
LOOKUP_TERMS = ("include", "a", "mx", "ptr", "exists")  # plus redirect=
_NEEDS_VALUE = ("include", "exists", "ip4", "ip6")
_DOMAIN_SPEC = re.compile(r"^[A-Za-z0-9_.%{}+\-/=,!*]+$")  # domain names with optional macros
_MODIFIER = re.compile(r"^([A-Za-z][A-Za-z0-9_.\-]*)=(.*)$")
_SPF_START = re.compile(r"^v=spf1(\s|$)", re.IGNORECASE)


def txt_value(strings: list[str]) -> str:
    """A TXT record's character-strings joined as RFC 7208 §3.3 says: no separator."""
    return "".join(strings)


def is_spf(value: str) -> bool:
    return bool(_SPF_START.match(value.strip()))


@dataclass
class SpfRecord:
    text: str
    mechanisms: list[dict] = field(default_factory=list)  # {"qualifier", "type", "value"}
    modifiers: list[dict] = field(default_factory=list)   # {"name", "value"}
    problems: list[str] = field(default_factory=list)
    valid: bool = True  # False when a term can't be parsed (an SPF permerror)

    @property
    def all_qualifier(self) -> str | None:
        alls = [m["qualifier"] for m in self.mechanisms if m["type"] == "all"]
        return alls[0] if alls else None

    @property
    def redirect(self) -> str | None:
        return next((m["value"] for m in self.modifiers if m["name"] == "redirect"), None)

    @property
    def dns_lookup_terms(self) -> int:
        return (sum(m["type"] in LOOKUP_TERMS for m in self.mechanisms)
                + sum(m["name"] == "redirect" for m in self.modifiers))


def _bad(rec: SpfRecord, message: str) -> None:
    rec.valid = False
    rec.problems.append(message)


def _check_ip(rec: SpfRecord, kind: str, value: str) -> None:
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        _bad(rec, f"{kind}:{value} is not a valid address or network")
        return
    if (kind == "ip4") != (net.version == 4):
        _bad(rec, f"{kind}:{value} is the wrong address family")


def parse_spf(text: str) -> SpfRecord:
    rec = SpfRecord(text=text)
    terms = text.split()
    if not terms or terms[0].lower() != "v=spf1":
        _bad(rec, "does not start with v=spf1")
        return rec
    seen_modifiers: set[str] = set()
    for term in terms[1:]:
        mod = _MODIFIER.match(term)
        if mod:
            name, value = mod.group(1).lower(), mod.group(2)
            if name in seen_modifiers and name in ("redirect", "exp"):
                _bad(rec, f"{name}= appears more than once")
            seen_modifiers.add(name)
            if name in ("redirect", "exp") and not value:
                _bad(rec, f"{name}= has no domain")
            rec.modifiers.append({"name": name, "value": value})
            continue
        qualifier = "pass"
        if term[0] in QUALIFIERS:
            qualifier, term = QUALIFIERS[term[0]], term[1:]
        name, sep, value = term.partition(":")
        name = name.lower()
        if "/" in name and name.split("/")[0] in ("a", "mx"):  # a/24, mx/24//64
            name, value = name.split("/", 1)[0], "/" + term.split("/", 1)[1]
            sep = ""
        if name not in MECHANISMS:
            _bad(rec, f"unknown mechanism {term!r}")
            continue
        if name == "all" and (sep or value):
            _bad(rec, f"all takes no value: {term!r}")
            continue
        if name in _NEEDS_VALUE and not value:
            _bad(rec, f"{name} needs a value: {term!r}")
            continue
        if name in ("ip4", "ip6"):
            _check_ip(rec, name, value)
        elif value and not _DOMAIN_SPEC.match(value):
            _bad(rec, f"{name} has a malformed domain: {term!r}")
        rec.mechanisms.append({"qualifier": qualifier, "type": name, "value": value or None})

    # Not errors in the record's syntax, but worth knowing.
    if rec.dns_lookup_terms > 10:
        rec.problems.append(f"{rec.dns_lookup_terms} terms need DNS lookups; SPF allows 10 in total")
    if any(m["type"] == "ptr" for m in rec.mechanisms):
        rec.problems.append("uses ptr, which RFC 7208 says not to use")
    if rec.all_qualifier == "pass":
        rec.problems.append("+all lets any server send as this domain")
    if rec.redirect and rec.all_qualifier:
        rec.problems.append("redirect= is ignored because the record has an all mechanism")
    alls = [i for i, m in enumerate(rec.mechanisms) if m["type"] == "all"]
    if alls and alls[0] != len(rec.mechanisms) - 1:
        rec.problems.append("terms after all are never used")
    if len(text.encode()) > 450:
        rec.problems.append("record is over 450 bytes and may not fit in one UDP DNS answer")
    return rec


@dataclass
class SpfResult:
    status: str  # present / missing / multiple / invalid (no_domain and lookup_failed come from the lookup)
    record: SpfRecord | None
    records: list[str]


def read_spf(answers: list[list[str]]) -> SpfResult:
    """Find the SPF record(s) among a domain's TXT records."""
    values = [txt_value(a) for a in answers]
    spf = [v for v in values if is_spf(v)]
    if not spf:
        return SpfResult("missing", None, [])
    if len(spf) > 1:
        return SpfResult("multiple", None, spf)
    rec = parse_spf(spf[0])
    return SpfResult("present" if rec.valid else "invalid", rec, spf)
