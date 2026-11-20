"""DKIM keys at selectors known from public evidence (issue 23.3).

A DKIM key lives at ``<selector>._domainkey.<domain>``, and the selector is chosen by whoever sends
the mail. It cannot be discovered from DNS, and guessing many names would be brute force, which we
don't do. We ask only selectors that public evidence ties to the domain:

* **Email providers named in the domain's own SPF record.** Some providers document fixed selectors.
  If a company's SPF (followed through its includes, at most 10 lookups as SPF itself allows)
  authorizes ``spf.protection.outlook.com``, Microsoft documents that its DKIM keys are at
  ``selector1`` and ``selector2``. The provider, the SPF include that named it and the provider's
  documentation are stored with every result.
* **Email providers shown by the domain's own MX records or provider verification record.** Mail
  delivered to ``*.mail.protection.outlook.com``, or an ``MS=`` TXT record (Microsoft's proof that
  the domain is added to a Microsoft 365 tenant), shows Microsoft 365; MX at Google shows Google
  Workspace. Many companies put a filter (Proofpoint, Mimecast) in their SPF and MX, so the SPF
  record alone misses them. The record that showed the provider is stored with every result.
* **Selectors supplied with a public source** (a CSV ``company_key,domain,selector,source_url``),
  for example a selector seen in the headers of a mail the company published.

A key not found at a known selector says nothing about DKIM at other selectors. With no known
selector the result is ``no_known_selector``: unknown, never "no DKIM".
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass

from .spf import read_spf

MAX_SPF_LOOKUPS = 10


@dataclass(frozen=True)
class Provider:
    name: str
    spf_includes: tuple[str, ...]  # an include equal to, or ending in, one of these names the provider
    selectors: tuple[str, ...]
    source_url: str  # the provider's documentation of these selectors
    mx_hosts: tuple[str, ...] = ()  # an MX host equal to, or ending in, one of these names the provider
    verification_prefix: str | None = None  # a TXT record at the domain starting with this names the provider


PROVIDERS = (
    Provider("Microsoft 365", ("spf.protection.outlook.com",), ("selector1", "selector2"),
             "https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dkim-configure",
             mx_hosts=("mail.protection.outlook.com",), verification_prefix="MS="),
    Provider("Google Workspace", ("_spf.google.com",), ("google",),
             "https://support.google.com/a/answer/174124",
             mx_hosts=("aspmx.l.google.com", "googlemail.com", "smtp.google.com")),
    Provider("Mailchimp", ("servers.mcsv.net",), ("k2", "k3"),
             "https://mailchimp.com/help/set-up-email-domain-authentication/"),
    Provider("SendGrid", ("sendgrid.net",), ("s1", "s2"),
             "https://www.twilio.com/docs/sendgrid/ui/account-and-settings/how-to-set-up-domain-authentication"),
    Provider("Zendesk", ("mail.zendesk.com",), ("zendesk1", "zendesk2"),
             "https://support.zendesk.com/hc/en-us/articles/4408832543770"),
)


@dataclass
class KnownSelector:
    selector: str
    source: str  # spf_provider / mail_provider / published
    evidence: str  # why we know it, in words
    source_url: str


def _matches(name: str, include: str) -> bool:
    name = name.lower().rstrip(".")
    return name == include or name.endswith("." + include)


def spf_includes(domain: str, txt) -> tuple[list[tuple[str, str]], int]:
    """Every include/redirect target reachable from ``domain``'s SPF record, as (target, path) where path
    says how it was reached; and how many DNS lookups that took (at most MAX_SPF_LOOKUPS, as SPF allows)."""
    found: list[tuple[str, str]] = []
    queue = [(domain, domain)]
    seen = {domain}
    lookups = 0
    while queue and lookups < MAX_SPF_LOOKUPS:
        name, path = queue.pop(0)
        lookups += 1
        answer = txt(name)
        if answer.outcome != "answered":
            continue
        spf = read_spf(answer.answers or [])
        if spf.record is None:
            continue
        targets = [m["value"] for m in spf.record.mechanisms if m["type"] == "include" and m["value"]]
        if spf.record.redirect:
            targets.append(spf.record.redirect)
        for t in targets:
            t = t.lower().rstrip(".")
            step = f"{path} -> {t}"
            found.append((t, step))
            if t not in seen and "%" not in t:  # macros can't be followed without a message
                seen.add(t)
                queue.append((t, step))
    return found, lookups


def selectors_from_spf(domain: str, txt) -> list[KnownSelector]:
    includes, _ = spf_includes(domain, txt)
    out: list[KnownSelector] = []
    done: set[str] = set()
    for target, path in includes:
        for p in PROVIDERS:
            if p.name in done or not any(_matches(target, inc) for inc in p.spf_includes):
                continue
            done.add(p.name)
            for sel in p.selectors:
                out.append(KnownSelector(sel, "spf_provider", f"SPF authorizes {p.name} ({path}); "
                                         f"{p.name} documents DKIM selector {sel!r}", p.source_url))
    return out


def selectors_from_mail_records(domain: str, txt, mx) -> list[KnownSelector]:
    """Providers shown by the domain's MX hosts (``mx(name)`` -> host names, or None if the lookup
    failed) or by a provider's domain verification TXT record at the domain."""
    out: list[KnownSelector] = []
    hosts = (mx(domain) or []) if mx is not None else []
    answer = txt(domain)
    values = ["".join(a) for a in answer.answers or []] if answer.outcome == "answered" else []
    for p in PROVIDERS:
        why = next((f"MX {h} is {p.name}" for h in hosts if any(_matches(h, m) for m in p.mx_hosts)), None)
        if why is None and p.verification_prefix:
            why = next((f"{domain} publishes {p.name}'s domain verification record ({v.strip()[:40]})"
                        for v in values if v.strip().startswith(p.verification_prefix)), None)
        if why:
            out += [KnownSelector(sel, "mail_provider", f"{why}; {p.name} documents DKIM selector {sel!r}",
                                  p.source_url) for sel in p.selectors]
    return out


@dataclass
class DkimKey:
    status: str  # key_found / revoked / invalid
    key_type: str | None = None
    key_bits: int | None = None
    problem: str | None = None


def read_dkim(value: str) -> DkimKey:
    """One DKIM TXT record (its strings already joined)."""
    tags = {}
    for part in value.split(";"):
        name, sep, arg = part.strip().partition("=")
        if sep:
            tags[name.strip().lower()] = "".join(arg.split())
    if tags.get("v") not in (None, "DKIM1"):
        return DkimKey("invalid", problem=f"v={tags.get('v')} is not DKIM1")
    if "p" not in tags:
        return DkimKey("invalid", problem="no p= (public key) tag")
    key_type = (tags.get("k") or "rsa").lower()
    if tags["p"] == "":
        return DkimKey("revoked", key_type, problem="empty p=: the key was revoked")
    try:
        der = base64.b64decode(tags["p"], validate=True)
    except (binascii.Error, ValueError):
        return DkimKey("invalid", key_type, problem="p= is not base64")
    if key_type == "ed25519":
        return DkimKey("key_found", key_type, 256) if len(der) == 32 else \
            DkimKey("invalid", key_type, problem="ed25519 key is not 32 bytes")
    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key

        bits = load_der_public_key(der).key_size
    except (ValueError, TypeError):
        return DkimKey("invalid", key_type, problem="p= is not a readable public key")
    return DkimKey("key_found", key_type, bits, "RSA key under 1024 bits" if bits < 1024 else None)
