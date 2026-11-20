"""Pick a company's side hosts from its Certificate Transparency names (issues 10.1 and 10.3).

A company's exposure is rarely on its website: it is on names like ``vpn.``, ``remote.``,
``owa.`` or ``sftp.``. Those names are already public in the certificates we collected from CT
logs (``certificate_hostnames``). From them we choose, per company domain, a capped list:

* only exact names (no wildcards) under the domain, from certificates valid within the last year;
* names whose labels suggest an internet-facing service go first (remote access, file transfer,
  admin consoles, mail, sign-in, development tools), then the most recently certified names.

The chosen names are only resolved in public DNS and their IPs looked up in Shodan's index.
Nothing is sent to the hosts themselves, and no name is guessed: every name comes from a
certificate the company had issued.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select

from ..models.certificates import Certificate, CertificateHostname

RECENT = timedelta(days=365)

# Label words that suggest a service exposed to the internet, by kind; the weight orders them.
HINTS: dict[str, tuple[int, frozenset[str]]] = {
    "remote_access": (6, frozenset({
        "vpn", "sslvpn", "remote", "citrix", "netscaler", "gateway", "gw", "rdp", "rdweb", "rdgateway", "rds",
        "vdi", "horizon", "globalprotect", "anyconnect", "pulse", "ivanti", "fortigate", "forti", "asa", "ra",
        "access", "connect", "workspace", "ztna", "zscaler"})),
    "file_transfer": (5, frozenset({"ftp", "sftp", "ftps", "mft", "files", "transfer", "sharefile", "upload"})),
    "admin": (5, frozenset({"admin", "manage", "mgmt", "management", "console", "cpanel", "plesk", "ilo", "idrac",
                            "kvm", "panel"})),
    "mail": (4, frozenset({"owa", "webmail", "mail", "exchange", "smtp", "imap", "pop", "autodiscover", "mx"})),
    "identity": (4, frozenset({"sso", "adfs", "fs", "sts", "login", "auth", "idp", "okta", "saml", "mfa"})),
    "development": (3, frozenset({"jira", "confluence", "git", "gitlab", "github", "jenkins", "bitbucket", "dev",
                                  "test", "staging", "stage", "uat", "qa", "sandbox", "api", "grafana", "kibana"})),
}
NAME_HINTS = tuple(HINTS)
_SPLIT = re.compile(r"[.\-_0-9]+")


def name_hint(hostname: str, domain: str) -> str | None:
    """The kind of service a name's own labels suggest (``vpn2.eu.acme.com`` -> remote_access), or None."""
    words = set(_SPLIT.split(hostname.lower().removesuffix("." + domain)))
    best = max(((w, kind) for kind, (w, names) in HINTS.items() if words & names), default=None)
    return best[1] if best else None


def side_hosts(s, domain_id: int, domain: str, limit: int, skip: set[str], now: datetime | None = None
               ) -> list[tuple[str, str | None]]:
    """Up to ``limit`` (hostname, name_hint) pairs for the domain, from recent CT certificates."""
    if limit <= 0:
        return []
    since = (now or datetime.now(UTC)) - RECENT
    rows = s.execute(
        select(CertificateHostname.hostname, func.max(Certificate.not_after).label("latest"))
        .join(Certificate, Certificate.id == CertificateHostname.certificate_id)
        .where(CertificateHostname.domain_id == domain_id, CertificateHostname.is_wildcard.is_(False),
               CertificateHostname.hostname.like("%." + domain), Certificate.not_after >= since)
        .group_by(CertificateHostname.hostname)).all()
    ranked = []
    for name, latest in rows:
        name = name.lower().rstrip(".")
        if name in skip or not re.fullmatch(r"[a-z0-9.-]+", name):
            continue
        hint = name_hint(name, domain)
        ranked.append((-(HINTS[hint][0] if hint else 0), -(latest.timestamp() if latest else 0), name, hint))
    ranked.sort()
    return [(name, hint) for _, _, name, hint in ranked[:limit]]
