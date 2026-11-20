"""Public DNS lookups (read-only TXT and MX queries; nothing else is sent to the domain).

``DnsResolver`` wraps dnspython. Tests pass a fake with the same ``txt`` (and optionally ``mx``) method.
The resolver used is recorded on every lookup: set ``DNS_RESOLVERS`` (comma
separated IPs, e.g. ``1.1.1.1,8.8.8.8``) to choose one, otherwise the system's.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Protocol


@dataclass
class TxtLookup:
    outcome: str  # answered / no_records / nxdomain / lookup_failed
    resolver: str
    rcode: str | None = None
    answers: list[list[str]] | None = None  # each record's character-strings, as published
    ttl: int | None = None
    message: str | None = None


class Resolver(Protocol):
    def txt(self, name: str) -> TxtLookup: ...


class DnsResolver:
    def __init__(self, nameservers: list[str] | None = None, timeout: float = 5.0, pause: float = 0.2):
        import dns.resolver

        env = [ip.strip() for ip in os.environ.get("DNS_RESOLVERS", "").split(",") if ip.strip()]
        self._r = dns.resolver.Resolver(configure=not (nameservers or env))
        if nameservers or env:
            self._r.nameservers = nameservers or env
        self._r.lifetime = timeout
        self.name = ",".join(self._r.nameservers) if (nameservers or env) else \
            "system:" + ",".join(self._r.nameservers)
        self.pause = pause

    def txt(self, name: str) -> TxtLookup:
        import dns.exception
        import dns.resolver

        time.sleep(self.pause)  # be gentle with shared resolvers
        try:
            ans = self._r.resolve(name, "TXT", raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return TxtLookup("nxdomain", self.name, rcode="NXDOMAIN")
        except dns.resolver.NoNameservers as exc:
            return TxtLookup("lookup_failed", self.name, rcode="SERVFAIL", message=str(exc)[:500])
        except (dns.exception.Timeout, dns.resolver.LifetimeTimeout) as exc:
            return TxtLookup("lookup_failed", self.name, rcode="TIMEOUT", message=str(exc)[:500])
        except dns.exception.DNSException as exc:
            return TxtLookup("lookup_failed", self.name, message=f"{type(exc).__name__}: {exc}"[:500])
        if ans.rrset is None:
            return TxtLookup("no_records", self.name, rcode="NOERROR")
        records = [[s.decode("utf-8", "replace") for s in r.strings] for r in ans.rrset]
        return TxtLookup("answered", self.name, rcode="NOERROR", answers=records, ttl=ans.rrset.ttl)

    def mx(self, name: str) -> list[str] | None:
        """The mail exchanger host names of ``name`` (empty when none), or None when the lookup failed."""
        import dns.exception
        import dns.resolver

        time.sleep(self.pause)
        try:
            ans = self._r.resolve(name, "MX", raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return []
        except dns.exception.DNSException:
            return None
        return [str(r.exchange).lower().rstrip(".") for r in ans.rrset] if ans.rrset is not None else []
