"""Look up each company host's IPs in Shodan InternetDB (issue 10.3).

Hosts asked, per company domain: the website hosts (the domain, plus ``www.`` for a registered
domain) and the domain's MX hosts that sit under one of the company's own domains. A mail host run
by a provider (Microsoft, Proofpoint, Google ...) is skipped: its IPs serve thousands of companies.
Each host is resolved through public DNS (A records); each IP is then looked up in InternetDB, once
per run. Nothing is sent to the hosts or IPs themselves.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select

from ..ct.website import hosts_for
from ..email_security.job import _TxtJob
from ..evidence import SecretDetected, record_evidence
from ..evidence.store import ObjectStore
from ..ingest.framework import (
    RowRejected,
    RowStatus,
    SourceSpec,
    WriteContext,
    ensure_source,
)
from ..models import CompanyDomain, Domain
from ..models.exposure import IndexedHostLookup, IndexedServiceObservation
from .internetdb import (
    SENSITIVE_PORTS,
    SERVICE_HINTS,
    SOURCE,
    HostRecord,
    InternetDbClient,
    attribution,
)

INTERNETDB_SOURCE = SourceSpec(
    source_key=SOURCE,
    name="Shodan InternetDB",
    source_type="other",
    access_method="api",
    notes="https://internetdb.shodan.io/<ip>: ports, CPEs, inferred CVEs, host names and tags from Shodan's "
          "own scans. Free, no key. Indexed data, not verification; no scan date given.",
)
MAX_IPS_PER_HOST = 8


def _within(name: str, domains: set[str]) -> bool:
    name = name.lower().rstrip(".")
    return any(name == d or name.endswith("." + d) for d in domains)


class IndexedExposureJob(_TxtJob):
    name = "indexed_exposure"
    dataset_key = "indexed_exposure_targets"

    def __init__(self, store: ObjectStore, resolver=None, client: InternetDbClient | None = None):
        super().__init__(store, resolver)
        self._client = client
        self._seen: dict[str, HostRecord] = {}  # one InternetDB lookup per IP per run

    @property
    def client(self) -> InternetDbClient:
        if self._client is None:
            self._client = InternetDbClient()
        return self._client

    def _record(self, ip: str) -> HostRecord:
        if ip not in self._seen:
            self._seen[ip] = self.client.host(ip)
        return self._seen[ip]

    def write(self, ctx: WriteContext) -> RowStatus:
        company, domain = self._target(ctx)
        s = ctx.session
        own = set(s.scalars(select(Domain.name).join(CompanyDomain, CompanyDomain.domain_id == Domain.id).where(
            CompanyDomain.company_id == company.id, CompanyDomain.valid_to.is_(None))).all()) | {domain.name}
        hosts = [(h, "website") for h in hosts_for(domain.name)]
        mx = getattr(self.resolver, "mx", None)
        hosts += [(m, "mail") for m in (mx(domain.name) or [] if mx else []) if _within(m, own)
                  and m not in {h for h, _ in hosts}]
        statuses = []
        for host, role in hosts:
            ips = self.resolver.a(host)
            now = datetime.now(UTC)
            base = {"company_id": company.id, "domain_id": domain.id, "host": host, "host_role": role,
                    "source": SOURCE, "retrieved_at": now, "ingestion_run_id": ctx.run.id}
            if not ips:
                s.add(IndexedHostLookup(**base, outcome="dns_failed" if ips is None else "no_address",
                                        message="A lookup failed" if ips is None else "no A record"))
                statuses.append("updated" if ips is None else "inserted")
                continue
            for ip in ips[:MAX_IPS_PER_HOST]:
                statuses.append(self._lookup(s, base, ip, own))
        s.flush()
        if "inserted" in statuses:
            return "inserted"
        return "unchanged" if "unchanged" in statuses else "updated"

    def _lookup(self, s, base: dict, ip: str, own: set[str]) -> RowStatus:
        rec = self._record(ip)
        row = IndexedHostLookup(**base, ip=ip, outcome=rec.outcome, message=rec.message)
        if rec.outcome != "found":
            s.add(row)
            return "updated" if rec.outcome == "lookup_failed" else "inserted"
        previous = s.scalar(select(IndexedHostLookup.evidence_version_id).where(
            IndexedHostLookup.ip == ip, IndexedHostLookup.evidence_version_id.is_not(None))
            .order_by(IndexedHostLookup.id.desc()).limit(1))
        try:
            version = record_evidence(s, self.store, source=ensure_source(s, INTERNETDB_SOURCE), source_url=rec.url,
                                      content=rec.document(), media_type="application/json", http_status=200,
                                      title=f"Shodan InternetDB record for {ip}")
        except SecretDetected as exc:
            raise RowRejected("withheld", f"InternetDB answer for {ip} not stored: {exc}", "domain") from None
        d = rec.data or {}
        row.evidence_version_id = version.id
        row.attribution = attribution(d, own)
        row.tags, row.hostnames = sorted(d.get("tags") or []) or None, sorted(d.get("hostnames") or []) or None
        row.cpes, row.potential_vulns = sorted(d.get("cpes") or []) or None, sorted(d.get("vulns") or []) or None
        s.add(row)
        s.flush()
        for port in sorted({int(p) for p in d.get("ports") or [] if 0 < int(p) < 65536}):
            s.add(IndexedServiceObservation(
                lookup_id=row.id, company_id=row.company_id, domain_id=row.domain_id, ip=ip, port=port,
                service_hint=SERVICE_HINTS.get(port), sensitive=port in SENSITIVE_PORTS, attribution=row.attribution,
                source=SOURCE, observed_at=row.retrieved_at, evidence_version_id=version.id))
        return "unchanged" if previous == version.id else "inserted"
