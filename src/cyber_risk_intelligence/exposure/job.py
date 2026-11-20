"""Look up each company host's IPs in Shodan InternetDB (issue 10.3).

Hosts asked, per company domain: the website hosts (the domain, plus ``www.`` for a registered
domain), the domain's MX hosts that sit under one of the company's own domains, and (``side_hosts``)
up to that many side hosts named in the company's CT certificates (see ``side_hosts``). A mail host run
by a provider (Microsoft, Proofpoint, Google ...) is skipped: its IPs serve thousands of companies.
Each host is resolved through public DNS (A records); each IP is then looked up in InternetDB, once
per run. Nothing is sent to the hosts or IPs themselves.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select, update

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
from .side_hosts import side_hosts

INTERNETDB_SOURCE = SourceSpec(
    source_key=SOURCE,
    name="Shodan InternetDB",
    source_type="other",
    access_method="api",
    notes="https://internetdb.shodan.io/<ip>: ports, CPEs, inferred CVEs, host names and tags from Shodan's "
          "own scans. Free, no key. Indexed data, not verification; no scan date given.",
)
MAX_IPS_PER_HOST = 8
OWN_ATTRIBUTIONS = ("company_only", "unknown")


def _within(name: str, domains: set[str]) -> bool:
    name = name.lower().rstrip(".")
    return any(name == d or name.endswith("." + d) for d in domains)


class IndexedExposureJob(_TxtJob):
    name = "indexed_exposure"
    dataset_key = "indexed_exposure_targets"

    def __init__(self, store: ObjectStore, resolver=None, client: InternetDbClient | None = None,
                 side_hosts: int = 0):
        super().__init__(store, resolver)
        self._client = client
        self.side_hosts = side_hosts
        self.side_hosts_asked = 0  # how many side hosts were chosen this run, over how many domains
        self.domains_with_side_hosts = 0
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
        hosts = [(h, "website", None) for h in hosts_for(domain.name)]
        mx = getattr(self.resolver, "mx", None)
        hosts += [(m, "mail", None) for m in (mx(domain.name) or [] if mx else []) if _within(m, own)
                  and m not in {h for h, _, _ in hosts}]
        side = side_hosts(s, domain.id, domain.name, self.side_hosts, {h for h, _, _ in hosts})
        self.side_hosts_asked += len(side)
        self.domains_with_side_hosts += bool(side)
        hosts += [(h, "certificate_name", hint) for h, hint in side]
        statuses = []
        for host, role, hint in hosts:
            ips = self.resolver.a(host)
            now = datetime.now(UTC)
            base = {"company_id": company.id, "domain_id": domain.id, "host": host, "host_role": role, "name_hint": hint,
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

    @staticmethod
    def _other_company(s, base: dict, ip: str) -> bool:
        """Whether another company's host pointed to this IP earlier in the run. If so the IP serves
        more than one organization (a shared cloud front end), so it is no one's own: the earlier rows
        are marked ``shared`` too, and the caller marks this one."""
        others = s.scalars(select(IndexedHostLookup.id).where(
            IndexedHostLookup.ingestion_run_id == base["ingestion_run_id"], IndexedHostLookup.ip == ip,
            IndexedHostLookup.company_id != base["company_id"])).all()
        if not others:
            return False
        s.execute(update(IndexedHostLookup).where(IndexedHostLookup.id.in_(others),
                                                  IndexedHostLookup.attribution.in_(OWN_ATTRIBUTIONS))
                  .values(attribution="shared"))
        s.execute(update(IndexedServiceObservation).where(IndexedServiceObservation.lookup_id.in_(others),
                                                          IndexedServiceObservation.attribution.in_(OWN_ATTRIBUTIONS))
                  .values(attribution="shared"))
        return True

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
        row.attribution = attribution(d, own, ip)
        if row.attribution in OWN_ATTRIBUTIONS and self._other_company(s, base, ip):
            row.attribution = "shared"
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
