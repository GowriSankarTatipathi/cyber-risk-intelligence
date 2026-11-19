"""Collect SPF records for company domains (issue 23.1).

Input is a CSV ``company_key,domain`` (``python -m cyber_risk_intelligence.email_security targets``
writes one from ``company_domains``). For each row the job asks a public resolver for the
domain's TXT records, stores the answer as evidence, records the lookup in
``dns_security_records`` and what it shows about SPF in ``email_security_observations``.

Only TXT queries are made. No mail is sent and nothing on the company's servers is contacted
directly. A failed lookup is ``lookup_failed``: it is never read as "no SPF".
"""

from __future__ import annotations

import csv
import io
import json

from sqlalchemy import select

from ..domains import normalize_domain
from ..evidence import SecretDetected, record_evidence
from ..evidence.store import ObjectStore
from ..ingest.framework import (
    InputRow,
    Job,
    RowRejected,
    RowStatus,
    Rule,
    SourceSpec,
    WriteContext,
    ensure_source,
)
from ..models import Company, CompanyDomain, Domain
from ..models.email_security import DnsSecurityRecord, EmailSecurityObservation
from .dns import DnsResolver, Resolver
from .spf import read_spf

DNS_SOURCE = SourceSpec(
    source_key="public_dns",
    name="Public DNS (TXT records)",
    source_type="other",
    access_method="api",
    notes="Read-only DNS queries through a recursive resolver; what a domain publishes for anyone to read.",
)


def answer_document(query_name: str, record_type: str, outcome: str, rcode: str | None,
                    answers: list[list[str]] | None) -> bytes:
    """The stored evidence: what DNS returned, without the time or resolver, so an unchanged
    answer is the same bytes (and the same evidence object) on every run."""
    return json.dumps({"query": query_name, "type": record_type, "outcome": outcome, "rcode": rcode,
                       "answers": sorted(answers or [])}, indent=1, ensure_ascii=False).encode()


class SpfJob(Job):
    name = "spf"
    dataset_key = "spf_targets"
    media_type = "text/csv"
    source = SourceSpec(
        source_key="project_domain_targets",
        name="Project domain target list",
        source_type="dataset",
        access_method="manual",
    )
    rules = (
        Rule("company_key_required", lambda r: None if r.get("company_key") else "company_key is empty",
             field="company_key"),
        Rule("domain_valid", lambda r: None if normalize_domain(r.get("domain", ""))
             else f"{r.get('domain')!r} is not a domain name", field="domain"),
    )

    def __init__(self, store: ObjectStore, resolver: Resolver | None = None):
        self.store = store
        self._resolver = resolver

    @property
    def resolver(self) -> Resolver:
        if self._resolver is None:
            self._resolver = DnsResolver()
        return self._resolver

    def parse(self, content: bytes):
        reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig")))
        if not reader.fieldnames or not {"company_key", "domain"} <= set(reader.fieldnames):
            raise ValueError("target CSV needs company_key and domain columns")
        for number, raw in enumerate(reader, start=1):
            data = {k.strip(): (v or "").strip() for k, v in raw.items() if k}
            yield InputRow(number, f"{data.get('company_key')}|{normalize_domain(data.get('domain', ''))}", data)

    def write(self, ctx: WriteContext) -> RowStatus:
        s, r = ctx.session, ctx.row.data
        company = s.scalar(select(Company).where(Company.company_key == r["company_key"]))
        if company is None:
            raise RowRejected("unknown_company", f"no company with key {r['company_key']!r}", "company_key")
        name = normalize_domain(r["domain"])
        domain = s.scalar(select(Domain).join(CompanyDomain, CompanyDomain.domain_id == Domain.id).where(
            Domain.name == name, CompanyDomain.company_id == company.id))
        if domain is None:
            raise RowRejected("domain_not_linked", f"{name} is not a known domain of {r['company_key']}; "
                                                   "import it with company-domains first", "domain")

        lookup = self.resolver.txt(name)
        dns_row = DnsSecurityRecord(
            domain_id=domain.id, query_name=name, record_type="TXT", resolver=lookup.resolver,
            outcome=lookup.outcome, rcode=lookup.rcode, message=lookup.message,
            answers=lookup.answers if lookup.outcome == "answered" else None, ttl=lookup.ttl,
            ingestion_run_id=ctx.run.id)
        version = None
        if lookup.outcome != "lookup_failed":
            try:
                version = record_evidence(
                    s, self.store, source=ensure_source(s, DNS_SOURCE), source_url=f"dns:{name}/TXT",
                    content=answer_document(name, "TXT", lookup.outcome, lookup.rcode, lookup.answers),
                    media_type="application/json", title=f"TXT records for {name}")
            except SecretDetected as exc:
                raise RowRejected("withheld", f"TXT answer for {name} not stored: {exc}", "domain") from None
            dns_row.evidence_version_id = version.id
        previous = s.scalar(select(DnsSecurityRecord.evidence_version_id).where(
            DnsSecurityRecord.domain_id == domain.id, DnsSecurityRecord.record_type == "TXT")
            .order_by(DnsSecurityRecord.id.desc()).limit(1))
        s.add(dns_row)
        s.flush()

        obs = EmailSecurityObservation(
            company_id=company.id, domain_id=domain.id, dns_record_id=dns_row.id, control="spf",
            observed_at=dns_row.queried_at, evidence_version_id=version.id if version else None,
            source_ref=f"dns:{name}/TXT via {lookup.resolver}")
        if lookup.outcome == "lookup_failed":
            obs.status = "lookup_failed"
            obs.problems = [lookup.message or lookup.rcode or "lookup failed"]
        elif lookup.outcome == "nxdomain":
            obs.status = "no_domain"
        else:
            spf = read_spf(lookup.answers or [])
            obs.status = spf.status
            obs.record_count = len(spf.records)
            obs.record_text = "\n".join(spf.records) or None
            if spf.status == "multiple":
                obs.problems = [f"{len(spf.records)} SPF records published; receivers treat this as an error"]
            if spf.record is not None:
                rec = spf.record
                obs.all_qualifier, obs.redirect = rec.all_qualifier, rec.redirect
                obs.mechanisms, obs.modifiers = rec.mechanisms, rec.modifiers
                obs.dns_lookup_terms, obs.problems = rec.dns_lookup_terms, rec.problems or None
        s.add(obs)
        s.flush()
        # Every lookup is kept (it is an observation at a time); the answer itself is stored once.
        return "unchanged" if version is not None and previous == version.id else "inserted"


def targets_csv(s) -> bytes:
    """company_key,domain for every current company domain."""
    rows = s.execute(select(Company.company_key, Domain.name).join(CompanyDomain, CompanyDomain.company_id == Company.id)
                     .join(Domain, Domain.id == CompanyDomain.domain_id).where(CompanyDomain.valid_to.is_(None))
                     .distinct().order_by(Company.company_key, Domain.name)).all()
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["company_key", "domain"])
    w.writerows(rows)
    return buf.getvalue().encode()
