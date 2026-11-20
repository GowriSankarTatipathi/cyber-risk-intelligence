"""Collect website security headers for company domains (issue 1.2).

Input is a CSV ``company_key,domain`` (``python -m cyber_risk_intelligence.http_security targets``
writes one from ``company_domains``). For each domain the job asks the domain and, for a registered
domain, its ``www.`` host (see ``fetch``), stores the kept response headers as evidence, records the
request in ``http_security_checks`` and each graded header in ``http_security_observations``.

A request that failed is ``request_failed`` and gets no header rows: it is never read as missing headers.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime

from sqlalchemy import select

from ..ct.website import hosts_for
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
from ..models.http_security import HttpSecurityCheck, HttpSecurityObservation
from .assess import ASSESSMENT_VERSION, KEPT, assess
from .fetch import HeaderFetcher, PageResponse

WEBSITE_HEADERS_SOURCE = SourceSpec(
    source_key="website_headers",
    name="Company website response headers",
    source_type="other",
    access_method="api",
    notes="GET of the home page (https and http) of each company's known website; response headers only.",
)


def evidence_document(page: PageResponse) -> bytes:
    """What is stored: the request, the redirects and the security headers that were sent. Other
    headers (cookies, dates, session ids) are left out, so nothing secret is kept and an unchanged
    answer is the same bytes on every run."""
    kept = sorted([k.lower(), v] for k, v in page.headers if k.lower() in KEPT)
    return json.dumps({"requested_url": page.requested_url, "final_url": page.final_url,
                       "http_status": page.http_status, "redirects": page.redirects, "headers": kept},
                      indent=1, ensure_ascii=False).encode()


class HttpSecurityJob(Job):
    name = "http_security_headers"
    dataset_key = "http_security_targets"
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

    def __init__(self, store: ObjectStore, fetcher: HeaderFetcher | None = None):
        self.store = store
        self._fetcher = fetcher

    @property
    def fetcher(self) -> HeaderFetcher:
        if self._fetcher is None:
            self._fetcher = HeaderFetcher()
        return self._fetcher

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
        statuses = []
        for host in hosts_for(name):
            page = self.fetcher.page(host)
            plain = self.fetcher.http_redirect(host)
            now = datetime.now(UTC)
            check = HttpSecurityCheck(
                domain_id=domain.id, host=host, requested_url=page.requested_url, checked_at=now,
                outcome=page.outcome, message=page.message, final_url=page.final_url,
                http_status=page.http_status, redirects=page.redirects or None, http_redirect=plain.outcome,
                http_redirect_location=plain.location, assessment_version=ASSESSMENT_VERSION,
                ingestion_run_id=ctx.run.id)
            if page.outcome != "answered":
                s.add(check)
                statuses.append("updated")
                continue
            previous = s.scalar(select(HttpSecurityCheck.evidence_version_id).where(
                HttpSecurityCheck.host == host, HttpSecurityCheck.evidence_version_id.is_not(None))
                .order_by(HttpSecurityCheck.id.desc()).limit(1))
            try:
                version = record_evidence(
                    s, self.store, source=ensure_source(s, WEBSITE_HEADERS_SOURCE), source_url=page.requested_url,
                    content=evidence_document(page), media_type="application/json", http_status=page.http_status,
                    title=f"Security headers of {host}")
            except SecretDetected as exc:
                raise RowRejected("withheld", f"headers of {host} not stored: {exc}", "domain") from None
            check.evidence_version_id = version.id
            s.add(check)
            s.flush()
            https = (page.final_url or "").startswith("https://")
            for res in assess(page.headers, https=https):
                s.add(HttpSecurityObservation(
                    check_id=check.id, domain_id=domain.id, header=res.header, observed_value=res.value,
                    value_count=res.value_count, result=res.result, note=res.note, observed_at=now,
                    evidence_version_id=version.id))
            statuses.append("unchanged" if previous == version.id else "inserted")
        s.flush()
        if "inserted" in statuses:
            return "inserted"
        return "unchanged" if "unchanged" in statuses else "updated"
