"""Import which domains belong to which company.

Input is a CSV ``company_key,domain,role,source_url[,notes]``. ``domain`` may be
a bare name or a website URL (``https://www.acme.com/``); it is stored lower
case, without ``www.``, path or port. Each row needs the public page it came
from (``source_url``), which is kept as ``source_ref`` and, with the CSV itself,
as evidence. Rows are ``unverified``: a list saying a domain is a company's is
a pointer, not proof.
"""

from __future__ import annotations

import csv
import io
import re
from urllib.parse import urlsplit

from sqlalchemy import select

from ..ingest.framework import (
    InputRow,
    Job,
    RowRejected,
    RowStatus,
    Rule,
    SourceSpec,
    WriteContext,
)
from ..models import Company, CompanyDomain, Domain
from ..models.company import DOMAIN_ROLES

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def normalize_domain(value: str) -> str | None:
    v = (value or "").strip().lower()
    if not v:
        return None
    if "://" not in v:
        v = "//" + v
    host = urlsplit(v).hostname or ""
    host = host.rstrip(".")
    host = host.removeprefix("www.")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = host.split(".")
    if len(labels) < 2 or not all(_LABEL.match(x) for x in labels) or labels[-1].isdigit():
        return None
    return host


class CompanyDomainsJob(Job):
    name = "company_domains"
    dataset_key = "company_domains"
    media_type = "text/csv"
    source = SourceSpec(
        source_key="company_domain_list",
        name="Company domain list",
        source_type="dataset",
        access_method="manual",
        notes="Each row cites the public page its domain came from (e.g. Wikidata 'official website').",
    )
    rules = (
        Rule("company_key_required", lambda r: None if r.get("company_key") else "company_key is empty",
             field="company_key"),
        Rule("domain_valid", lambda r: None if normalize_domain(r.get("domain", ""))
             else f"{r.get('domain')!r} is not a domain name", field="domain"),
        Rule("role_known", lambda r: None if r.get("role") in DOMAIN_ROLES
             else f"role must be one of {', '.join(DOMAIN_ROLES)}", field="role"),
        Rule("source_url_required", lambda r: None if urlsplit(r.get("source_url", "")).scheme in ("http", "https")
             else "source_url must be the http(s) page the domain came from", field="source_url"),
    )

    def parse(self, content: bytes):
        reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig")))
        missing = {"company_key", "domain", "source_url"} - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"domain CSV is missing columns: {', '.join(sorted(missing))}")
        for number, raw in enumerate(reader, start=1):
            data = {k.strip(): (v or "").strip() for k, v in raw.items() if k}
            data["role"] = data.get("role") or "primary_website"
            yield InputRow(number, f"{data.get('company_key')}|{normalize_domain(data.get('domain', ''))}|"
                                   f"{data['role']}", data)

    def write(self, ctx: WriteContext) -> RowStatus:
        s, r = ctx.session, ctx.row.data
        company = s.scalar(select(Company).where(Company.company_key == r["company_key"]))
        if company is None:
            raise RowRejected("unknown_company", f"no company with key {r['company_key']!r}", "company_key")
        name = normalize_domain(r["domain"])
        domain = s.scalar(select(Domain).where(Domain.name == name))
        if domain is None:
            domain = Domain(name=name)
            s.add(domain)
            s.flush()
        link = s.scalar(select(CompanyDomain).where(
            CompanyDomain.company_id == company.id, CompanyDomain.domain_id == domain.id,
            CompanyDomain.role == r["role"], CompanyDomain.valid_to.is_(None)))
        status: RowStatus = "unchanged"
        if link is None:
            link = CompanyDomain(company_id=company.id, domain_id=domain.id, role=r["role"],
                                 source_ref=r["source_url"], verification_status="unverified")
            s.add(link)
            s.flush()
            status = "inserted"
        ctx.cite(link)
        return status
