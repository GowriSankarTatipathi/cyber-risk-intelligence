"""Import entries from independent certification and authorization registers.

Input is a CSV, one row per register entry, with the company it belongs to:

    company_key,directory,record_url,framework,report_type,level,issuer,accreditation_body,
    certificate_number,scope,issued_on,valid_from,valid_until,status,holder_name

``directory`` must be one of the registers in ``DIRECTORIES`` and ``record_url``
must point at that register's own site, so a company web page can never be
passed off as independent verification. Each row becomes a
``security_assurances`` row with ``basis = 'issuer_directory'`` and
``verification_status = 'verified'``; the imported file is stored as evidence
and each row keeps its register URL. A withdrawn, suspended or expired entry is
still imported (that is useful to know) with its ``directory_status``.

Rows are usually exported from, or copied by hand out of, the register's public
search. Gated registers (login, paid API) are not scraped.
"""

from __future__ import annotations

import csv
import io
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
from ..models import Company
from ..models.assurance import (
    DIRECTORY_STATUSES,
    FRAMEWORKS,
    REPORT_TYPES,
    SecurityAssurance,
)
from .parse import parse_date

# register -> hosts its records live on
DIRECTORIES: dict[str, tuple[str, ...]] = {
    "IAF CertSearch": ("iafcertsearch.org",),
    "UKAS CertCheck": ("certcheck.ukas.com",),
    "ANAB Directory": ("anab.ansi.org", "ansi.org"),
    "FedRAMP Marketplace": ("marketplace.fedramp.gov", "fedramp.gov"),
    "StateRAMP Authorized Product List": ("stateramp.org",),
    "CSA STAR Registry": ("cloudsecurityalliance.org",),
    "HITRUST Assurance Results": ("hitrustalliance.net",),
    "IASME Cyber Essentials Register": ("iasme.co.uk",),
    "ENX TISAX Results": ("enx.com", "portal.enx.com"),
    "Australian IRAP Assessed Services": ("cyber.gov.au",),
    "PCI SSC Listings": ("pcisecuritystandards.org", "listings.pcisecuritystandards.org"),
}

COLUMNS = ("company_key", "directory", "record_url", "framework", "report_type", "level", "issuer",
           "accreditation_body", "certificate_number", "scope", "issued_on", "valid_from", "valid_until", "status",
           "holder_name")


def _host_ok(row) -> str | None:
    hosts = DIRECTORIES.get(row.get("directory", ""))
    if hosts is None:
        return "directory must be one of: " + ", ".join(DIRECTORIES)
    parts = urlsplit(row.get("record_url", ""))
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not any(host == h or host.endswith("." + h) for h in hosts):
        return f"record_url must be an https link on {' or '.join(hosts)}"
    return None


def _dates_ok(row) -> str | None:
    for name in ("issued_on", "valid_from", "valid_until"):
        if row.get(name) and parse_date(row[name]) is None:
            return f"{name} {row[name]!r} is not a date (use YYYY-MM-DD)"
    vf, vu = parse_date(row.get("valid_from") or ""), parse_date(row.get("valid_until") or "")
    if vf and vu and vu < vf:
        return "valid_until is before valid_from"
    return None


class AssuranceDirectoryJob(Job):
    name = "assurance_directory"
    dataset_key = "assurance_directory_entries"
    media_type = "text/csv"
    source = SourceSpec(
        source_key="assurance_registers",
        name="Independent certification and authorization registers",
        source_type="registry",
        access_method="manual",
        notes="Entries copied from issuer / accreditation registers (IAF CertSearch, FedRAMP Marketplace ...); "
              "each row keeps its register URL.",
    )
    rules = (
        Rule("company_key_required", lambda r: None if r.get("company_key") else "company_key is empty",
             field="company_key"),
        Rule("directory_known", _host_ok, field="record_url"),
        Rule("framework_known", lambda r: None if r.get("framework") in FRAMEWORKS
             else f"framework must be one of {', '.join(FRAMEWORKS)}", field="framework"),
        Rule("report_type_valid", lambda r: None if not r.get("report_type") or (
            r["report_type"] in REPORT_TYPES and r.get("framework") in ("SOC 1", "SOC 2"))
             else "report_type is only for SOC 1 / SOC 2 and must be Type I or Type II", field="report_type"),
        Rule("status_known", lambda r: None if (r.get("status") or "unknown") in DIRECTORY_STATUSES
             else f"status must be one of {', '.join(DIRECTORY_STATUSES)}", field="status"),
        Rule("dates_valid", _dates_ok, field="valid_until"),
    )

    def parse(self, content: bytes):
        reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig")))
        missing = {"company_key", "directory", "record_url", "framework"} - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"register CSV is missing columns: {', '.join(sorted(missing))}")
        for number, raw in enumerate(reader, start=1):
            data = {k.strip(): (v or "").strip() for k, v in raw.items() if k}
            yield InputRow(number, "|".join(data.get(k, "") for k in ("company_key", "directory", "record_url",
                                                                       "framework", "certificate_number")), data)

    def write(self, ctx: WriteContext) -> RowStatus:
        s, r = ctx.session, ctx.row.data
        company = s.scalar(select(Company).where(Company.company_key == r["company_key"]))
        if company is None:
            raise RowRejected("unknown_company", f"no company with key {r['company_key']!r}", "company_key")
        values = {
            "company_id": company.id, "framework": r["framework"], "report_type": r.get("report_type") or None,
            "level": r.get("level") or None, "basis": "issuer_directory", "evidence_version_id": ctx.evidence.id,
            "certificate_number": r.get("certificate_number") or None,
        }
        existing = s.scalar(select(SecurityAssurance).where(
            *[(getattr(SecurityAssurance, k).is_(None) if v is None else getattr(SecurityAssurance, k) == v)
              for k, v in values.items()]))
        if existing is not None:
            return "unchanged"
        row = SecurityAssurance(
            **values, kind=FRAMEWORKS[r["framework"]], verification_status="verified",
            report_availability="unknown", issuer=r.get("issuer") or None,
            accreditation_body=r.get("accreditation_body") or None, scope_text=r.get("scope") or None,
            issued_on=parse_date(r.get("issued_on") or ""), valid_from=parse_date(r.get("valid_from") or ""),
            valid_until=parse_date(r.get("valid_until") or ""), directory_status=r.get("status") or "unknown",
            source_ref=r["record_url"],
            quote=f"{r['directory']}: {r.get('holder_name') or r['company_key']} — {r['framework']}"
                  + (f" {r['report_type']}" if r.get("report_type") else "")
                  + (f" ({r['level']})" if r.get("level") else ""),
        )
        s.add(row)
        s.flush()
        return "inserted"
