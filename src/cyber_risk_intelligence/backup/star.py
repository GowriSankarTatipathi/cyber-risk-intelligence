"""Import backup answers from CSA STAR Registry CAIQ self-assessments (issue 2.1, second source).

Input is a CSV, one row per cloud service listed on the registry:

    company_key,service_name,service_url,caiq_url

``caiq_url`` is the registry's own "Download CAIQ Self-assessment" link
(``https://cloudsecurityalliance.org/star/registry/<provider>/services/<service>/download/<id>``).
The workbook is fetched (robots.txt is obeyed), stored as evidence, and each
answered backup question becomes a ``backup_policy_claims`` row with
``basis = 'csa_star_caiq'``:

* the schedule, if any, is read from the provider's implementation description;
  "periodically" or no description leaves it unknown (NULL);
* a "No" answer is kept with ``assertion = 'negated'``; NA or blank answers say
  nothing and give no row;
* a control the questionnaire marks as the customer's (``CSC-owned``) is stored as
  ``customer_responsibility``, never as the provider's own practice.

A CAIQ is the provider describing its own service, so these rows are claims.
"""

from __future__ import annotations

import csv
import hashlib
import io
from urllib.parse import urlsplit

from sqlalchemy import select

from ..collectors.trust_center.fetch import Fetcher, HttpFetcher
from ..evidence import record_evidence
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
from ..models import Company
from ..models.backup import BackupPolicyClaim
from .caiq import read_caiq
from .parse import BackupStatement, read_backup_statement

REGISTRY_HOST = "cloudsecurityalliance.org"
XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

CAIQ_SOURCE = SourceSpec(
    source_key="csa_star_registry",
    name="CSA STAR Registry (CAIQ self-assessments)",
    source_type="registry",
    access_method="web_page",
    base_url="https://cloudsecurityalliance.org/star/registry",
    notes="Self-assessments published by cloud providers on the Cloud Security Alliance STAR Registry. "
          "The provider's own answers: claims, not verification.",
)


def _registry_link(url: str, part: str) -> str | None:
    p = urlsplit(url or "")
    if p.scheme != "https" or (p.hostname or "").lower() != REGISTRY_HOST or not p.path.startswith("/star/registry/"):
        return f"must be an https link on {REGISTRY_HOST}/star/registry/"
    if part and f"/{part}/" not in p.path:
        return f"must be a registry {part} link"
    return None


def _link_rule(row: dict, column: str, part: str) -> str | None:
    if column == "service_url" and not row.get(column):
        return None  # optional
    problem = _registry_link(row.get(column, ""), part)
    return f"{column} {problem}" if problem else None


def _hash(*parts: str | None) -> str:
    return hashlib.sha256("\x1f".join(p or "" for p in parts).encode()).hexdigest()


class CsaStarJob(Job):
    name = "csa_star"
    dataset_key = "csa_star_targets"
    media_type = "text/csv"
    source = SourceSpec(
        source_key="project_csa_star_targets",
        name="Project list of CSA STAR Registry services",
        source_type="dataset",
        access_method="manual",
        notes="Company to CSA STAR Registry service mapping, one row per service.",
    )
    rules = (
        Rule("company_key_required", lambda r: None if r.get("company_key") else "company_key is empty",
             field="company_key"),
        Rule("caiq_url_on_registry", lambda r: _link_rule(r, "caiq_url", "download"), field="caiq_url"),
        Rule("service_url_on_registry", lambda r: _link_rule(r, "service_url", "services"), field="service_url"),
    )

    def __init__(self, store: ObjectStore, fetcher: Fetcher | None = None):
        self.store = store
        self.fetcher = fetcher or HttpFetcher()

    def parse(self, content: bytes):
        reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig")))
        missing = {"company_key", "caiq_url"} - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"CSA STAR CSV is missing columns: {', '.join(sorted(missing))}")
        for number, raw in enumerate(reader, start=1):
            data = {k.strip(): (v or "").strip() for k, v in raw.items() if k}
            yield InputRow(number, f"{data.get('company_key', '')}|{data.get('caiq_url', '')}", data)

    def write(self, ctx: WriteContext) -> RowStatus:
        s, r = ctx.session, ctx.row.data
        company = s.scalar(select(Company).where(Company.company_key == r["company_key"]))
        if company is None:
            raise RowRejected("unknown_company", f"no company with key {r['company_key']!r}", "company_key")
        result = self.fetcher.fetch(r["caiq_url"])
        if result.outcome != "captured" or not result.content:
            raise RowRejected("fetch_failed", f"{result.outcome}: {result.message or 'no content'}", "caiq_url")
        try:
            answers = read_caiq(result.content)
        except Exception as exc:  # any unreadable workbook is the same problem for us
            raise RowRejected("not_a_caiq", f"could not read the workbook: {exc}", "caiq_url") from exc
        if not answers:
            raise RowRejected("not_a_caiq", "no CAIQ backup questions found in the file", "caiq_url")
        source = ensure_source(s, CAIQ_SOURCE)
        version = record_evidence(s, self.store, source=source, source_url=r["caiq_url"], content=result.content,
                                  media_type=XLSX, http_status=result.http_status,
                                  title=f"CAIQ self-assessment: {r.get('service_name') or r['company_key']}")
        service = r.get("service_name") or (urlsplit(r.get("service_url", "")).path.rstrip("/").rsplit("/", 1)[-1]
                                            or None)
        added = 0
        for a in answers:
            if a.answer not in ("yes", "no"):
                continue  # NA or blank: the questionnaire says nothing about backups here
            st = read_backup_statement(a.description or "") or BackupStatement()
            scope = "customer_responsibility" if (a.ownership or "").lower().startswith("csc") else st.scope
            quote = f"{a.question_id} {a.question} Answer: {a.answer.capitalize()}." + (
                f" {a.description}" if a.description else "")
            claim_hash = _hash(a.question_id, a.question, a.answer, a.description)
            for f in st.frequencies or [None]:
                phrase = f.phrase if f else None
                if s.scalar(select(BackupPolicyClaim.id).where(
                        BackupPolicyClaim.evidence_version_id == version.id,
                        BackupPolicyClaim.claim_hash == claim_hash,
                        BackupPolicyClaim.frequency_phrase.is_not_distinct_from(phrase))) is not None:
                    continue
                s.add(BackupPolicyClaim(
                    company_id=company.id, evidence_version_id=version.id, source_ref=r["caiq_url"], quote=quote,
                    claim_hash=claim_hash, section_heading=a.question_id,
                    assertion="affirmed" if a.answer == "yes" else "negated", basis="csa_star_caiq",
                    caiq_question_id=a.question_id, caiq_answer=a.answer, control_ownership=a.ownership,
                    service_name=service, scope=scope, covered_system=st.covered_system,
                    frequency_class=f.frequency_class if f else None,
                    interval_minutes=f.interval_minutes if f else None, frequency_phrase=phrase,
                    methods=st.methods or None, retention_days=st.retention_days,
                    retention_phrase=st.retention_phrase, rpo_minutes=st.rpo_minutes, rto_minutes=st.rto_minutes,
                    objective_phrase=st.objective_phrase, observed_at=version.collected_at,
                    verification_status="claimed"))
                added += 1
        s.flush()
        return "inserted" if added else "unchanged"
