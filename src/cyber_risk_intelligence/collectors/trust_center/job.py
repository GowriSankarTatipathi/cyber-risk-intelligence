"""Collect public trust-center pages and store the security claims they make.

Input is a CSV of targets: ``company_key,url,page_type[,notes]``. For each
target the job fetches the page (see ``fetch.py``), stores it as evidence,
extracts claims (see ``extract.py``) and records the attempt in ``page_fetches``.

A page we couldn't read is recorded with its outcome (unavailable, login
required, blocked by robots.txt, rate limited). That never creates or removes a
claim: not seeing a control is not evidence the company lacks it.
"""

from __future__ import annotations

import csv
import io
from urllib.parse import urlsplit

from sqlalchemy import select

from ...evidence import SecretDetected, find_secrets, record_evidence
from ...evidence.store import ObjectStore, sha256_hex
from ...ingest.framework import InputRow, Job, RowRejected, RowStatus, Rule, SourceSpec, WriteContext, ensure_source
from ...models import (
    Company,
    CollectionTarget,
    EvidenceObject,
    EvidenceVersion,
    PageFetch,
    SecurityControlClaim,
)
from ...models.controls import PAGE_TYPES
from .extract import extract
from .fetch import Fetcher, HttpFetcher
from .scrub import scrub_html

PAGES_SOURCE = SourceSpec(
    source_key="company_trust_centers",
    name="Company trust-center and security pages",
    source_type="company_website",
    access_method="web_page",
    notes="Public pages only; robots.txt obeyed; companies' own statements (claims, not verification).",
)


class TrustCenterJob(Job):
    name = "trust_center"
    dataset_key = "trust_center_targets"
    media_type = "text/csv"
    source = SourceSpec(
        source_key="project_target_list",
        name="Project collection target list",
        source_type="dataset",
        access_method="manual",
    )
    rules = (
        Rule("company_key_required", lambda r: None if r.get("company_key") else "company_key is empty",
             field="company_key"),
        Rule("url_is_http", lambda r: None if urlsplit(r.get("url", "")).scheme in ("http", "https")
             and urlsplit(r.get("url", "")).netloc else "url must be an http(s) URL", field="url"),
        Rule("page_type_known", lambda r: None if r.get("page_type", "other") in PAGE_TYPES
             else f"page_type must be one of {', '.join(PAGE_TYPES)}", field="page_type"),
    )

    def __init__(self, store: ObjectStore, fetcher: Fetcher | None = None):
        self.store = store
        self.fetcher = fetcher or HttpFetcher()

    def parse(self, content: bytes):
        reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig")))
        if not reader.fieldnames or not {"company_key", "url"} <= set(reader.fieldnames):
            raise ValueError("target CSV needs company_key and url columns")
        for number, raw in enumerate(reader, start=1):
            data = {k.strip(): (v or "").strip() for k, v in raw.items() if k}
            data.setdefault("page_type", "other")
            data["page_type"] = data["page_type"] or "other"
            yield InputRow(number, f"{data.get('company_key')}|{data.get('url')}", data)

    def write(self, ctx: WriteContext) -> RowStatus:
        s, r = ctx.session, ctx.row.data
        company = s.scalar(select(Company).where(Company.company_key == r["company_key"]))
        if company is None:
            raise RowRejected("unknown_company", f"no company with key {r['company_key']!r}", "company_key")

        target = s.scalar(select(CollectionTarget).where(CollectionTarget.company_id == company.id,
                                                         CollectionTarget.url == r["url"]))
        new_target = target is None
        if new_target:
            target = CollectionTarget(company_id=company.id, url=r["url"], page_type=r["page_type"],
                                      notes=r.get("notes") or None)
            s.add(target)
            s.flush()
        elif not target.active:
            raise RowRejected("target_inactive", "target is marked inactive", "url")

        result = self.fetcher.fetch(target.url)
        fetch = PageFetch(target_id=target.id, ingestion_run_id=ctx.run.id, outcome=result.outcome,
                          http_status=result.http_status, final_url=result.final_url, message=result.message)
        # The fetch row is added only once it is complete (its evidence link depends on the outcome).
        if result.content is None:
            s.add(fetch)
            s.flush()
            return "inserted" if new_target else "updated"

        content = result.content
        if result.outcome == "captured" and find_secrets(content):
            # Usually a browser key embedded in the page's code; keep the page, drop the code.
            content, removed = scrub_html(content)
            fetch.message = f"stored without page scripts and {removed} code item(s) that looked like keys"

        source = ensure_source(s, PAGES_SOURCE)
        digest = sha256_hex(content)
        seen_before = s.scalar(
            select(EvidenceVersion.id).join(EvidenceObject).where(
                EvidenceVersion.source_id == source.id, EvidenceVersion.source_url == target.url,
                EvidenceObject.sha256 == digest))
        page = extract(content) if result.outcome == "captured" else None
        try:
            version = record_evidence(
                s, self.store, source=source, source_url=target.url, content=content,
                media_type=result.content_type or "application/octet-stream", http_status=result.http_status,
                title=page.title if page else None, published_at=page.published_at if page else None)
        except SecretDetected as exc:
            fetch.outcome, fetch.message = "withheld", str(exc)
            s.add(fetch)
            s.flush()
            return "inserted" if new_target else "updated"
        fetch.evidence_version_id = version.id
        if seen_before and result.outcome == "captured":
            fetch.outcome = "not_modified"
        s.add(fetch)

        added = 0
        if page is not None:
            for c in page.claims:
                exists = s.scalar(select(SecurityControlClaim.id).where(
                    SecurityControlClaim.evidence_version_id == version.id,
                    SecurityControlClaim.control_category == c.category,
                    SecurityControlClaim.qualifier.is_not_distinct_from(c.qualifier),
                    SecurityControlClaim.claim_hash == c.claim_hash))
                if exists is None:
                    s.add(SecurityControlClaim(
                        company_id=company.id, evidence_version_id=version.id, control_category=c.category,
                        assertion=c.assertion, qualifier=c.qualifier, claim_text=c.claim_text,
                        context_text=c.context_text, section_heading=c.section_heading, claim_hash=c.claim_hash,
                        page_updated_on=page.updated_on, source_ref=target.url, verification_status="claimed",
                        observed_at=version.collected_at))
                    added += 1
            fetch.claims_found = len(page.claims)
        s.flush()
        if new_target or added:
            return "inserted"
        return "unchanged" if fetch.outcome == "not_modified" else "updated"
