"""Turn what 1.1 collected into ``security_assurances`` rows (status always ``claimed``).

* Each affirmed ``compliance_certification`` claim naming an assessment
  framework becomes a ``company_claim`` row. Details (issuer, dates) are read
  from the claim sentence only, so one framework's date isn't pinned on another.
* A stored certificate or audit report the company publishes (PDF, Word ...)
  becomes ``company_document`` rows for the frameworks named at its top, with
  issuer, certificate number, dates and scope read from the document.

Re-running is safe: a row that already exists for the same statement is not added again.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import EvidenceVersion, SecurityControlClaim
from ..models.assurance import FRAMEWORKS, SecurityAssurance
from .parse import (
    details,
    framework_from_qualifier,
    frameworks_in,
    looks_like_assurance_document,
)


def _exists(s: Session, **key) -> bool:
    q = select(SecurityAssurance.id)
    for name, value in key.items():
        col = getattr(SecurityAssurance, name)
        q = q.where(col.is_(None) if value is None else col == value)
    return s.scalar(q.limit(1)) is not None


def _add(s: Session, row: SecurityAssurance) -> bool:
    key = {k: getattr(row, k) for k in ("company_id", "framework", "report_type", "level", "basis",
                                        "evidence_version_id", "certificate_number")}
    if _exists(s, **key):
        return False
    s.add(row)
    return True


def from_claim(s: Session, claim: SecurityControlClaim, source_ref: str | None = None) -> SecurityAssurance | None:
    if claim.control_category != "compliance_certification" or claim.assertion != "affirmed":
        return None
    fw = framework_from_qualifier(claim.qualifier)
    if fw is None:
        return None
    framework, report_type, level = fw
    if _exists(s, company_id=claim.company_id, framework=framework, basis="company_document",
               evidence_version_id=claim.evidence_version_id):
        return None  # the sentence comes from a published certificate/report already recorded as a document
    d = details(claim.claim_text)
    gated = details(claim.context_text or "").gated or d.gated
    row = SecurityAssurance(
        company_id=claim.company_id, legal_entity_id=claim.legal_entity_id, kind=FRAMEWORKS[framework],
        framework=framework, report_type=report_type, level=level, basis="company_claim",
        verification_status="claimed", report_availability="gated" if gated else "unknown",
        issuer=d.issuer, accreditation_body=d.accreditation_body, certificate_number=d.certificate_number,
        issued_on=d.issued_on, valid_from=d.valid_from, valid_until=d.valid_until,
        period_start=d.period_start, period_end=d.period_end,
        evidence_version_id=claim.evidence_version_id, claim_id=claim.id,
        source_ref=source_ref or claim.source_ref, quote=claim.claim_text, observed_at=claim.observed_at,
    )
    return row if _add(s, row) else None


def from_document(s: Session, company_id: int, version: EvidenceVersion, text: str,
                  source_ref: str | None = None) -> list[SecurityAssurance]:
    if not looks_like_assurance_document(text):
        return []
    d = details(text)
    head = frameworks_in(text[:3000]) or d.frameworks
    added = []
    for framework, report_type, level in head:
        row = SecurityAssurance(
            company_id=company_id, kind=FRAMEWORKS[framework], framework=framework, report_type=report_type,
            level=level, basis="company_document", verification_status="claimed", report_availability="public",
            issuer=d.issuer, accreditation_body=d.accreditation_body, certificate_number=d.certificate_number,
            scope_text=d.scope_text, issued_on=d.issued_on, valid_from=d.valid_from, valid_until=d.valid_until,
            period_start=d.period_start, period_end=d.period_end, evidence_version_id=version.id,
            source_ref=source_ref or version.source_url, quote=text[:400].strip(), observed_at=version.collected_at,
        )
        if _add(s, row):
            added.append(row)
    return added
