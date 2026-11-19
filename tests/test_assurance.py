"""Acceptance tests for issue 1.3 (security certifications, attestations, authorizations). No network."""

import csv
import io
from datetime import date

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from cyber_risk_intelligence import assurance
from cyber_risk_intelligence.assurance.__main__ import derive
from cyber_risk_intelligence.assurance.directory import AssuranceDirectoryJob
from cyber_risk_intelligence.collectors.trust_center import TrustCenterJob
from cyber_risk_intelligence.collectors.trust_center.fetch import FetchResult
from cyber_risk_intelligence.evidence import LocalStore
from cyber_risk_intelligence.ingest import run_import
from cyber_risk_intelligence.models import IngestionError, ValidationResult
from cyber_risk_intelligence.models.assurance import SecurityAssurance
from cyber_risk_intelligence.quality import run_validation

from . import factories as f
from .pdfmaker import make_pdf

PAGE_URL = "https://trust.acme.example/compliance"
CERT_URL = "https://trust.acme.example/iso27001-certificate.pdf"
PAGE = b"""<html><head><title>Acme Compliance</title></head><body><main>
<h2>Certifications</h2>
<p>Acme is ISO/IEC 27001 certified.</p>
<p>We maintain a SOC 2 Type II report, available upon request under NDA.</p>
</main></body></html>"""
CERT = make_pdf([[
    "CERTIFICATE OF REGISTRATION",
    "This is to certify that Acme Inc. operates an Information Security Management System",
    "which complies with the requirements of ISO/IEC 27001:2022",
    "Certificate Number: IS 712345",
    "Issued by BSI. Accredited by UKAS.",
    "Date of issue: 1 March 2024",
    "Expiry date: 28 February 2027",
    "Scope: The provision of cloud software services from the Dublin and London offices.",
]])
FAKE_CERT = make_pdf([["Our policies", "Acme takes ISO/IEC 27001 seriously and aligns with it."]])

REGISTER_COLUMNS = ["company_key", "directory", "record_url", "framework", "report_type", "level", "issuer",
                    "accreditation_body", "certificate_number", "scope", "issued_on", "valid_from", "valid_until",
                    "status", "holder_name"]


def register(*rows):
    buf = io.StringIO()
    w = csv.DictWriter(buf, REGISTER_COLUMNS)
    w.writeheader()
    for r in rows:
        w.writerow(r)
    return buf.getvalue().encode()


def entry(**kw):
    base = {"company_key": "acme", "directory": "IAF CertSearch",
            "record_url": "https://www.iafcertsearch.org/certification/abc123", "framework": "ISO/IEC 27001",
            "issuer": "BSI", "accreditation_body": "UKAS", "certificate_number": "IS 712345",
            "issued_on": "2024-03-01", "valid_until": "2099-02-28", "status": "active", "holder_name": "Acme Inc."}
    base.update(kw)
    return base


class FakeFetcher:
    def __init__(self, pages):
        self.pages = pages

    def fetch(self, url):
        media, content = self.pages[url]
        return FetchResult("captured", url, url, 200, media, content)


def targets(*rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["company_key", "url", "page_type"])
    w.writerows(rows)
    return buf.getvalue().encode()


@pytest.fixture
def store(tmp_path):
    return LocalStore(tmp_path)


@pytest.fixture
def acme(session_factory):
    with session_factory() as s:
        c = f.company(s, "acme", "Acme")
        s.commit()
        return c


def rows(sf):
    with sf() as s:
        return s.scalars(select(SecurityAssurance).order_by(SecurityAssurance.id)).all()


def summary(sf):
    with sf() as s:
        return {(r.framework, r.report_type): r for r in s.execute(text(
            "SELECT * FROM company_assurance_summary")).all()}


def collect(sf, store, pages=None):
    pages = pages or {PAGE_URL: ("text/html", PAGE), CERT_URL: ("application/pdf", CERT)}
    job = TrustCenterJob(store, FakeFetcher(pages))
    t = targets(*[["acme", url, "trust_center" if media == "text/html" else "compliance"]
                  for url, (media, _) in pages.items()])
    return run_import(sf, store, job, t, source_url="file:///targets.csv")


# --- parsing --------------------------------------------------------------------------------------------

def test_certificate_details_are_read():
    from cyber_risk_intelligence.collectors.trust_center.documents import document_text

    d = assurance.details(document_text(CERT, "pdf"))
    assert (d.issuer, d.accreditation_body, d.certificate_number) == ("BSI", "UKAS", "IS 712345")
    assert (d.issued_on, d.valid_until) == (date(2024, 3, 1), date(2027, 2, 28))
    assert d.scope_text.startswith("The provision of cloud software services")


def test_frameworks_map_to_kinds():
    assert assurance.framework_from_qualifier("SOC 2 Type II") == ("SOC 2", "Type II", None)
    assert assurance.framework_from_qualifier("ISO/IEC 27001")[0] == "ISO/IEC 27001"
    assert assurance.framework_from_qualifier("GDPR") is None  # a law, not an assessment


def test_policy_page_mentioning_a_standard_is_not_a_certificate():
    assert not assurance.looks_like_assurance_document("Acme aligns its controls with ISO/IEC 27001.")


# --- from trust-center collection ------------------------------------------------------------------------

def test_collection_records_claims_and_published_certificate(session_factory, store, acme):
    run = collect(session_factory, store)
    assert run.status == "succeeded"
    found = {(r.framework, r.report_type, r.basis): r for r in rows(session_factory)}
    assert set(found) == {("ISO/IEC 27001", None, "company_claim"), ("SOC 2", "Type II", "company_claim"),
                          ("ISO/IEC 27001", None, "company_document")}
    assert all(r.verification_status == "claimed" for r in found.values())  # a company's word is not verification
    iso = found["ISO/IEC 27001", None, "company_claim"]
    soc = found["SOC 2", "Type II", "company_claim"]
    doc = found["ISO/IEC 27001", None, "company_document"]
    assert (iso.kind, soc.kind) == ("certification", "attestation")
    assert soc.report_availability == "gated" and iso.claim_id is not None and iso.source_ref == PAGE_URL
    assert (doc.certificate_number, doc.issuer, doc.valid_until) == ("IS 712345", "BSI", date(2027, 2, 28))
    assert doc.source_ref == CERT_URL and doc.report_availability == "public"
    s = summary(session_factory)
    assert s["ISO/IEC 27001", None].status == "claimed" and s["ISO/IEC 27001", None].validity == "current"
    assert s["SOC 2", "Type II"].validity == "unknown"  # no date known: unknown, not expired


def test_repeat_collection_and_derive_do_not_duplicate(session_factory, store, acme):
    collect(session_factory, store)
    collect(session_factory, store)
    assert derive(session_factory, store) == (0, 0)
    assert len(rows(session_factory)) == 3


def test_derive_backfills_from_earlier_captures(session_factory, store, acme):
    collect(session_factory, store)
    with session_factory() as s:
        s.execute(text("DELETE FROM security_assurances"))
        s.commit()
    assert derive(session_factory, store) == (2, 1)
    assert derive(session_factory, store) == (0, 0)


def test_document_that_only_mentions_a_standard_is_not_recorded(session_factory, store, acme):
    collect(session_factory, store, {CERT_URL: ("application/pdf", FAKE_CERT)})
    assert "company_document" not in {r.basis for r in rows(session_factory)}


def test_company_evidence_cannot_be_marked_verified(session_factory, store, acme):
    collect(session_factory, store)
    with session_factory() as s:
        row = s.scalars(select(SecurityAssurance).where(SecurityAssurance.basis == "company_claim")).first()
        row.verification_status = "verified"
        with pytest.raises(IntegrityError, match="verified_only_from_directory"):
            s.flush()


# --- independent registers -------------------------------------------------------------------------------

def test_register_entry_verifies(session_factory, store, acme):
    collect(session_factory, store)
    run = run_import(session_factory, store, AssuranceDirectoryJob(), register(entry()), source_url="file:///r.csv")
    assert (run.status, run.rows_inserted) == ("succeeded", 1)
    [reg] = [r for r in rows(session_factory) if r.basis == "issuer_directory"]
    assert (reg.verification_status, reg.directory_status, reg.kind) == ("verified", "active", "certification")
    assert reg.source_ref.startswith("https://www.iafcertsearch.org/")
    s = summary(session_factory)["ISO/IEC 27001", None]
    assert (s.status, s.company_claims, s.company_documents, s.register_entries) == ("verified", 1, 1, 1)
    assert summary(session_factory)["SOC 2", "Type II"].status == "claimed"  # verifying one doesn't verify others
    again = run_import(session_factory, store, AssuranceDirectoryJob(), register(entry()), source_url="file:///r.csv")
    assert again.rows_inserted == 0
    assert len([r for r in rows(session_factory) if r.basis == "issuer_directory"]) == 1


def test_withdrawn_or_expired_register_entry_is_not_current(session_factory, store, acme):
    collect(session_factory, store)
    run_import(session_factory, store, AssuranceDirectoryJob(),
               register(entry(status="withdrawn", valid_until="2025-01-31")), source_url="file:///r.csv")
    s = summary(session_factory)["ISO/IEC 27001", None]
    assert s.status == "verified_lapsed"
    run = run_validation(session_factory)
    with session_factory() as ses:
        hits = set(ses.scalars(select(ValidationResult.rule).where(
            ValidationResult.validation_run_id == run.id, ValidationResult.rows_failed > 0)))
    assert run.status == "warnings"
    assert "assurance_register_lapsed_but_claimed" in hits
    assert "assurance_verified_from_company_source" not in hits


def test_bad_register_rows_are_rejected(session_factory, store, acme):
    bad = register(*[{**r, "certificate_number": f"C{i}"} for i, r in enumerate([
        entry(record_url="https://trust.acme.example/iso"),           # company site, not the register
        entry(record_url="http://www.iafcertsearch.org/x"),           # not https
        entry(directory="Some Blog"),
        entry(company_key="nobody"),
        entry(framework="ISO 27001 compliant"),
        entry(valid_from="2025-01-01", valid_until="2024-01-01"),
        entry(framework="ISO/IEC 27001", report_type="Type II"),
        entry(status="maybe"),
    ])])
    run = run_import(session_factory, store, AssuranceDirectoryJob(), bad, source_url="file:///r.csv")
    assert run.rows_rejected == 8 and run.rows_inserted == 0
    with session_factory() as s:
        codes = sorted(e.code for e in s.scalars(select(IngestionError).where(IngestionError.run_id == run.id)))
    assert codes == sorted(["directory_known", "directory_known", "directory_known", "unknown_company",
                            "framework_known", "dates_valid", "report_type_valid", "status_known"])
    assert rows(session_factory) == []
