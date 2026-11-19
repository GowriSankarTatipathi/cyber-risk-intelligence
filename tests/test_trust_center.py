"""Acceptance tests for issue 1.1 (trust-center collection). Saved/synthetic pages only; no network."""

import csv
import io
from datetime import UTC, date, datetime
from pathlib import Path

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from cyber_risk_intelligence.collectors.trust_center import HttpFetcher, TrustCenterJob, classify, extract
from cyber_risk_intelligence.collectors.trust_center.documents import detect_kind, extract_document
from cyber_risk_intelligence.collectors.trust_center.fetch import FetchResult
from cyber_risk_intelligence.evidence import LocalStore, read_evidence
from cyber_risk_intelligence.ingest import run_import
from cyber_risk_intelligence.models import EvidenceVersion, PageFetch, SecurityControlClaim
from cyber_risk_intelligence.quality import run_validation

from . import factories as f
from .docmaker import make_docx, make_pptx, make_xlsx
from .pdfmaker import make_pdf

FIXTURE = (Path(__file__).parent / "fixtures" / "trust_center" / "acme_trust.html").read_bytes()
URL = "https://trust.acme.example/security"

EXPECTED = {
    ("encryption_at_rest", "affirmed", "AES-256"),
    ("encryption_in_transit", "affirmed", "TLS 1.2"),
    ("key_management", "affirmed", None),
    ("mfa", "affirmed", None),
    ("access_control", "affirmed", None),
    ("sso", "negated", None),
    ("compliance_certification", "affirmed", "SOC 2 Type II"),
    ("compliance_certification", "affirmed", "ISO/IEC 27001"),
    ("penetration_testing", "affirmed", None),
    ("bug_bounty", "affirmed", None),
    ("backup_and_recovery", "affirmed", None),
}


class FakeFetcher:
    def __init__(self, pages):
        self.pages, self.calls = pages, []

    def fetch(self, url):
        self.calls.append(url)
        page = self.pages[url]
        return page if isinstance(page, FetchResult) else FetchResult("captured", url, url, 200, "text/html", page)


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


def claims(sf):
    with sf() as s:
        return s.scalars(select(SecurityControlClaim).order_by(SecurityControlClaim.id)).all()


def fetches(sf):
    with sf() as s:
        return s.scalars(select(PageFetch).order_by(PageFetch.id)).all()


# --- extraction --------------------------------------------------------------------------------------

def test_saved_page_yields_expected_claims_with_citations():
    page = extract(FIXTURE)
    assert page.title == "Acme Trust Center"
    assert page.published_at == datetime(2025, 3, 1, 9, tzinfo=UTC)
    assert page.updated_on == date(2025, 6, 10)
    assert {(c.category, c.assertion, c.qualifier) for c in page.claims} == EXPECTED
    by_cat = {c.category: c for c in page.claims}
    assert by_cat["encryption_at_rest"].claim_text == "All customer data is encrypted at rest using AES-256."
    assert by_cat["encryption_at_rest"].section_heading == "Data protection"
    assert "TLS 1.2" in by_cat["encryption_at_rest"].context_text  # the whole paragraph is kept
    assert by_cat["sso"].claim_text.startswith("We do not currently support SAML")


def test_navigation_and_scripts_are_ignored():
    page = extract(b"<html><nav>SSO MFA SOC 2</nav><script>MFA</script><p>Welcome to our site.</p></html>")
    assert page.claims == []


def test_last_updated_text_is_read_when_no_metadata():
    page = extract(b"<p>We use multi-factor authentication everywhere.</p><p>Last updated: March 3, 2025</p>")
    assert page.updated_on == date(2025, 3, 3) and page.published_at is None


# --- collection ------------------------------------------------------------------------------------

def test_collection_stores_page_claims_and_attempt(session_factory, store, acme):
    job = TrustCenterJob(store, FakeFetcher({URL: FIXTURE}))
    run = run_import(session_factory, store, job, targets(["acme", URL, "trust_center"]), source_url="file:///targets.csv")
    assert (run.status, run.rows_inserted) == ("succeeded", 1)
    [fetch] = fetches(session_factory)
    assert (fetch.outcome, fetch.http_status, fetch.claims_found) == ("captured", 200, len(EXPECTED))
    found = claims(session_factory)
    assert {(c.control_category, c.assertion, c.qualifier) for c in found} == EXPECTED
    assert all(c.verification_status == "claimed" and c.company_id == acme.id for c in found)
    assert all(c.evidence_version_id == fetch.evidence_version_id and c.source_ref == URL for c in found)
    assert all(c.page_updated_on == date(2025, 6, 10) for c in found)
    with session_factory() as s:
        version = s.get(EvidenceVersion, fetch.evidence_version_id)
        assert version.published_at == datetime(2025, 3, 1, 9, tzinfo=UTC)
        assert version.title == "Acme Trust Center"
        assert read_evidence(s, store, version) == FIXTURE  # the original page is preserved


def test_repeating_the_same_capture_does_not_duplicate_claims(session_factory, store, acme):
    job = TrustCenterJob(store, FakeFetcher({URL: FIXTURE}))
    t = targets(["acme", URL, "trust_center"])
    run_import(session_factory, store, job, t, source_url="file:///targets.csv")
    second = run_import(session_factory, store, job, t, source_url="file:///targets.csv")
    assert second.rows_unchanged == 1
    assert len(claims(session_factory)) == len(EXPECTED)
    assert [x.outcome for x in fetches(session_factory)] == ["captured", "not_modified"]


def test_changed_page_keeps_history(session_factory, store, acme):
    t = targets(["acme", URL, "trust_center"])
    run_import(session_factory, store, TrustCenterJob(store, FakeFetcher({URL: FIXTURE})), t, source_url="file:///t.csv")
    changed = FIXTURE.replace(b"AES-256", b"AES-128")
    run_import(session_factory, store, TrustCenterJob(store, FakeFetcher({URL: changed})), t, source_url="file:///t.csv")
    found = claims(session_factory)
    rest = sorted(c.qualifier for c in found if c.control_category == "encryption_at_rest")
    assert rest == ["AES-128", "AES-256"]  # both versions' claims kept, each tied to its own capture
    assert len({c.evidence_version_id for c in found}) == 2


@pytest.mark.parametrize("result, outcome", [
    (FetchResult("unavailable", URL, URL, 404, message="HTTP 404"), "unavailable"),
    (FetchResult("login_required", URL, "https://acme.example/login", 200, message="page requires sign-in"),
     "login_required"),
    (FetchResult("blocked_by_robots", URL, message="robots.txt disallows this page"), "blocked_by_robots"),
    (FetchResult("rate_limited", URL, URL, 429, message="HTTP 429 Too Many Requests"), "rate_limited"),
])
def test_inaccessible_page_is_unavailable_not_absent(session_factory, store, acme, result, outcome):
    job = TrustCenterJob(store, FakeFetcher({URL: result}))
    run = run_import(session_factory, store, job, targets(["acme", URL, "trust_center"]), source_url="file:///t.csv")
    assert run.status == "succeeded"
    [fetch] = fetches(session_factory)
    assert (fetch.outcome, fetch.evidence_version_id, fetch.claims_found) == (outcome, None, None)
    assert claims(session_factory) == []  # no claims, and nothing recorded as "absent"


def test_failed_fetch_does_not_remove_earlier_claims(session_factory, store, acme):
    t = targets(["acme", URL, "trust_center"])
    run_import(session_factory, store, TrustCenterJob(store, FakeFetcher({URL: FIXTURE})), t, source_url="file:///t.csv")
    down = FetchResult("unavailable", URL, URL, 503, message="HTTP 503")
    run_import(session_factory, store, TrustCenterJob(store, FakeFetcher({URL: down})), t, source_url="file:///t.csv")
    assert len(claims(session_factory)) == len(EXPECTED)
    assert [x.outcome for x in fetches(session_factory)] == ["captured", "unavailable"]


def test_unknown_company_and_bad_targets_are_rejected(session_factory, store, acme):
    job = TrustCenterJob(store, FakeFetcher({}))
    run = run_import(session_factory, store, job,
                     targets(["nobody", URL, "trust_center"], ["acme", "ftp://acme.example/x", "trust_center"],
                             ["acme", URL, "brochure"]), source_url="file:///t.csv")
    assert (run.status, run.rows_rejected) == ("partial", 3)
    with session_factory() as s:
        from cyber_risk_intelligence.models import IngestionError
        codes = sorted(e.code for e in s.scalars(select(IngestionError).where(IngestionError.run_id == run.id)))
    assert codes == ["page_type_known", "unknown_company", "url_is_http"]
    assert job.fetcher.calls == []  # nothing fetched for rejected rows


def test_page_with_a_credential_is_withheld(session_factory, store, acme):
    leaky = FIXTURE.replace(b"</body>", b"<p>Staging login: password = CorrectHorse99</p></body>")
    job = TrustCenterJob(store, FakeFetcher({URL: leaky}))
    run_import(session_factory, store, job, targets(["acme", URL, "trust_center"]), source_url="file:///t.csv")
    [fetch] = fetches(session_factory)
    assert fetch.outcome == "withheld" and fetch.evidence_version_id is None
    assert "CorrectHorse99" not in fetch.message
    assert claims(session_factory) == []


def test_keys_in_page_code_are_scrubbed_not_withheld(session_factory, store, acme):
    # Public pages embed browser keys in scripts and widget attributes. Keep the page, drop the code.
    noisy = FIXTURE.replace(b"</body>", (
        b'<script>var cfg = {password: "widgetpass123", u: "https://bot:hunter2hunter@cdn.example/x"};</script>'
        b'<div class="search" api-key="d068ed3ac1510812754af5c8b930c3cf"></div><!-- token=abcdefgh12345 --></body>'))
    job = TrustCenterJob(store, FakeFetcher({URL: noisy}))
    run_import(session_factory, store, job, targets(["acme", URL, "trust_center"]), source_url="file:///t.csv")
    [fetch] = fetches(session_factory)
    assert fetch.outcome == "captured" and fetch.evidence_version_id is not None
    assert fetch.claims_found == len(EXPECTED) and "scripts" in fetch.message
    with session_factory() as s:
        stored = read_evidence(s, store, s.get(EvidenceVersion, fetch.evidence_version_id))
    for gone in (b"widgetpass123", b"hunter2hunter", b"d068ed3ac1510812754af5c8b930c3cf", b"abcdefgh12345"):
        assert gone not in stored
    assert b"encrypted at rest using AES-256" in stored and b'class="search"' in stored


def test_claims_can_never_be_marked_verified(session_factory, store, acme):
    job = TrustCenterJob(store, FakeFetcher({URL: FIXTURE}))
    run_import(session_factory, store, job, targets(["acme", URL, "trust_center"]), source_url="file:///t.csv")
    with session_factory() as s:
        claim = s.scalar(select(SecurityControlClaim))
        claim.verification_status = "verified"
        with pytest.raises(IntegrityError, match="always_claimed"):
            s.flush()


def test_collected_data_passes_validation(session_factory, store, acme):
    job = TrustCenterJob(store, FakeFetcher({URL: FIXTURE}))
    run_import(session_factory, store, job, targets(["acme", URL, "trust_center"]), source_url="file:///t.csv")
    assert run_validation(session_factory, store=store).status in ("passed", "warnings")


# --- HTTP behaviour (mock transport, no network) -------------------------------------------------------

def test_classify_http_outcomes():
    html = "text/html; charset=utf-8"
    assert classify(URL, 200, URL, html, b"<p>x</p>").outcome == "captured"
    assert classify(URL, 404, URL, html, b"").outcome == "unavailable"
    assert classify(URL, 503, URL, html, b"").outcome == "unavailable"
    assert classify(URL, 401, URL, html, b"").outcome == "login_required"
    assert classify(URL, 200, "https://acme.example/login?next=/security", html, b"").outcome == "login_required"
    assert classify(URL, 429, URL, html, b"").outcome == "rate_limited"
    assert classify(URL, 200, URL, "application/pdf", b"%PDF-1.4").outcome == "captured"
    assert classify(URL, 200, URL, "application/octet-stream", b"%PDF-1.7 ...").content_type == "application/pdf"
    assert classify(URL, 200, URL, "image/png", b"\x89PNG").outcome == "not_html"


def test_http_fetcher_obeys_robots_backs_off_and_identifies_itself():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.path, request.headers["user-agent"]))
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nDisallow: /private/\n")
        if request.url.path == "/busy":
            return httpx.Response(429)
        return httpx.Response(200, html="<p>We use MFA.</p>")

    fetcher = HttpFetcher(user_agent="test-agent/1.0", min_delay=0, transport=httpx.MockTransport(handler))
    assert fetcher.fetch("https://acme.example/private/x").outcome == "blocked_by_robots"
    assert fetcher.fetch("https://acme.example/security").outcome == "captured"
    assert fetcher.fetch("https://acme.example/busy").outcome == "rate_limited"
    assert fetcher.fetch("https://acme.example/security").outcome == "rate_limited"  # host backed off
    paths = [p for p, _ in seen]
    assert paths == ["/robots.txt", "/security", "/busy"]  # private page and backed-off host never requested
    assert {ua for _, ua in seen} == {"test-agent/1.0"}


# --- PDFs ------------------------------------------------------------------------------------------

POLICY_PDF = make_pdf(
    [["Acme Information Security Policy", "Customer data is encrypted at rest using AES-256.",
      "All employees complete security awareness training every year."],
     ["Our platform holds a SOC 2 Type II report and ISO 27001 certification.",
      "Administrators must use multi-factor authentication."]],
    title="Acme Information Security Policy", created="D:20250301090000Z", modified="D:20250610120000Z")
PDF_URL = "https://acme.example/docs/security-policy.pdf"


def test_pdf_claims_cite_their_page():
    page = extract(POLICY_PDF)
    assert page.title == "Acme Information Security Policy"
    assert page.published_at == datetime(2025, 3, 1, 9, tzinfo=UTC) and page.updated_on == date(2025, 6, 10)
    found = {(c.category, c.qualifier, c.section_heading) for c in page.claims}
    assert {("encryption_at_rest", "AES-256", "page 1"), ("security_training", None, "page 1"),
            ("compliance_certification", "SOC 2 Type II", "page 2"),
            ("compliance_certification", "ISO/IEC 27001", "page 2"), ("mfa", None, "page 2")} <= found
    rest = next(c for c in page.claims if c.category == "encryption_at_rest")
    assert rest.claim_text == "Customer data is encrypted at rest using AES-256."


def test_unreadable_pdf_yields_no_claims_instead_of_failing():
    assert extract(b"%PDF-1.4 this is not really a pdf").claims == []


def test_pdf_is_stored_and_its_claims_collected(session_factory, store, acme):
    pdf = FetchResult("captured", PDF_URL, PDF_URL, 200, "application/pdf", POLICY_PDF)
    job = TrustCenterJob(store, FakeFetcher({PDF_URL: pdf}))
    run_import(session_factory, store, job, targets(["acme", PDF_URL, "security"]), source_url="file:///t.csv")
    [fetch] = fetches(session_factory)
    assert fetch.outcome == "captured" and fetch.claims_found >= 5
    with session_factory() as s:
        version = s.get(EvidenceVersion, fetch.evidence_version_id)
        assert read_evidence(s, store, version) == POLICY_PDF  # the original PDF, byte for byte
        assert version.evidence_object.media_type == "application/pdf"
    assert {c.page_updated_on for c in claims(session_factory)} == {date(2025, 6, 10)}


def test_pdf_with_a_credential_in_its_text_is_withheld(session_factory, store, acme):
    leaky = make_pdf([["Security policy. Encrypted at rest.", "Service account password = CorrectHorse99"]])
    pdf = FetchResult("captured", PDF_URL, PDF_URL, 200, "application/pdf", leaky)
    job = TrustCenterJob(store, FakeFetcher({PDF_URL: pdf}))
    run_import(session_factory, store, job, targets(["acme", PDF_URL, "security"]), source_url="file:///t.csv")
    [fetch] = fetches(session_factory)
    assert fetch.outcome == "withheld" and fetch.evidence_version_id is None
    assert "CorrectHorse99" not in fetch.message and claims(session_factory) == []


# --- other document formats ------------------------------------------------------------------------

DOCX = make_docx([("Title", "Acme Security Whitepaper"), ("Heading1", "Data protection"),
                  (None, "Customer data is encrypted at rest using AES-256."),
                  (None, "We maintain a SOC 2 Type II report.")],
                 title="Acme Security Whitepaper", created="2025-03-01T09:00:00Z", modified="2025-06-10T12:00:00Z")


def test_detects_formats_by_content_type_extension_and_signature():
    assert detect_kind(DOCX) == "docx"
    assert detect_kind(make_pptx([["x"]])) == "pptx" and detect_kind(make_xlsx([["x"]])) == "xlsx"
    assert detect_kind(b"%PDF-1.7") == "pdf"
    assert detect_kind(b"Contact: mailto:security@acme.example", "text/plain") == "text"
    assert detect_kind(b"# Security", "application/octet-stream", "https://acme.example/SECURITY.md") == "markdown"
    assert detect_kind(b"{}", "application/json") == "json"
    assert detect_kind(b"<p>x</p>", "text/html; charset=utf-8") == "html"
    assert detect_kind(b"\x89PNG...", "image/png") is None
    assert detect_kind(b"not a zip", MEDIA_DOCX := "application/vnd.openxmlformats-officedocument.wordprocessingml.document") is None
    assert MEDIA_DOCX


def test_word_document_claims_keep_their_heading_and_dates():
    page = extract_document(DOCX, "docx")
    assert page.title == "Acme Security Whitepaper"
    assert page.published_at == datetime(2025, 3, 1, 9, tzinfo=UTC) and page.updated_on == date(2025, 6, 10)
    by_cat = {c.category: c for c in page.claims}
    assert by_cat["encryption_at_rest"].qualifier == "AES-256"
    assert by_cat["encryption_at_rest"].section_heading == "Data protection"
    assert by_cat["compliance_certification"].qualifier == "SOC 2 Type II"


def test_slides_spreadsheets_text_markdown_and_json():
    slides = extract_document(make_pptx([["Security overview"], ["All admins use multi-factor authentication."]]), "pptx")
    assert [(c.category, c.section_heading) for c in slides.claims] == [("mfa", "slide 2")]

    caiq = make_xlsx([["Question", "Answer"],
                      ["Is data encrypted at rest?", "Yes, AES-256 for all customer data"],
                      ["Do you run penetration tests?", "Annually, by an independent firm"]])
    sheet = {(c.category, c.section_heading) for c in extract_document(caiq, "xlsx").claims}
    assert {("encryption_at_rest", "Questionnaire row 2"), ("penetration_testing", "Questionnaire row 3")} <= sheet
    row = next(c for c in extract_document(caiq, "xlsx").claims if c.category == "penetration_testing")
    assert row.claim_text == "Do you run penetration tests? | Annually, by an independent firm"

    txt = extract_document(b"Contact: mailto:security@acme.example\nPolicy: https://acme.example/policy\n\n"
                           b"We run a responsible disclosure program.\n", "text")
    assert {c.category for c in txt.claims} == {"bug_bounty"}  # the https:// link is not a TLS claim

    md = extract_document(b"# Security at Acme\n\n## Access\n\n- We enforce **least privilege** and quarterly access reviews.\n", "markdown")
    assert md.title == "Security at Acme"
    assert [(c.category, c.section_heading) for c in md.claims] == [("access_control", "Access")]

    js = extract_document(b'{"policy": {"text": "<p>We run a bug bounty program on HackerOne.</p>"}}', "json")
    assert [(c.category, c.section_heading) for c in js.claims] == [("bug_bounty", "policy.text")]


def test_broken_documents_give_no_claims_instead_of_failing():
    for kind in ("docx", "pptx", "xlsx", "json"):
        assert extract_document(b"PK\x03\x04 garbage", kind).claims == []


def test_word_document_is_collected(session_factory, store, acme):
    url = "https://acme.example/security-whitepaper.docx"
    doc = FetchResult("captured", url, url, 200, "application/vnd.openxmlformats-officedocument.wordprocessingml.document", DOCX)
    run_import(session_factory, store, TrustCenterJob(store, FakeFetcher({url: doc})),
               targets(["acme", url, "security"]), source_url="file:///t.csv")
    [fetch] = fetches(session_factory)
    assert fetch.outcome == "captured" and fetch.claims_found == 2
    with session_factory() as s:
        assert read_evidence(s, store, s.get(EvidenceVersion, fetch.evidence_version_id)) == DOCX


def test_office_file_with_a_credential_in_its_text_is_withheld(session_factory, store, acme):
    url = "https://acme.example/runbook.docx"
    leaky = make_docx([(None, "Encrypted at rest."), (None, "Admin password = CorrectHorse99")])
    doc = FetchResult("captured", url, url, 200, "application/octet-stream", leaky)
    run_import(session_factory, store, TrustCenterJob(store, FakeFetcher({url: doc})),
               targets(["acme", url, "security"]), source_url="file:///t.csv")
    [fetch] = fetches(session_factory)
    assert fetch.outcome == "withheld" and claims(session_factory) == []


def test_encrypted_pdf_is_read(tmp_path):
    from pypdf import PdfReader, PdfWriter
    w = PdfWriter(clone_from=PdfReader(io.BytesIO(POLICY_PDF)))
    w.encrypt(user_password="", owner_password="owner-only", algorithm="AES-256")  # how many reports are published
    buf = io.BytesIO()
    w.write(buf)
    page = extract(buf.getvalue())
    assert {c.category for c in page.claims} >= {"encryption_at_rest", "mfa"}


def test_unreadable_pdf_does_not_stop_the_run(session_factory, store, acme, monkeypatch):
    from cyber_risk_intelligence.collectors.trust_center import documents, pdf

    def boom(_content):
        raise RuntimeError("cannot decrypt")

    monkeypatch.setattr(documents, "pdf_pages", boom)
    monkeypatch.setattr(pdf, "pdf_pages", boom)
    doc = FetchResult("captured", PDF_URL, PDF_URL, 200, "application/pdf", POLICY_PDF)
    run = run_import(session_factory, store, TrustCenterJob(store, FakeFetcher({PDF_URL: doc})),
                     targets(["acme", PDF_URL, "security"]), source_url="file:///t.csv")
    assert run.status == "succeeded"
    [fetch] = fetches(session_factory)
    assert fetch.outcome == "captured" and fetch.claims_found == 0  # stored, can be read again later
