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
from cyber_risk_intelligence.collectors.trust_center.fetch import FetchResult
from cyber_risk_intelligence.evidence import LocalStore, read_evidence
from cyber_risk_intelligence.ingest import run_import
from cyber_risk_intelligence.models import EvidenceVersion, PageFetch, SecurityControlClaim
from cyber_risk_intelligence.quality import run_validation

from . import factories as f

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
    assert classify(URL, 200, URL, "application/pdf", b"%PDF").outcome == "not_html"


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
