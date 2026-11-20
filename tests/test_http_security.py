"""Website security headers (issue 1.2)."""

import csv
import io
import json

import httpx
import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from cyber_risk_intelligence.domains import CompanyDomainsJob
from cyber_risk_intelligence.evidence import LocalStore
from cyber_risk_intelligence.http_security import HttpSecurityJob, assess
from cyber_risk_intelligence.http_security.fetch import HeaderFetcher
from cyber_risk_intelligence.ingest import run_import
from cyber_risk_intelligence.models.http_security import (
    HttpSecurityCheck,
    HttpSecurityObservation,
)

from . import factories as f

GOOD = [("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload"),
        ("Content-Security-Policy", "default-src 'self'; script-src 'self' 'nonce-abc'; frame-ancestors 'none'"),
        ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "strict-origin-when-cross-origin")]


def results(headers, https=True):
    return {r.header: r for r in assess(headers, https=https)}


# --- grading -------------------------------------------------------------------------------------------

def test_good_headers_pass_and_csp_frame_ancestors_covers_framing():
    r = results(GOOD)
    assert {h: x.result for h, x in r.items()} == {
        "strict-transport-security": "pass", "content-security-policy": "pass", "x-frame-options": "pass",
        "x-content-type-options": "pass", "referrer-policy": "pass"}
    assert "includesubdomains, preload" in r["strict-transport-security"].note
    assert r["x-frame-options"].value is None and "frame-ancestors" in r["x-frame-options"].note


def test_missing_headers_are_missing():
    r = results([("Server", "nginx")])
    assert all(x.result == "missing" and x.value is None and x.value_count == 0 for x in r.values())


def test_weak_values():
    r = results([("Strict-Transport-Security", "max-age=86400"),
                 ("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval'"),
                 ("Referrer-Policy", "unsafe-url")])
    assert r["strict-transport-security"].result == "weak" and "under 180 days" in r["strict-transport-security"].note
    assert r["content-security-policy"].result == "weak"
    assert "unsafe-inline" in r["content-security-policy"].note and "any host" in r["content-security-policy"].note
    assert r["referrer-policy"].result == "weak"
    assert results([("Strict-Transport-Security", "max-age=0")])["strict-transport-security"].result == "weak"


def test_malformed_values_are_invalid():
    r = results([("Strict-Transport-Security", "includeSubDomains"), ("X-Frame-Options", "ALLOW-FROM https://x"),
                 ("X-Content-Type-Options", "yes"), ("Referrer-Policy", "whatever")])
    assert {h: x.result for h, x in r.items() if h != "content-security-policy"} == {
        "strict-transport-security": "invalid", "x-frame-options": "invalid", "x-content-type-options": "invalid",
        "referrer-policy": "invalid"}


def test_duplicates():
    same = results([("X-Frame-Options", "DENY"), ("x-frame-options", "DENY")])["x-frame-options"]
    assert (same.result, same.value_count) == ("pass", 2) and "sent 2 times" in same.note
    clash = results([("X-Frame-Options", "DENY"), ("X-Frame-Options", "SAMEORIGIN")])["x-frame-options"]
    assert clash.result == "invalid" and clash.value == "DENY\nSAMEORIGIN"
    # several CSP headers all apply; one strong policy is enough
    csp = results([("Content-Security-Policy", "default-src *"),
                   ("Content-Security-Policy", "script-src 'self'")])["content-security-policy"]
    assert csp.result == "pass" and csp.value_count == 2


def test_hsts_on_plain_http_page_is_missing_with_reason():
    r = results([], https=False)["strict-transport-security"]
    assert r.result == "missing" and "not served over HTTPS" in r.note


def test_context_headers_are_info_only():
    r = results([("Permissions-Policy", "camera=()"), ("Content-Security-Policy-Report-Only", "default-src 'self'")])
    assert r["permissions-policy"].result == "info" and r["content-security-policy-report-only"].result == "info"
    assert r["content-security-policy"].result == "missing"


# --- fetching ------------------------------------------------------------------------------------------

def fetcher(routes, calls=None):
    """routes: url -> (status, headers) or an exception to raise."""
    def handler(request):
        url = str(request.url)
        if calls is not None:
            calls.append(url)
        answer = routes.get(url)
        if answer is None:
            raise httpx.ConnectError("refused", request=request)
        if isinstance(answer, Exception):
            raise answer
        status, headers = answer
        return httpx.Response(status, headers=headers, content=b"<html>body is not read</html>")
    return HeaderFetcher(httpx.Client(transport=httpx.MockTransport(handler)))


def test_redirects_are_followed_and_recorded():
    f_ = fetcher({"https://acme.example/": (301, [("Location", "https://www.acme.example/")]),
                  "https://www.acme.example/": (302, [("Location", "/home")]),
                  "https://www.acme.example/home": (200, GOOD)})
    page = f_.page("acme.example")
    assert page.outcome == "answered" and page.final_url == "https://www.acme.example/home"
    assert page.redirects == [[301, "https://www.acme.example/"], [302, "https://www.acme.example/home"]]
    assert ("X-Content-Type-Options", "nosniff") in page.headers


def test_redirect_loop_and_timeout_are_request_failures():
    loop = fetcher({"https://acme.example/": (302, [("Location", "https://acme.example/")])}).page("acme.example")
    assert loop.outcome == "request_failed" and "redirects" in loop.message
    slow = fetcher({"https://acme.example/": httpx.ReadTimeout("timed out")}).page("acme.example")
    assert slow.outcome == "request_failed" and "ReadTimeout" in slow.message and slow.headers == []


def test_plain_http_redirect():
    to_https = fetcher({"http://acme.example/": (301, [("Location", "http://www.acme.example/")]),
                        "http://www.acme.example/": (301, [("Location", "https://www.acme.example/")])})
    r = to_https.http_redirect("acme.example")
    assert (r.outcome, r.location) == ("redirects_to_https", "https://www.acme.example/")
    assert fetcher({"http://acme.example/": (200, [])}).http_redirect("acme.example").outcome == "no_redirect"
    assert fetcher({}).http_redirect("acme.example").outcome == "request_failed"


# --- the job -------------------------------------------------------------------------------------------

def csv_bytes(header, *rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    w.writerows(rows)
    return buf.getvalue().encode()


@pytest.fixture
def store(tmp_path):
    return LocalStore(tmp_path / "evidence")


@pytest.fixture
def acme(session_factory, store):
    with session_factory() as s:
        f.company(s, "acme", "Acme")
        s.commit()
    run = run_import(session_factory, store, CompanyDomainsJob(), csv_bytes(
        ["company_key", "domain", "role", "source_url"],
        ["acme", "acme.example", "primary_website", "https://www.wikidata.org/entity/Q1"]),
        source_url="file:///domains.csv")
    assert run.status == "succeeded"


ROUTES = {"https://acme.example/": (301, [("Location", "https://www.acme.example/")]),
          "https://www.acme.example/": (200, [*GOOD, ("Set-Cookie", "session=SECRET123; Secure"),
                                              ("Date", "Thu, 19 Nov 2026 00:00:00 GMT")]),
          "http://acme.example/": (301, [("Location", "https://acme.example/")]),
          "http://www.acme.example/": (200, [])}


def run_job(sf, store, routes):
    calls = []
    run = run_import(sf, store, HttpSecurityJob(store, fetcher(routes, calls)),
                     csv_bytes(["company_key", "domain"], ["acme", "acme.example"]), source_url="file:///t.csv")
    return run, calls


def test_job_records_checks_and_graded_headers(session_factory, store, acme, tmp_path):
    run, calls = run_job(session_factory, store, ROUTES)
    assert run.status == "succeeded" and run.rows_inserted == 1
    assert all("acme.example/" in c for c in calls)  # home pages of the two known hosts only
    with session_factory() as s:
        checks = {c.host: c for c in s.scalars(select(HttpSecurityCheck))}
        obs = s.scalars(select(HttpSecurityObservation)).all()
        latest = s.execute(text("SELECT count(*) FROM latest_http_security_checks")).scalar()
    bare, www = checks["acme.example"], checks["www.acme.example"]
    assert bare.http_redirect == "redirects_to_https" and www.http_redirect == "no_redirect"
    assert bare.final_url == "https://www.acme.example/" and bare.redirects == [[301, "https://www.acme.example/"]]
    assert {o.result for o in obs} == {"pass"} and len(obs) == 10 and latest == 2
    stored = b"".join(p.read_bytes() for p in (tmp_path / "evidence").rglob("*") if p.is_file())
    assert b"SECRET123" not in stored and b"Thu, 19 Nov" not in stored  # cookies and dates are not kept
    doc = json.loads(next(p.read_bytes() for p in (tmp_path / "evidence").rglob("*")
                          if p.is_file() and b"final_url" in p.read_bytes()))
    assert ["x-content-type-options", "nosniff"] in doc["headers"]

    run, _ = run_job(session_factory, store, ROUTES)  # same headers again: same evidence
    assert run.rows_unchanged == 1


def test_unreachable_site_is_a_failed_request_not_missing_headers(session_factory, store, acme):
    run, _ = run_job(session_factory, store, {})
    assert run.rows_updated == 1
    with session_factory() as s:
        checks = s.scalars(select(HttpSecurityCheck)).all()
        assert {c.outcome for c in checks} == {"request_failed"} and all(c.evidence_version_id is None for c in checks)
        assert s.scalars(select(HttpSecurityObservation)).all() == []


def test_database_refuses_missing_header_with_a_value(session_factory, store, acme):
    run_job(session_factory, store, ROUTES)
    with session_factory() as s:
        o = s.scalars(select(HttpSecurityObservation)).first()
        o.result = "missing"
        with pytest.raises(IntegrityError):
            s.flush()
