"""MTA-STS and SMTP TLS reporting (issue 23.4). Fake resolver and mock HTTP only; nothing is contacted."""

import csv
import io

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from cyber_risk_intelligence.domains import CompanyDomainsJob
from cyber_risk_intelligence.email_security import (
    MtaStsJob,
    PolicyFetcher,
    TxtLookup,
    read_policy,
    read_sts_record,
    read_tlsrpt_record,
)
from cyber_risk_intelligence.email_security.__main__ import mta_sts_summary
from cyber_risk_intelligence.evidence import LocalStore
from cyber_risk_intelligence.ingest import run_import
from cyber_risk_intelligence.models import MtaStsObservation, TlsReportingObservation

from . import factories as f

NX = TxtLookup("nxdomain", "fake-resolver", rcode="NXDOMAIN")
TIMEOUT = TxtLookup("lookup_failed", "fake-resolver", rcode="TIMEOUT", message="timed out")
URL = "https://mta-sts.acme.example/.well-known/mta-sts.txt"
POLICY = b"version: STSv1\r\nmode: enforce\r\nmx: mail.acme.example\r\nmx: *.mx.acme.example\r\nmax_age: 604800\r\n"


class FakeResolver:
    name = "fake-resolver"

    def __init__(self, answers):
        self.answers, self.calls = answers, []

    def txt(self, name):
        self.calls.append(name)
        a = self.answers.get(name, NX)
        if isinstance(a, TxtLookup):
            return a
        return TxtLookup("answered", self.name, rcode="NOERROR", answers=a, ttl=300)


def fetcher(answer, calls=None):
    """answer: (status, body, headers) or an exception to raise for every request."""
    def handler(request):
        if calls is not None:
            calls.append((str(request.url), request.headers.get("user-agent")))
        if isinstance(answer, Exception):
            raise answer
        status, body, headers = answer
        return httpx.Response(status, content=body, headers=headers)
    return PolicyFetcher(httpx.Client(transport=httpx.MockTransport(handler)))


# --- reading records and policies ----------------------------------------------------------------------

def test_sts_record():
    r = read_sts_record(["v=spf1 -all", "v=STSv1; id=20261101T000000"])
    assert (r.status, r.tags["id"]) == ("present", "20261101T000000")
    assert read_sts_record(["v=STSv1; id=bad-id!"]).status == "invalid"
    assert read_sts_record(["v=STSv1;"]).status == "invalid"  # id is required
    assert read_sts_record(["v=STSv1; id=a", "v=STSv1; id=b"]).status == "multiple"
    assert read_sts_record(["v=STSv10; id=a"]).status == "missing"


def test_tlsrpt_record():
    r = read_tlsrpt_record(["v=TLSRPTv1; rua=mailto:tls@acme.example,https://report.acme.example/tls"])
    assert r.status == "present"
    assert read_tlsrpt_record(["v=TLSRPTv1;"]).problems == ["no rua= reporting address"]
    assert read_tlsrpt_record(["v=TLSRPTv1; rua=ftp://x"]).status == "invalid"
    assert read_tlsrpt_record([]).status == "missing"


def test_valid_policy():
    p = read_policy(POLICY.decode())
    assert (p.status, p.version, p.mode, p.max_age) == ("valid", "STSv1", "enforce", 604800)
    assert p.mx == ["mail.acme.example", "*.mx.acme.example"]
    assert read_policy("version: STSv1\nmode: none\nmax_age: 86400\n").status == "valid"  # none needs no mx


def test_malformed_policies_are_invalid_with_reasons():
    assert read_policy("<html>Welcome</html>").problems[0].startswith("line '<html>")
    p = read_policy("version: STSv2\nmode: strict\nmax_age: forever\n")
    assert p.status == "invalid" and len(p.problems) == 3
    assert "no mx patterns" in read_policy("version: STSv1\nmode: enforce\nmax_age: 60\n").problems
    assert "max_age over" in read_policy(f"version: STSv1\nmode: none\nmax_age: {10**9}\n").problems[0]


# --- fetching the policy -------------------------------------------------------------------------------

def test_fetch_retrieves_policy_and_sends_no_redirect():
    calls = []
    got = fetcher((200, POLICY, {}), calls).fetch("acme.example")
    assert (got.outcome, got.body) == ("retrieved", POLICY) and calls[0][0] == URL
    moved = fetcher((301, b"", {"Location": "https://elsewhere.example/policy"})).fetch("acme.example")
    assert (moved.outcome, moved.http_status) == ("request_failed", 301)  # RFC 8461: redirects not followed


def test_fetch_outcomes_are_kept_apart():
    assert fetcher((404, b"", {})).fetch("acme.example").outcome == "not_found"
    expired = httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: certificate has expired")
    assert fetcher(expired).fetch("acme.example").outcome == "certificate_invalid"
    slow = fetcher(httpx.ReadTimeout("timed out")).fetch("acme.example")
    assert slow.outcome == "request_failed" and "ReadTimeout" in slow.message
    big = fetcher((200, b"x" * (64 * 1024 + 1), {})).fetch("acme.example")
    assert big.outcome == "request_failed" and "64 KB" in big.message


# --- the job -------------------------------------------------------------------------------------------

def csv_bytes(header, *rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    w.writerows(rows)
    return buf.getvalue().encode()


@pytest.fixture
def store(tmp_path):
    return LocalStore(tmp_path)


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


ANNOUNCED = {"_mta-sts.acme.example": [["v=STSv1; id=20261101"]],
             "_smtp._tls.acme.example": [["v=TLSRPTv1; rua=mailto:tls-reports@acme.example"]]}


def collect(sf, store, answers, http, calls=None):
    resolver = FakeResolver(answers)
    run = run_import(sf, store, MtaStsJob(store, resolver, fetcher(http, calls)),
                     csv_bytes(["company_key", "domain"], ["acme", "acme.example"]), source_url="file:///t.csv")
    return run, resolver


def latest(sf):
    with sf() as s:
        m = s.scalars(select(MtaStsObservation).order_by(MtaStsObservation.id.desc())).first()
        t = s.scalars(select(TlsReportingObservation).order_by(TlsReportingObservation.id.desc())).first()
        s.expunge_all()
    return m, t


def test_valid_policy_is_recorded_with_evidence(session_factory, store, acme, tmp_path, capsys):
    calls = []
    run, resolver = collect(session_factory, store, ANNOUNCED, (200, POLICY, {}), calls)
    assert run.status == "succeeded" and run.rows_inserted == 1
    assert resolver.calls == ["_mta-sts.acme.example", "_smtp._tls.acme.example"]
    assert [c[0] for c in calls] == [URL]  # one request, to the policy URL only
    m, t = latest(session_factory)
    assert (m.dns_status, m.sts_id, m.policy_retrieval, m.policy_status, m.mode) == (
        "present", "20261101", "retrieved", "valid", "enforce")
    assert m.mx_patterns == ["mail.acme.example", "*.mx.acme.example"] and m.max_age == 604800
    assert m.policy_evidence_version_id is not None and m.problems is None
    assert (t.status, t.report_uris) == ("present", ["mailto:tls-reports@acme.example"])
    assert any(p.read_bytes() == POLICY for p in tmp_path.rglob("*") if p.is_file())
    mta_sts_summary(session_factory)
    out = capsys.readouterr().out
    assert "valid policy mode=enforce: 1" in out and "tls-rpt present: 1" in out

    run, _ = collect(session_factory, store, ANNOUNCED, (200, POLICY, {}))
    assert run.rows_unchanged == 1  # same records and same policy file


def test_no_record_means_no_fetch(session_factory, store, acme):
    calls = []
    run, _ = collect(session_factory, store, {}, (200, POLICY, {}), calls)
    assert calls == [] and run.rows_inserted == 1
    m, t = latest(session_factory)
    assert (m.dns_status, m.policy_retrieval, m.policy_status) == ("missing", "not_attempted", None)
    assert t.status == "missing" and t.evidence_version_id is not None  # the empty answer is evidence


def test_expired_certificate_is_its_own_outcome(session_factory, store, acme):
    expired = httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: certificate has expired")
    collect(session_factory, store, ANNOUNCED, expired)
    m, _ = latest(session_factory)
    assert (m.dns_status, m.policy_retrieval, m.policy_status) == ("present", "certificate_invalid", None)
    assert "expired" in m.message and m.policy_evidence_version_id is None


def test_malformed_policy_is_invalid_and_kept(session_factory, store, acme):
    collect(session_factory, store, ANNOUNCED, (200, b"version: STSv1\nmode: enforce\n", {}))
    m, _ = latest(session_factory)
    assert (m.policy_retrieval, m.policy_status) == ("retrieved", "invalid")
    assert "no mx patterns" in m.problems and m.policy_evidence_version_id is not None


def test_failed_lookup_and_failed_fetch_are_not_absence(session_factory, store, acme):
    run, _ = collect(session_factory, store, {"_mta-sts.acme.example": TIMEOUT, "_smtp._tls.acme.example": TIMEOUT},
                     (200, POLICY, {}))
    assert run.rows_updated == 1
    m, t = latest(session_factory)
    assert (m.dns_status, m.policy_retrieval, m.message) == ("lookup_failed", "not_attempted", "timed out")
    assert (t.status, t.evidence_version_id) == ("lookup_failed", None)

    run, _ = collect(session_factory, store, ANNOUNCED, httpx.ConnectTimeout("timed out"))
    assert run.rows_updated == 1
    m, _ = latest(session_factory)
    assert (m.dns_status, m.policy_retrieval) == ("present", "request_failed")


def test_database_refuses_a_fetch_without_an_announcement(session_factory, store, acme):
    collect(session_factory, store, {}, (200, POLICY, {}))
    with session_factory() as s:
        m = s.scalars(select(MtaStsObservation)).one()
        m.policy_retrieval = "not_found"
        with pytest.raises(IntegrityError):
            s.flush()
