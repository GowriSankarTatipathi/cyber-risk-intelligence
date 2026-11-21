"""Aggregate infostealer exposure (issue 11.2). Synthetic Hudson Rock answers via a mocked client; nothing is contacted."""
# ruff: noqa: F811 - pytest fixtures imported from test_exposure

import json

import httpx
from sqlalchemy import select, text

from cyber_risk_intelligence.breaches.__main__ import infostealer_summary
from cyber_risk_intelligence.breaches.infostealers import (
    InfostealerClient,
    InfostealerJob,
    summarize,
)
from cyber_risk_intelligence.evidence import read_evidence
from cyber_risk_intelligence.ingest import run_import
from cyber_risk_intelligence.models import AggregateExposureObservation, EvidenceVersion

from .test_exposure import acme, store  # noqa: F401 - fixtures


def answer(employees=3, users=40, third=2, **kw):
    doc = {"total": employees + users + third, "totalStealers": 37000000, "employees": employees, "users": users,
           "third_parties": third, "logo": "https://cdn.example/logo.png",
           "data": {"employees_urls": [
               {"occurrence": 5, "type": "Employee", "url": "https://vpn.acme.example/+CSCOE+/logon.html?token=s3cr3t"},
               {"occurrence": 2, "type": "Employee", "url": "https://vpn.acme.example/"},
               {"occurrence": 1, "type": "Employee", "url": "https://jane.doe@intranet.acme.example/login"},
               {"occurrence": 1, "type": "Employee", "url": "android://abc@com.acme.app/"}],
                    "clients_urls": [{"occurrence": 30, "type": "User", "url": "https://shop.acme.example/signin"}]},
           "last_employee_compromised": "2026-08-03T08:27:18.794Z", "last_user_compromised": "2026-11-19T23:32:48.000Z",
           "employeePasswords": {"totalPass": 4, "too_weak": {"qty": 1, "perc": 25}, "weak": {"qty": 2, "perc": 50},
                                 "medium": {"qty": 1, "perc": 25}, "strong": {"qty": 0, "perc": 0}},
           "thirdPartyDomains": [{"occurrence": 4, "domain": "microsoftonline.com"}, {"domain": "x@y.example"}],
           "stealerFamilies": {"total": 45, "RedLine": 20, "Lumma": 25}}
    doc.update(kw)
    return doc


NONE = {"total": 0, "totalStealers": 37000000, "employees": 0, "users": 0, "third_parties": 0,
        "data": {"employees_urls": [], "clients_urls": [], "all_urls": []}}


def client(answers, calls=None):
    def handler(request):
        if calls is not None:
            calls.append(request)
        a = answers.pop(0) if isinstance(answers, list) else answers
        return a if isinstance(a, httpx.Response) else httpx.Response(200, json=a)
    return InfostealerClient(httpx.Client(transport=httpx.MockTransport(handler)), pause=0, backoff_s=0)


def run(sf, store, c, domains=("acme.example",)):
    job = InfostealerJob(store, c)
    content = ("company_key,domain\n" + "".join(f"acme,{d}\n" for d in domains)).encode()
    return run_import(sf, store, job, content, source_url="db:company_domains"), job


def test_summary_keeps_counts_and_host_names_only():
    s = summarize(answer())
    blob = json.dumps(s)
    assert (s["employees"], s["users"], s["third_parties"], s["total"]) == (3, 40, 2, 45)
    assert s["employee_login_hosts"] == [{"host": "vpn.acme.example", "occurrence": 7, "hint": "remote_access"}]
    assert s["employee_passwords"] == {"total": 4, "too_weak": 1, "weak": 2, "medium": 1, "strong": 0}
    assert s["stealer_families"] == {"Lumma": 25, "RedLine": 20}
    assert s["third_party_domains"] == [{"domain": "microsoftonline.com", "occurrence": 4}]
    for leaked in ("token", "s3cr3t", "jane", "@", "CSCOE", "logon.html", "logo"):
        assert leaked not in blob  # no paths, queries, user names or addresses


def test_answers_are_stored_with_redacted_evidence(session_factory, store, acme):
    r, job = run(session_factory, store, client([answer()]))
    assert (r.status, r.rows_inserted, job.tally["found"]) == ("succeeded", 1, 1)
    with session_factory() as s:
        o = s.scalar(select(AggregateExposureObservation))
        assert (o.outcome, o.provider, o.employees, o.users, o.third_parties) == ("found", "hudson_rock", 3, 40, 2)
        assert o.last_employee_infection_at.year == 2026 and o.employee_login_hosts[0]["host"] == "vpn.acme.example"
        stored = read_evidence(s, store, s.get(EvidenceVersion, o.evidence_version_id))
        assert b"s3cr3t" not in stored and b"@" not in stored and json.loads(stored)["employees"] == 3
        latest = s.execute(text("SELECT employees FROM latest_aggregate_exposure")).scalar()
        assert latest == 3


def test_rate_limit_is_unknown_not_zero_and_keeps_the_last_answer(session_factory, store, acme, capsys):
    run(session_factory, store, client([answer(employees=9)]))
    calls = []
    _, job = run(session_factory, store, client([httpx.Response(429), httpx.Response(503), httpx.Response(429)],
                                                calls))
    assert job.tally["lookup_failed"] == 1 and len(calls) == 3  # retried, then recorded as failed
    with session_factory() as s:
        failed = s.scalar(select(AggregateExposureObservation).where(
            AggregateExposureObservation.outcome == "lookup_failed"))
        assert (failed.employees, failed.users, failed.total_infections, failed.evidence_version_id) == (
            None, None, None, None)
        assert "429" in failed.message
        assert s.execute(text("SELECT employees FROM latest_aggregate_exposure")).scalar() == 9  # last real answer
    _, job = run(session_factory, store, client([httpx.Response(403)]))
    assert job.tally["lookup_failed"] == 1  # other 4xx is not retried, still unknown


def test_nothing_in_the_source_is_none_reported(session_factory, store, acme, capsys):
    _, job = run(session_factory, store, client([NONE]))
    assert job.tally["none_reported"] == 1
    with session_factory() as s:
        o = s.scalar(select(AggregateExposureObservation))
        assert (o.outcome, o.employees, o.users) == ("none_reported", 0, 0) and o.evidence_version_id is not None
    infostealer_summary(session_factory)
    assert "0 with infections, 1 none reported" in capsys.readouterr().out


def test_bad_answers_are_failed_lookups(session_factory, store, acme):
    _, job = run(session_factory, store, client([httpx.Response(200, text="<html>blocked</html>")]))
    assert job.tally["lookup_failed"] == 1
    _, job = run(session_factory, store, client([{"message": "no total"}]))
    assert job.tally["lookup_failed"] == 1


def test_unknown_domain_is_rejected_before_any_request(session_factory, store, acme):
    calls = []
    r, _ = run(session_factory, store, client([answer()], calls), domains=("other.example",))
    assert r.rows_rejected == 1 and calls == []


def test_summary_lists_companies_by_employee_count(session_factory, store, acme, capsys):
    run(session_factory, store, client([answer()]))
    infostealer_summary(session_factory)
    out = capsys.readouterr().out
    assert "1 with infections" in out and "vpn.acme.example" in out and "3/4" in out
