"""Acceptance tests for issue 23.1 (SPF record collection). Fake resolver only; no DNS queries, no email."""

import csv
import io
import json

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from cyber_risk_intelligence.domains import CompanyDomainsJob, normalize_domain
from cyber_risk_intelligence.email_security import (
    SpfJob,
    TxtLookup,
    parse_spf,
    read_spf,
    targets_csv,
)
from cyber_risk_intelligence.evidence import LocalStore, read_evidence
from cyber_risk_intelligence.ingest import run_import
from cyber_risk_intelligence.models import (
    CompanyDomain,
    DnsSecurityRecord,
    EmailSecurityObservation,
    EvidenceVersion,
    IngestionError,
    ValidationResult,
)
from cyber_risk_intelligence.quality import run_validation

from . import factories as f

GOOGLE_STYLE = ["v=spf1 include:_spf.google.com ip4:192.0.2.0/24 ", "ip6:2001:db8::/32 ~all"]  # split TXT strings


class FakeResolver:
    name = "fake-resolver"

    def __init__(self, answers):
        self.answers, self.calls = answers, []

    def txt(self, name):
        self.calls.append(name)
        a = self.answers[name]
        if isinstance(a, TxtLookup):
            return a
        return TxtLookup("answered", self.name, rcode="NOERROR", answers=a, ttl=300)


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
        f.company(s, "globex", "Globex")
        s.commit()
    run = run_import(session_factory, store, CompanyDomainsJob(), csv_bytes(
        ["company_key", "domain", "role", "source_url"],
        ["acme", "https://www.Acme.example/", "primary_website", "https://www.wikidata.org/entity/Q1"],
        ["acme", "acme-mail.example", "email", "https://www.wikidata.org/entity/Q1"],
        ["globex", "globex.example", "primary_website", "https://www.wikidata.org/entity/Q2"],
    ), source_url="file:///domains.csv")
    assert (run.status, run.rows_inserted) == ("succeeded", 3)


def collect(sf, store, answers, *rows):
    job = SpfJob(store, FakeResolver(answers))
    rows = rows or (["acme", "acme.example"],)
    return run_import(sf, store, job, csv_bytes(["company_key", "domain"], *rows), source_url="file:///t.csv"), job


def observations(sf):
    with sf() as s:
        return s.scalars(select(EmailSecurityObservation).order_by(EmailSecurityObservation.id)).all()


# --- parsing --------------------------------------------------------------------------------------------

def test_split_txt_strings_are_joined_without_spaces():
    r = read_spf([GOOGLE_STYLE, ["google-site-verification=abc"]])
    assert r.status == "present"
    assert r.record.text == "v=spf1 include:_spf.google.com ip4:192.0.2.0/24 ip6:2001:db8::/32 ~all"
    assert [(m["qualifier"], m["type"], m["value"]) for m in r.record.mechanisms] == [
        ("pass", "include", "_spf.google.com"), ("pass", "ip4", "192.0.2.0/24"),
        ("pass", "ip6", "2001:db8::/32"), ("softfail", "all", None)]
    assert (r.record.all_qualifier, r.record.dns_lookup_terms, r.record.problems) == ("softfail", 1, [])


@pytest.mark.parametrize("record, qualifier", [
    ("v=spf1 -all", "fail"), ("v=spf1 ~all", "softfail"), ("v=spf1 ?all", "neutral"), ("v=spf1 +all", "pass"),
    ("v=spf1 all", "pass"), ("v=spf1 mx", None),
])
def test_qualifiers(record, qualifier):
    assert parse_spf(record).all_qualifier == qualifier


def test_plus_all_and_too_many_lookups_are_flagged():
    assert "+all lets any server send as this domain" in parse_spf("v=spf1 +all").problems
    many = parse_spf("v=spf1 " + " ".join(f"include:s{i}.example" for i in range(11)) + " -all")
    assert many.valid and many.dns_lookup_terms == 11 and "SPF allows 10" in many.problems[0]


@pytest.mark.parametrize("record, problem", [
    ("v=spf1 ip4:999.1.1.1 -all", "not a valid address"),
    ("v=spf1 ip4:2001:db8::1 -all", "wrong address family"),
    ("v=spf1 include -all", "include needs a value"),
    ("v=spf1 foo:bar -all", "unknown mechanism"),
    ("v=spf1 all:example.com", "all takes no value"),
    ("v=spf1 redirect=a.example redirect=b.example", "more than once"),
])
def test_malformed_mechanisms_make_the_record_invalid(record, problem):
    rec = parse_spf(record)
    assert not rec.valid and any(problem in p for p in rec.problems)
    assert read_spf([[record]]).status == "invalid"


def test_modifiers_and_cidr_forms():
    rec = parse_spf("v=spf1 a/24 mx:mail.example/24//64 redirect=_spf.example exp=explain.example")
    assert rec.valid and rec.redirect == "_spf.example" and rec.dns_lookup_terms == 3
    assert [m["name"] for m in rec.modifiers] == ["redirect", "exp"]


def test_multiple_and_missing_records():
    assert read_spf([["v=spf1 -all"], ["v=spf1 include:x.example ~all"]]).status == "multiple"
    assert read_spf([["v=spf10 nope"], ["some other txt"]]).status == "missing"
    assert read_spf([]).status == "missing"


def test_domain_normalization():
    assert normalize_domain("https://WWW.Acme.Example:443/about") == "acme.example"
    assert normalize_domain("bücher.example") == "xn--bcher-kva.example"
    for bad in ("", "localhost", "-bad.example", "1.2.3.4", "a..b"):
        assert normalize_domain(bad) is None


# --- domains ----------------------------------------------------------------------------------------------

def test_domain_import_cites_its_source_and_is_idempotent(session_factory, store, acme):
    again = run_import(session_factory, store, CompanyDomainsJob(), csv_bytes(
        ["company_key", "domain", "role", "source_url"],
        ["acme", "acme.example", "primary_website", "https://www.wikidata.org/entity/Q1"],
        ["nobody", "x.example", "primary_website", "https://example.org/"],
        ["acme", "not a domain", "primary_website", "https://example.org/"],
        ["acme", "acme.example", "primary_website", ""],
    ), source_url="file:///domains2.csv")
    assert (again.rows_unchanged, again.rows_rejected, again.rows_inserted) == (1, 3, 0)
    with session_factory() as s:
        links = s.scalars(select(CompanyDomain)).all()
        assert len(links) == 3 and {cd.verification_status for cd in links} == {"unverified"}
        assert all(cd.source_ref.startswith("https://www.wikidata.org/") for cd in links)
        assert targets_csv(s).decode().splitlines() == [
            "company_key,domain", "acme,acme-mail.example", "acme,acme.example", "globex,globex.example"]


# --- collection --------------------------------------------------------------------------------------------

def test_spf_lookup_is_stored_with_raw_answer_and_evidence(session_factory, store, acme):
    run, _ = collect(session_factory, store, {"acme.example": [GOOGLE_STYLE, ["google-site-verification=abc"]]})
    assert (run.status, run.rows_inserted) == ("succeeded", 1)
    [obs] = observations(session_factory)
    assert (obs.status, obs.all_qualifier, obs.record_count, obs.dns_lookup_terms) == ("present", "softfail", 1, 1)
    assert obs.record_text.startswith("v=spf1 include:_spf.google.com") and obs.verification_status == "observed"
    with session_factory() as s:
        lookup = s.get(DnsSecurityRecord, obs.dns_record_id)
        assert (lookup.outcome, lookup.resolver, lookup.ttl, lookup.record_type) == ("answered", "fake-resolver", 300, "TXT")
        assert GOOGLE_STYLE in lookup.answers  # the strings exactly as split on the wire
        version = s.get(EvidenceVersion, obs.evidence_version_id)
        stored = json.loads(read_evidence(s, store, version))
        assert stored["query"] == "acme.example" and GOOGLE_STYLE in stored["answers"]


@pytest.mark.parametrize("answer, status", [
    ([["v=spf1 -all"], ["v=spf1 ~all"]], "multiple"),
    ([["v=spf1 ip4:300.0.0.1 -all"]], "invalid"),
    ([["MS=ms12345"]], "missing"),
    (TxtLookup("no_records", "fake-resolver", rcode="NOERROR"), "missing"),
    (TxtLookup("nxdomain", "fake-resolver", rcode="NXDOMAIN"), "no_domain"),
])
def test_each_outcome_is_recorded_distinctly(session_factory, store, acme, answer, status):
    collect(session_factory, store, {"acme.example": answer})
    [obs] = observations(session_factory)
    assert obs.status == status and obs.evidence_version_id is not None


def test_dns_failure_is_not_missing_spf(session_factory, store, acme):
    failed = TxtLookup("lookup_failed", "fake-resolver", rcode="TIMEOUT", message="The DNS operation timed out")
    run, _ = collect(session_factory, store, {"acme.example": failed})
    assert run.status == "succeeded"
    [obs] = observations(session_factory)
    assert (obs.status, obs.evidence_version_id, obs.record_text) == ("lookup_failed", None, None)
    assert obs.problems == ["The DNS operation timed out"]
    run = run_validation(session_factory)
    with session_factory() as s:
        hits = set(s.scalars(select(ValidationResult.rule).where(
            ValidationResult.validation_run_id == run.id, ValidationResult.rows_failed > 0)))
    assert "spf_lookup_failed" in hits  # flagged to retry, never counted as "no SPF"


def test_failure_after_success_keeps_history(session_factory, store, acme):
    collect(session_factory, store, {"acme.example": [["v=spf1 -all"]]})
    collect(session_factory, store, {"acme.example": TxtLookup("lookup_failed", "fake-resolver", rcode="SERVFAIL")})
    assert [o.status for o in observations(session_factory)] == ["present", "lookup_failed"]
    with session_factory() as s:
        latest = s.execute(text("SELECT status FROM latest_spf_observations")).scalars().all()
    assert latest == ["lookup_failed"]


def test_repeat_lookup_reuses_the_stored_answer(session_factory, store, acme):
    collect(session_factory, store, {"acme.example": [["v=spf1 -all"]]})
    second, _ = collect(session_factory, store, {"acme.example": [["v=spf1 -all"]]})
    assert second.rows_unchanged == 1
    obs = observations(session_factory)
    assert len(obs) == 2 and obs[0].evidence_version_id == obs[1].evidence_version_id  # two observations, one copy
    third, _ = collect(session_factory, store, {"acme.example": [["v=spf1 ~all"]]})
    assert third.rows_inserted == 1
    assert observations(session_factory)[-1].evidence_version_id != obs[0].evidence_version_id


def test_unknown_company_or_unlinked_domain_is_rejected_without_a_query(session_factory, store, acme):
    run, job = collect(session_factory, store, {}, ["nobody", "acme.example"], ["acme", "globex.example"],
                       ["acme", "not_a_domain"])
    assert run.rows_rejected == 3 and job._resolver.calls == []
    with session_factory() as s:
        codes = sorted(e.code for e in s.scalars(select(IngestionError).where(IngestionError.run_id == run.id)))
    assert codes == ["domain_not_linked", "domain_valid", "unknown_company"]


def test_observations_cannot_be_marked_verified(session_factory, store, acme):
    collect(session_factory, store, {"acme.example": [["v=spf1 -all"]]})
    with session_factory() as s:
        obs = s.scalars(select(EmailSecurityObservation)).one()
        obs.verification_status = "verified"
        with pytest.raises(IntegrityError):
            s.flush()


def test_wikidata_domain_list_keeps_parent_domains_and_reports_gaps():
    import httpx

    from cyber_risk_intelligence.domains.wikidata import build

    seed = (b"Company name,Current issuer CIK\nAcme Corp,0000000001\nGlobex,0000000002\n")

    def handler(request):
        assert request.url.host == "query.wikidata.org"
        item = {"type": "uri", "value": "http://www.wikidata.org/entity/Q1"}
        rows = [{"cik": {"value": "0000000001"}, "item": item, "site": {"value": url}}
                for url in ("https://www.acme.example/", "https://de.acme.example/", "https://acme.example/en")]
        return httpx.Response(200, json={"results": {"bindings": rows}})

    out, missing = build(seed, client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert out.splitlines() == ["company_key,domain,role,source_url,notes",
                                "acme,acme.example,primary_website,https://www.wikidata.org/entity/Q1,"
                                "Wikidata P856 official website"]
    assert missing == ["globex"]  # no match is reported, not written as "no domain"
