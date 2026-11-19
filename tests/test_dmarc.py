"""Acceptance tests for issue 23.2 (DMARC policy collection). Fake resolver only; no DNS queries, no reports sent."""
# ruff: noqa: F811 - the store/acme fixtures are shared with test_email_security

import pytest
from sqlalchemy import select, text

from cyber_risk_intelligence.email_security import (
    DmarcJob,
    TxtLookup,
    organizational_domain,
    parse_dmarc,
    read_dmarc,
)
from cyber_risk_intelligence.ingest import run_import
from cyber_risk_intelligence.models import (
    DnsSecurityRecord,
    EmailSecurityObservation,
    ValidationResult,
)
from cyber_risk_intelligence.quality import run_validation

from .test_email_security import (  # noqa: F401 - fixtures
    FakeResolver,
    acme,
    csv_bytes,
    store,
)

REJECT = "v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=r; pct=100; rua=mailto:dmarc@acme.example; " \
         "ruf=mailto:forensic@acme.example; fo=1"


def collect(sf, store, answers, *rows):
    job = DmarcJob(store, FakeResolver(answers))
    rows = rows or (["acme", "acme.example"],)
    return run_import(sf, store, job, csv_bytes(["company_key", "domain"], *rows), source_url="file:///t.csv"), job


def observations(sf):
    with sf() as s:
        return s.scalars(select(EmailSecurityObservation).where(EmailSecurityObservation.control == "dmarc")
                         .order_by(EmailSecurityObservation.id)).all()


# --- parsing --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("record, policy", [
    ("v=DMARC1; p=none; rua=mailto:r@acme.example", "none"),
    ("v=DMARC1; p=quarantine; rua=mailto:r@acme.example", "quarantine"),
    ("v=DMARC1;p=REJECT;rua=mailto:r@acme.example", "reject"),
])
def test_policies(record, policy):
    rec = parse_dmarc(record)
    assert rec.valid and rec.policy == policy and rec.subdomain_policy == policy  # sp defaults to p


def test_strict_and_relaxed_alignment_and_defaults_are_kept_apart():
    rec = parse_dmarc(REJECT)
    assert (rec.dkim_alignment, rec.spf_alignment, rec.subdomain_policy, rec.pct) == ("strict", "relaxed", "quarantine", 100)
    assert rec.defaults_used == [] and rec.tags["aspf"] == "r"  # relaxed because the record says so
    bare = parse_dmarc("v=DMARC1; p=reject; rua=mailto:r@acme.example")
    assert (bare.dkim_alignment, bare.spf_alignment) == ("relaxed", "relaxed")
    assert bare.defaults_used == ["sp", "adkim", "aspf", "pct"]  # relaxed by default


def test_reporting_destinations_are_recorded_not_used():
    rec = parse_dmarc("v=DMARC1; p=none; rua=mailto:a@x.example,mailto:b@y.example!10m; ruf=mailto:f@x.example")
    assert rec.aggregate_reports == ["mailto:a@x.example", "mailto:b@y.example!10m"]
    assert rec.failure_reports == ["mailto:f@x.example"]


@pytest.mark.parametrize("record, problem", [
    ("v=DMARC1; sp=quarantine", "required tag p is missing"),
    ("v=DMARC1; p=block", "p=block"),
    ("p=reject; v=DMARC1", "does not start with v=DMARC1"),
    ("v=DMARC1 p=reject", "does not start with v=DMARC1"),  # missing semicolon after the version
])
def test_records_receivers_discard_are_invalid(record, problem):
    rec = parse_dmarc(record)
    assert not rec.valid and any(problem in p for p in rec.problems)


@pytest.mark.parametrize("record, problem", [
    ("v=DMARC1; p=reject; adkim=x", "adkim=x"),
    ("v=DMARC1; p=reject; pct=150", "pct=150"),
    ("v=DMARC1; p=reject; rua=dmarc@acme.example", "not a mailto"),
    ("v=DMARC1; p=reject; p=none", "more than once"),
    ("v=DMARC1; p=reject; garbage", "malformed tag"),
    ("v=DMARC1; p=reject; sp=maybe", "sp=maybe"),
])
def test_other_malformed_tags_are_flagged_but_the_policy_stands(record, problem):
    rec = parse_dmarc(record)
    assert rec.valid and rec.policy == "reject" and rec.pct == 100
    assert any(problem in p and "ignored by receivers" in p for p in rec.problems)
    assert read_dmarc([[record]]).status == "present"


def test_missing_semicolon_between_report_tags():
    # Seen in the wild: rua and ruf run together, so both addresses are unusable but p=none still applies.
    rec = parse_dmarc("v=DMARC1; p=none; pct=100; rua=mailto:d@acme.example ruf=mailto:d@acme.example")
    assert rec.valid and rec.policy == "none" and rec.aggregate_reports == []
    assert any("missing ';'" in p for p in rec.problems)


def test_bad_p_with_valid_rua_is_read_as_none():
    rec = parse_dmarc("v=DMARC1; p=block; rua=mailto:r@acme.example")
    assert rec.valid and rec.policy == "none" and rec.subdomain_policy == "none"


def test_ignored_values_take_their_defaults():
    rec = parse_dmarc("v=DMARC1; p=reject; adkim=x; pct=abc; rua=mailto:r@acme.example")
    assert (rec.dkim_alignment, rec.pct) == ("relaxed", 100)
    assert rec.defaults_used == ["sp", "adkim", "aspf", "pct"]


def test_valid_records_with_weak_points_are_noted():
    assert "no usable rua" in parse_dmarc("v=DMARC1; p=none").problems[0]
    assert any("pct=25" in p for p in parse_dmarc("v=DMARC1; p=reject; pct=25; rua=mailto:r@x.example").problems)
    assert "unknown tag zz (ignored by receivers)" in parse_dmarc("v=DMARC1; p=none; rua=mailto:r@x.example; zz=1").problems


def test_finding_the_record():
    assert read_dmarc([[REJECT[:60], REJECT[60:]]]).status == "present"  # split TXT strings
    assert read_dmarc([["v=DMARC1; p=none"], ["v=DMARC1; p=reject"]]).status == "multiple"
    assert read_dmarc([["v=spf1 -all"]]).status == "missing"
    assert read_dmarc([]).status == "missing"
    assert read_dmarc([["v=DMARC1 p=reject"]]).status == "invalid"  # missing semicolon


def test_organizational_domain():
    assert organizational_domain("corporate.acme.example") == "acme.example"
    assert organizational_domain("acme.co.uk") == "acme.co.uk"
    assert organizational_domain("www.acme.com.mx") == "acme.com.mx"


# --- collection --------------------------------------------------------------------------------------------

def test_dmarc_lookup_is_stored_with_raw_answer_and_evidence(session_factory, store, acme):
    run, job = collect(session_factory, store, {"_dmarc.acme.example": [[REJECT]]})
    assert run.status == "succeeded" and job._resolver.calls == ["_dmarc.acme.example"]
    [obs] = observations(session_factory)
    assert (obs.status, obs.dmarc_policy, obs.dmarc_subdomain_policy, obs.dmarc_pct) == ("present", "reject", "quarantine", 100)
    assert (obs.dkim_alignment, obs.spf_alignment, obs.policy_source) == ("strict", "relaxed", "domain")
    assert obs.aggregate_report_uris == ["mailto:dmarc@acme.example"] and obs.tags["fo"] == "1"
    assert obs.evidence_version_id is not None and obs.verification_status == "observed"
    with session_factory() as s:
        assert s.get(DnsSecurityRecord, obs.dns_record_id).query_name == "_dmarc.acme.example"


@pytest.mark.parametrize("answer, status", [
    (TxtLookup("nxdomain", "fake-resolver", rcode="NXDOMAIN"), "missing"),  # no _dmarc name is "missing", not "no domain"
    (TxtLookup("no_records", "fake-resolver", rcode="NOERROR"), "missing"),
    ([["v=DMARC1; p=none"], ["v=DMARC1; p=reject"]], "multiple"),
    ([["v=DMARC1; p=maybe"]], "invalid"),  # no usable p and no rua to fall back on
])
def test_each_outcome_is_recorded_distinctly(session_factory, store, acme, answer, status):
    collect(session_factory, store, {"_dmarc.acme.example": answer})
    [obs] = observations(session_factory)
    assert obs.status == status and obs.dmarc_policy is None and obs.evidence_version_id is not None


def test_lookup_failure_is_not_absence(session_factory, store, acme):
    collect(session_factory, store, {"_dmarc.acme.example": TxtLookup("lookup_failed", "fake-resolver", rcode="TIMEOUT")})
    [obs] = observations(session_factory)
    assert (obs.status, obs.evidence_version_id) == ("lookup_failed", None)
    run = run_validation(session_factory)
    with session_factory() as s:
        hits = set(s.scalars(select(ValidationResult.rule).where(
            ValidationResult.validation_run_id == run.id, ValidationResult.rows_failed > 0)))
    assert "dmarc_lookup_failed" in hits


def test_subdomain_without_a_record_inherits_the_organizational_policy(session_factory, store, acme):
    from cyber_risk_intelligence.domains import CompanyDomainsJob

    run_import(session_factory, store, CompanyDomainsJob(), csv_bytes(
        ["company_key", "domain", "role", "source_url"],
        ["acme", "corporate.acme.example", "corporate", "https://corporate.acme.example/"]), source_url="file:///d.csv")
    _, job = collect(session_factory, store, {
        "_dmarc.corporate.acme.example": TxtLookup("nxdomain", "fake-resolver", rcode="NXDOMAIN"),
        "_dmarc.acme.example": [[REJECT]]}, ["acme", "corporate.acme.example"])
    assert job._resolver.calls == ["_dmarc.corporate.acme.example", "_dmarc.acme.example"]
    [obs] = observations(session_factory)
    assert (obs.status, obs.policy_source, obs.dmarc_policy) == ("present", "organizational_domain", "reject")
    with session_factory() as s:
        assert s.get(DnsSecurityRecord, obs.policy_dns_record_id).query_name == "_dmarc.acme.example"
        assert s.get(DnsSecurityRecord, obs.dns_record_id).query_name == "_dmarc.corporate.acme.example"


def test_repeat_lookup_reuses_the_stored_answer_and_keeps_history(session_factory, store, acme):
    collect(session_factory, store, {"_dmarc.acme.example": [["v=DMARC1; p=none; rua=mailto:r@acme.example"]]})
    second, _ = collect(session_factory, store, {"_dmarc.acme.example": [["v=DMARC1; p=none; rua=mailto:r@acme.example"]]})
    assert second.rows_unchanged == 1
    third, _ = collect(session_factory, store, {"_dmarc.acme.example": [[REJECT]]})
    assert third.rows_inserted == 1
    assert [o.dmarc_policy for o in observations(session_factory)] == ["none", "none", "reject"]
    with session_factory() as s:
        assert s.execute(text("SELECT dmarc_policy FROM latest_dmarc_observations")).scalars().all() == ["reject"]


def test_spf_and_dmarc_for_the_same_domain_do_not_mix(session_factory, store, acme):
    from cyber_risk_intelligence.email_security import SpfJob

    answers = {"acme.example": [["v=spf1 -all"]], "_dmarc.acme.example": [[REJECT]]}
    run_import(session_factory, store, SpfJob(store, FakeResolver(answers)),
               csv_bytes(["company_key", "domain"], ["acme", "acme.example"]), source_url="file:///t.csv")
    collect(session_factory, store, answers)
    second, _ = collect(session_factory, store, answers)
    assert second.rows_unchanged == 1  # compared with the last _dmarc lookup, not the SPF one
    with session_factory() as s:
        controls = sorted(s.execute(text("SELECT control FROM email_security_observations")).scalars())
    assert controls == ["dmarc", "dmarc", "spf"]
