"""Acceptance tests for issue 27.7 (data-quality validation). Synthetic fixtures only.

Bad rows are injected by dropping the constraint that would normally reject them,
inside the test transaction (rolled back afterwards). This proves the suite
catches problems even when a constraint is missing or was bypassed.
"""

from datetime import UTC, date, datetime, timedelta

import pytest
from sqlalchemy import select, text

from cyber_risk_intelligence.evidence import LocalStore, link_evidence, record_evidence
from cyber_risk_intelligence.ingest import run_import
from cyber_risk_intelligence.ingest.seed_companies import SeedCompaniesJob
from cyber_risk_intelligence.models import (
    Company,
    CompanyAlias,
    EntityRelationship,
    EvidenceLink,
    IndexMembership,
    IngestionRun,
    ValidationFinding,
    ValidationResult,
)
from cyber_risk_intelligence.quality import CHECKS, Check, run_validation

from . import factories as f
from .test_ingestion import GOOD, URL, to_csv


@pytest.fixture
def store(tmp_path):
    return LocalStore(tmp_path)


def findings(sf, run, check):
    with sf() as s:
        return s.scalars(select(ValidationFinding).where(
            ValidationFinding.validation_run_id == run.id, ValidationFinding.check_name == check)).all()


def result(sf, run, check):
    with sf() as s:
        return s.scalar(select(ValidationResult).where(
            ValidationResult.validation_run_id == run.id, ValidationResult.rule == check))


def ddl(sf, *statements):
    with sf() as s:
        for stmt in statements:
            s.execute(text(stmt))
        s.commit()


def test_valid_synthetic_records_pass(session_factory, store):
    with session_factory() as s:
        c = f.company(s)
        e = f.entity(s, c, jurisdiction_country="US")
        sub = f.entity(s, c, "Acme Labs LLC")
        f.identifier(s, e, valid_from=date(2001, 1, 1))
        s.add(EntityRelationship(child_entity_id=sub.id, parent_entity_id=e.id, relationship_type="subsidiary_of",
                                 valid_from=date(2015, 3, 1), source_ref="synthetic fixture"))
        ev = record_evidence(s, store, source=f.source(s), source_url="https://example.com/10-k",
                             content=b"Acme Corp annual report", media_type="text/plain",
                             published_at=datetime(2024, 2, 1, tzinfo=UTC))
        link_evidence(s, ev, e)
        s.commit()
    run = run_validation(session_factory, store=store)
    assert run.status == "passed", [(x.check_name, x.message) for x in findings(session_factory, run, None) or []]
    assert (run.errors, run.warnings, run.checks_run) == (0, 0, len(CHECKS) + 1)
    r = result(session_factory, run, "duplicate_active_identifier")
    assert (r.rows_checked, r.rows_failed) == (1, 0)
    assert r.description  # every result documents what it checks


def test_unknown_values_are_valid_and_documented(session_factory):
    with session_factory() as s:
        e = f.entity(s, None, "Unlinked Holdings Ltd")  # group unknown; no country, no dates
        f.identifier(s, e, scheme="lei", value="INR2EJN1ERAN0W5ZP974", scope="GLEIF")
        s.commit()
    run = run_validation(session_factory)
    assert run.status == "passed"
    info = findings(session_factory, run, "unlinked_legal_entity")
    assert [x.severity for x in info] == ["info"]
    assert "unknown, not absent" in result(session_factory, run, "unlinked_legal_entity").description


def test_duplicate_identifiers_are_caught(session_factory):
    ddl(session_factory, "ALTER TABLE entity_identifiers DROP CONSTRAINT no_overlapping_identifier")
    with session_factory() as s:
        c = f.company(s)
        a, b = f.entity(s, c), f.entity(s, c, "Acme Corporation")
        i1 = f.identifier(s, a, value="789019")
        i2 = f.identifier(s, b, value="0000789019")  # same CIK once normalized
        s.commit()
    run = run_validation(session_factory)
    assert run.status == "failed"
    hits = findings(session_factory, run, "duplicate_active_identifier")
    assert {x.record_id for x in hits} == {i1.id, i2.id}
    assert all(x.table_name == "entity_identifiers" and "0000789019" in x.message for x in hits)
    assert result(session_factory, run, "duplicate_active_identifier").rows_failed == 2


def test_impossible_date_ranges_are_caught(session_factory):
    ddl(session_factory, "ALTER TABLE company_aliases DROP CONSTRAINT ck_company_aliases_valid_period")
    with session_factory() as s:
        c = f.company(s)
        bad = CompanyAlias(company_id=c.id, alias="Acme Old", normalized_alias="acme old", alias_type="former_name",
                           valid_from=date(2020, 1, 1), valid_to=date(2019, 1, 1), source_ref="fixture")
        s.add(bad)
        s.add(IndexMembership(company_id=c.id, index_name="S&P 500", source_ref="fixture",
                              observed_on=date.today() + timedelta(days=30)))
        s.commit()
    run = run_validation(session_factory)
    assert run.status == "failed"
    hits = findings(session_factory, run, "valid_period_order")
    assert [(x.table_name, x.record_id) for x in hits] == [("company_aliases", bad.id)]
    future = findings(session_factory, run, "date_in_future")
    assert [x.table_name for x in future] == ["index_memberships"]


def test_reversed_period_does_not_break_overlap_checks(session_factory):
    # The exclusion constraint itself refuses a reversed range, so drop both guards.
    ddl(session_factory,
        "ALTER TABLE entity_relationships DROP CONSTRAINT ck_entity_relationships_valid_period",
        "ALTER TABLE entity_relationships DROP CONSTRAINT no_overlapping_relationship")
    with session_factory() as s:
        c = f.company(s)
        p, ch = f.entity(s, c), f.entity(s, c, "Acme Labs LLC")
        bad = EntityRelationship(child_entity_id=ch.id, parent_entity_id=p.id, relationship_type="subsidiary_of",
                                 valid_from=date(2020, 1, 1), valid_to=date(2019, 1, 1), source_ref="fixture")
        s.add(bad)
        s.commit()
    run = run_validation(session_factory)
    assert run.status == "failed"  # not "error": every check still ran
    assert [x.record_id for x in findings(session_factory, run, "valid_period_order")] == [bad.id]
    assert findings(session_factory, run, "duplicate_active_relationship") == []


def test_orphan_links_are_caught(session_factory, store):
    ddl(session_factory, "ALTER TABLE evidence_links DROP CONSTRAINT fk_evidence_links_legal_entity_id_legal_entities")
    with session_factory() as s:
        ev = record_evidence(s, store, source=f.source(s), source_url="https://example.com/a",
                             content=b"page", media_type="text/plain")
        s.add(EvidenceLink(evidence_version_id=ev.id, legal_entity_id=987654321))
        s.commit()
    run = run_validation(session_factory)
    hits = findings(session_factory, run, "orphan_evidence_link")
    assert run.status == "failed" and len(hits) == 1
    assert "987654321" in hits[0].message


def test_not_valid_constraints_are_reported(session_factory):
    with session_factory() as s:
        f.company(s, "bad-key", "x")
        s.commit()
    ddl(session_factory, "ALTER TABLE companies ADD CONSTRAINT ck_companies_demo CHECK (length(display_name) > 3) NOT VALID")
    run = run_validation(session_factory)
    hits = findings(session_factory, run, "constraints_validated")
    assert run.status == "failed" and "ck_companies_demo" in hits[0].message


def test_verified_needs_evidence_and_sources_need_references(session_factory):
    with session_factory() as s:
        c = f.company(s)
        verified = f.entity(s, c, verification_status="verified")
        unsourced = f.entity(s, c, "Acme Labs LLC", source_ref=None)
        s.commit()
    run = run_validation(session_factory)
    assert run.status == "failed"
    assert [x.record_id for x in findings(session_factory, run, "verified_without_evidence")] == [verified.id]
    missing = findings(session_factory, run, "missing_source_reference")
    assert [(x.record_id, x.severity) for x in missing] == [(unsourced.id, "warning")]


def test_failed_import_without_retry_is_flagged(session_factory):
    with session_factory() as s:
        src = f.source(s)
        failed = IngestionRun(job_name="demo", source_id=src.id, status="failed",
                              finished_at=datetime.now(UTC), error_message="HTTP 503")
        s.add(failed)
        s.commit()
    run = run_validation(session_factory)
    assert run.status == "warnings"
    assert [x.record_id for x in findings(session_factory, run, "failed_ingestion_not_retried")] == [failed.id]


def test_repeated_ingestion_keeps_counts_and_evidence_integrity(session_factory, store):
    job = SeedCompaniesJob()
    run_import(session_factory, store, job, to_csv(GOOD), source_url=URL)
    first = run_validation(session_factory, store=store)
    run_import(session_factory, store, job, to_csv(GOOD), source_url=URL)
    second = run_validation(session_factory, store=store)
    assert first.status == second.status == "passed"
    for check in ("orphan_evidence_link", "duplicate_active_identifier", "evidence_bytes_integrity"):
        a, b = result(session_factory, first, check), result(session_factory, second, check)
        assert (a.rows_checked, a.rows_failed) == (b.rows_checked, b.rows_failed)
    with session_factory() as s:
        assert len(s.scalars(select(Company)).all()) == 3

    # Tampering with stored evidence is detected.
    path = next(p for p in store.root.rglob("*") if p.is_file())
    path.write_bytes(b"tampered")
    third = run_validation(session_factory, store=store)
    assert third.status == "failed"
    assert "SHA-256" in findings(session_factory, third, "evidence_bytes_integrity")[0].message


def test_a_broken_check_is_recorded_not_fatal(session_factory):
    broken = Check("broken", "error", "always fails to run", "SELECT 1", "SELECT * FROM no_such_table")
    run = run_validation(session_factory, checks=(*CHECKS[:2], broken))
    assert run.status == "error"
    hit = findings(session_factory, run, "broken")[0]
    assert hit.table_name == "(check)" and "no_such_table" in hit.message
    assert result(session_factory, run, "valid_period_order") is not None  # other checks still ran
