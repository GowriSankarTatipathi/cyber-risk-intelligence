"""Acceptance tests for issue 17.8 (ingestion and data quality). Synthetic fixtures only."""

import csv
import io

import pytest
from sqlalchemy import func, select

from cyber_risk_intelligence.evidence import LocalStore
from cyber_risk_intelligence.ingest import IngestionFailed, TransientError, retry_import, run_import
from cyber_risk_intelligence.ingest.seed_companies import SeedCompaniesJob
from cyber_risk_intelligence.models import (
    Company,
    CompanyAlias,
    DataVersion,
    EntityIdentifier,
    EvidenceLink,
    IndexMembership,
    IndustryClassification,
    IngestionCursor,
    IngestionError,
    IngestionRun,
    LegalEntity,
    ValidationResult,
)

HEADER = [
    "Project sector group (sheet)", "Company name", "Ticker", "Why we chose this company for the cyber-risk project",
    "Index memberships", "Source sector / industry classification", "Business sub-industry",
    "S&P 500", "Nasdaq-100", "Dow Jones IA", "Stock exchange (SEC metadata)", "SEC issuer name",
    "Current issuer CIK", "Membership check date",
]


def row(name, ticker, cik, *, issuer=None, exchange="NYSE", sp="Yes", ndx="No", dow="No",
        cls="Industrials (GICS)", sub="Widgets", group="Industrials", why="Synthetic test company"):
    listed = "; ".join(n for n, f in (("S&P 500", sp), ("Nasdaq-100", ndx), ("Dow Jones Industrial Average", dow)) if f == "Yes")
    return [group, name, ticker, why, listed, cls, sub, sp, ndx, dow, exchange, issuer or name.upper() + " INC",
            cik, "2026-11-18 12:00:00"]


def to_csv(rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(HEADER)
    w.writerows(rows)
    return buf.getvalue().encode()


GOOD = [
    row("Alpha Widgets", "ALPW", "0000000101", ndx="Yes", exchange="Nasdaq", cls="Information Technology (GICS)"),
    row("Beta Tools", "BETT", "102", dow="Yes"),
    row("Gamma Health", "GMH", "0000000103", cls="Health Care (ICB)"),
]
URL = "file:///fixtures/seed.csv"


@pytest.fixture
def store(tmp_path):
    return LocalStore(tmp_path)


@pytest.fixture
def job():
    return SeedCompaniesJob()


def count(sf, model):
    with sf() as s:
        return s.scalar(select(func.count()).select_from(model))


def test_import_creates_linked_records_with_evidence(session_factory, store, job):
    run = run_import(session_factory, store, job, to_csv(GOOD), source_url=URL)
    assert (run.status, run.rows_seen, run.rows_inserted, run.rows_rejected) == ("succeeded", 3, 3, 0)
    with session_factory() as s:
        beta = s.scalar(select(Company).where(Company.company_key == "beta-tools"))
        entity = s.scalar(select(LegalEntity).where(LegalEntity.company_id == beta.id))
        ids = {(i.scheme, i.issuer_scope, i.normalized_value) for i in entity.identifiers}
        assert ids == {("sec_cik", "US-SEC", "0000000102"), ("ticker", "NYSE", "BETT")}
        assert entity.verification_status == "unverified"  # a compiled list is not verification
        idx = s.scalars(select(IndexMembership.index_name).where(IndexMembership.company_id == beta.id)).all()
        assert sorted(idx) == ["Dow Jones Industrial Average", "S&P 500"]  # "No" is not stored as a fact
        systems = s.scalars(select(IndustryClassification.system).where(
            IndustryClassification.company_id == s.scalar(select(Company.id).where(Company.company_key == "gamma-health")))).all()
        assert sorted(systems) == ["ICB", "ICB", "project_group"]
        # Every company and entity cites the stored input, with its row number.
        links = s.scalars(select(EvidenceLink).where(EvidenceLink.company_id == beta.id)).all()
        assert [l.locator for l in links] == ["row 2"]
        assert links[0].evidence_version_id == run.input_evidence_version_id


def test_repeating_the_same_import_does_not_duplicate(session_factory, store, job):
    first = run_import(session_factory, store, job, to_csv(GOOD), source_url=URL)
    totals = {m: count(session_factory, m) for m in (Company, LegalEntity, EntityIdentifier, CompanyAlias,
                                                     IndustryClassification, IndexMembership, EvidenceLink)}
    second = run_import(session_factory, store, job, to_csv(GOOD), source_url=URL)
    assert (second.status, second.rows_unchanged, second.rows_inserted) == ("succeeded", 3, 0)
    assert {m: count(session_factory, m) for m in totals} == totals
    assert second.data_version_id == first.data_version_id
    assert count(session_factory, DataVersion) == 1


def test_changed_input_gets_a_new_data_version_and_updates(session_factory, store, job):
    run_import(session_factory, store, job, to_csv(GOOD), source_url=URL)
    changed = [row("Alpha Widgets", "ALPW", "101", issuer="ALPHA WIDGETS HOLDINGS INC", ndx="Yes",
                   exchange="Nasdaq", cls="Information Technology (GICS)"), *GOOD[1:]]
    run = run_import(session_factory, store, job, to_csv(changed), source_url=URL)
    assert (run.rows_updated, run.rows_unchanged) == (1, 2)
    with session_factory() as s:
        assert sorted(s.scalars(select(DataVersion.version)).all()) == [1, 2]
        aliases = s.scalars(select(CompanyAlias.alias_type).where(CompanyAlias.alias == "ALPHA WIDGETS INC")).all()
        assert sorted(aliases) == ["former_name", "legal_name"]  # history kept


def test_invalid_rows_are_rejected_with_reasons(session_factory, store, job):
    bad = [
        *GOOD,
        row("No Ticker Co", "", "0000000104"),
        row("Bad Cik Co", "BCC", "12AB"),
        row("Duplicate Beta", "DUPB", "0000000102"),
        row("Odd Exchange", "ODD", "0000000106", exchange="LSE"),
        row("Ticker Thief", "BETT", "0000000107"),
    ]
    run = run_import(session_factory, store, job, to_csv(bad), source_url=URL)
    assert (run.status, run.rows_seen, run.rows_inserted, run.rows_rejected) == ("partial", 8, 3, 5)
    with session_factory() as s:
        errs = {(e.row_number, e.code) for e in s.scalars(select(IngestionError).where(IngestionError.run_id == run.id))}
        assert errs == {
            (4, "ticker_required"), (4, "ticker_valid"),
            (5, "cik_valid"),
            (6, "duplicate_in_input"),
            (7, "exchange_known"),
            (8, "identifier_conflict"),
        }
        raw = s.scalar(select(IngestionError.raw_row).where(IngestionError.run_id == run.id, IngestionError.row_number == 5))
        assert raw["Company name"] == "Bad Cik Co"
        vr = {v.rule: (v.rows_checked, v.rows_failed) for v in
              s.scalars(select(ValidationResult).where(ValidationResult.run_id == run.id))}
        assert vr["cik_valid"] == (7, 1)  # the in-file duplicate is rejected before validation
        assert s.scalar(select(func.count()).select_from(Company).where(Company.company_key == "ticker-thief")) == 0


def test_warnings_are_recorded_but_row_is_kept(session_factory, store, job):
    odd = row("Delta Corp", "DLT", "0000000108", cls="Industrials")  # no (GICS) suffix
    run = run_import(session_factory, store, job, to_csv([odd]), source_url=URL)
    assert (run.status, run.rows_inserted) == ("succeeded", 1)
    with session_factory() as s:
        vr = s.scalar(select(ValidationResult).where(ValidationResult.run_id == run.id,
                                                    ValidationResult.rule == "classification_parsable"))
        assert (vr.severity, vr.rows_failed) == ("warning", 1)


class FlakyJob(SeedCompaniesJob):
    """Fails like a rate-limited source when it reaches ``fail_at``, once."""

    def __init__(self, fail_at):
        self.fail_at, self.failed = fail_at, False

    def write(self, ctx):
        if ctx.row.number == self.fail_at and not self.failed:
            self.failed = True
            raise TransientError("HTTP 429 Too Many Requests from source")
        return super().write(ctx)


def test_partial_failure_is_recorded_and_safely_retried(session_factory, store):
    job = FlakyJob(fail_at=3)
    content = to_csv(GOOD + [row("Epsilon Energy", "EPS", "0000000109", cls="Energy (GICS)")])
    with pytest.raises(IngestionFailed) as err:
        run_import(session_factory, store, job, content, source_url=URL, batch_size=2)
    with session_factory() as s:
        failed = s.get(IngestionRun, err.value.run_id)
        assert failed.status == "failed"
        assert "429" in failed.error_message
        assert failed.last_committed_row == 2  # first batch is kept
        assert failed.finished_at is not None
        assert s.scalar(select(IngestionError.code).where(IngestionError.run_id == failed.id)) == "TransientError"
    assert count(session_factory, Company) == 2

    retry = retry_import(session_factory, store, job, failed.id, batch_size=2)
    assert (retry.status, retry.retry_of_run_id, retry.resumed_from_row) == ("succeeded", failed.id, 2)
    assert (retry.rows_seen, retry.rows_inserted) == (2, 2)
    assert count(session_factory, Company) == 4

    # Retrying again from the beginning is still safe.
    again = retry_import(session_factory, store, job, retry.id)
    assert (again.rows_unchanged, again.rows_inserted) == (4, 0)
    assert count(session_factory, Company) == 4
    with session_factory() as s:
        cur = s.scalar(select(IngestionCursor).where(IngestionCursor.job_name == "seed_companies"))
        assert cur.last_run_id == again.id and cur.cursor["data_version"] == 1


def test_unreadable_file_fails_the_run(session_factory, store, job):
    with pytest.raises(IngestionFailed) as err:
        run_import(session_factory, store, job, b"just,some,columns\n1,2,3\n", source_url=URL)
    with session_factory() as s:
        run = s.get(IngestionRun, err.value.run_id)
        assert run.status == "failed" and "Company name" in run.error_message
        assert run.input_evidence_version_id is not None  # the raw input is still preserved


def test_secrets_in_rejected_rows_are_not_logged(session_factory, store, job):
    leaky = row("Leaky Co", "", "0000000110", why="debug: password=Hunter2Hunter2")
    content = to_csv([leaky])
    with pytest.raises(IngestionFailed):
        # The whole input is refused by the evidence store before anything is written.
        run_import(session_factory, store, job, content, source_url=URL)
    with session_factory() as s:
        assert s.scalar(select(func.count()).select_from(Company)) == 0
        for e in s.scalars(select(IngestionError)):
            assert "Hunter2" not in e.message and e.raw_row is None
