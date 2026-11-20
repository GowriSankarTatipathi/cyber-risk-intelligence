"""Issue 2.1: published backup frequencies."""

import csv
import io

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from cyber_risk_intelligence.backup.__main__ import derive
from cyber_risk_intelligence.backup.parse import read_backup_statement
from cyber_risk_intelligence.collectors.trust_center import TrustCenterJob
from cyber_risk_intelligence.collectors.trust_center.fetch import FetchResult
from cyber_risk_intelligence.evidence import LocalStore
from cyber_risk_intelligence.ingest import run_import
from cyber_risk_intelligence.models import ValidationResult
from cyber_risk_intelligence.models.backup import BackupPolicyClaim
from cyber_risk_intelligence.quality import run_validation

from . import factories as f

PAGE_URL = "https://trust.acme.example/resilience"
PAGE = b"""<html><head><title>Acme Resilience</title></head><body><main>
<h2>Backups</h2>
<p>Customer data is backed up daily and backups are retained for 35 days.</p>
<p>We continuously replicate production databases to a second region.</p>
<p>Backups are encrypted at rest.</p>
<p>Our disaster recovery plan is tested annually.</p>
<p>With Acme Vault you can schedule backups hourly.</p>
</main></body></html>"""
QUIET_URL = "https://trust.quiet.example/security"
QUIET = b"""<html><body><main><p>All production systems are backed up to a separate location.</p></main></body></html>"""


# --- parsing --------------------------------------------------------------------------------------------

def freqs(sentence):
    st = read_backup_statement(sentence)
    return [(x.frequency_class, x.interval_minutes) for x in st.frequencies]


def test_daily_and_continuous_keep_their_meanings():
    assert freqs("Customer data is backed up daily.") == [("daily", 1440)]
    assert freqs("Customer data is backed up nightly.") == [("daily", 1440)]
    assert freqs("We continuously replicate production databases.") == [("continuous", None)]
    assert freqs("Backups are taken in real time.") == [("continuous", None)]


def test_intervals():
    assert freqs("Database snapshots are taken every 15 minutes.") == [("sub_hourly", 15)]
    assert freqs("Backups run hourly.") == [("hourly", 60)]
    assert freqs("Incremental backups run every 4 hours and full backups weekly.") == [
        ("sub_daily", 240), ("weekly", 10080)]
    assert freqs("Backups are taken twice a day.") == [("sub_daily", None)]
    assert freqs("Archives are backed up monthly.") == [("monthly", 43200)]


def test_unstated_frequency_stays_unknown():
    st = read_backup_statement("All production systems are backed up to a separate location.")
    assert st is not None and st.frequencies == []


def test_test_and_review_schedules_are_not_backup_frequencies():
    assert read_backup_statement("Our disaster recovery plan is tested annually.") is None
    assert freqs("Data is backed up nightly and restore tests are performed quarterly.") == [("daily", 1440)]
    assert freqs("Backups are tested monthly.") == []


def test_scope_keeps_product_features_and_customer_duties_apart():
    assert read_backup_statement("We back up customer data daily.").scope == "own_practice"
    assert read_backup_statement("You can schedule backups hourly.").scope == "product_capability"
    assert read_backup_statement("Customers are responsible for backing up their own data.").scope == \
        "customer_responsibility"


def test_details_are_read():
    st = read_backup_statement("Full and incremental backups of customer databases are retained for 35 days.")
    assert st.methods == ["full", "incremental"] and st.retention_days == 35
    assert st.covered_system == "customer databases"
    st = read_backup_statement("Our RPO is 1 hour and our RTO is 4 hours.")
    assert (st.rpo_minutes, st.rto_minutes) == (60, 240)


# --- database -------------------------------------------------------------------------------------------

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
def companies(session_factory):
    with session_factory() as s:
        f.company(s, "acme", "Acme")
        f.company(s, "quiet", "Quiet")
        s.commit()


def collect(sf, store):
    pages = {PAGE_URL: ("text/html", PAGE), QUIET_URL: ("text/html", QUIET)}
    job = TrustCenterJob(store, FakeFetcher(pages))
    t = targets(["acme", PAGE_URL, "trust_center"], ["quiet", QUIET_URL, "trust_center"])
    return run_import(sf, store, job, t, source_url="file:///targets.csv")


def rows(sf):
    with sf() as s:
        return s.scalars(select(BackupPolicyClaim).order_by(BackupPolicyClaim.id)).all()


def by_quote(sf):
    return {(r.quote, r.frequency_class): r for r in rows(sf)}


def test_collection_records_backup_schedules(session_factory, store, companies):
    assert collect(session_factory, store).status == "succeeded"
    found = by_quote(session_factory)
    daily = found["Customer data is backed up daily and backups are retained for 35 days.", "daily"]
    assert (daily.interval_minutes, daily.retention_days, daily.scope) == (1440, 35, "own_practice")
    assert daily.source_ref == PAGE_URL and daily.evidence_version_id and daily.claim_id and daily.observed_at
    assert daily.verification_status == "claimed"
    cont = found["We continuously replicate production databases to a second region.", "continuous"]
    assert cont.interval_minutes is None and cont.methods == ["replication"]
    assert found["Backups are encrypted at rest.", None].frequency_phrase is None  # unknown, not guessed
    assert found["With Acme Vault you can schedule backups hourly.", "hourly"].scope == "product_capability"
    assert not any("disaster recovery plan" in q for q, _ in found)
    with session_factory() as s:
        view = {(r.company_id, r.scope, r.frequency_class): r for r in s.execute(text(
            "SELECT * FROM company_backup_frequencies")).all()}
    acme_own = {k[2] for k in view if k[1] == "own_practice" and k[0] == daily.company_id}
    assert acme_own == {"daily", "continuous", None}  # product feature is not Acme's own practice


def test_repeat_collection_and_derive_do_not_duplicate(session_factory, store, companies):
    collect(session_factory, store)
    n = len(rows(session_factory))
    collect(session_factory, store)
    assert derive(session_factory) == 0
    assert len(rows(session_factory)) == n
    with session_factory() as s:
        s.execute(text("DELETE FROM backup_policy_claims"))
        s.commit()
    assert derive(session_factory) == n  # backfill from earlier 1.1 claims
    assert derive(session_factory) == 0


def test_unstated_frequency_is_flagged(session_factory, store, companies):
    collect(session_factory, store)
    run_validation(session_factory)
    with session_factory() as s:
        res = s.scalars(select(ValidationResult).where(ValidationResult.rule == "backup_frequency_not_stated")).one()
    assert res.rows_failed == 1  # Quiet mentions backups without a schedule; Acme states one


def test_database_refuses_contradictions(session_factory, store, companies):
    collect(session_factory, store)
    bad = ["UPDATE backup_policy_claims SET interval_minutes = 1440 WHERE frequency_class = 'continuous'",
           "UPDATE backup_policy_claims SET frequency_class = 'daily' WHERE frequency_class IS NULL",
           "UPDATE backup_policy_claims SET verification_status = 'verified'",
           """UPDATE backup_policy_claims SET methods = '["mirroring"]'"""]
    for sql in bad:
        with session_factory() as s, pytest.raises(IntegrityError):
            s.execute(text(sql))
            s.flush()
