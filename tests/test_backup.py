"""Issue 2.1: published backup frequencies."""

import csv
import io

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from cyber_risk_intelligence.backup.__main__ import derive
from cyber_risk_intelligence.backup.caiq import read_caiq
from cyber_risk_intelligence.backup.parse import read_backup_statement
from cyber_risk_intelligence.backup.star import CsaStarJob
from cyber_risk_intelligence.collectors.trust_center import TrustCenterJob
from cyber_risk_intelligence.collectors.trust_center.fetch import FetchResult
from cyber_risk_intelligence.evidence import LocalStore
from cyber_risk_intelligence.ingest import run_import
from cyber_risk_intelligence.models import ValidationResult
from cyber_risk_intelligence.models.backup import BackupPolicyClaim
from cyber_risk_intelligence.quality import run_validation

from . import factories as f
from .docmaker import make_xlsx

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


def test_wording_from_published_questionnaires():
    st = read_backup_statement("Full backups are performed, at least, every seven days direct to disk and are retained "
                               "for a minimum of fourteen (14) days, with differential backups taken every 24 hours.")
    assert [(x.frequency_class, x.interval_minutes) for x in st.frequencies] == [("weekly", 10080), ("daily", 1440)]
    assert st.retention_days == 14 and st.methods == ["full", "differential"]
    assert freqs("Backup data validation is part of the monthly disaster recovery test.") == []
    assert freqs("Backup activities can be monitored in real time.") == []
    assert freqs("Duo backs up data stores housing customer sensitive data at least daily.") == [("daily", 1440)]


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


# --- CSA STAR CAIQ self-assessments ---------------------------------------------------------------------

CAIQ_URL = "https://cloudsecurityalliance.org/star/registry/acme/services/acme-cloud/download/AbC123"
V4_HEADER = ["Question ID", "Question", "CSP CAIQ Answer", "SSRM Control Ownership",
             "CSP Implementation Description (Optional/Recommended)", "CSC Responsibilities (Optional/Recommended)"]
CAIQ_V4 = make_xlsx([
    ["Consensus Assessments Initiative Questionnaire v4.0.2"],
    V4_HEADER,
    ["BCR-08.1", "Are backups performed periodically?", "Yes", "Shared CSP and CSC",
     "Customer content is backed up daily and backups are retained for 30 days.", "Customers back up their own exports."],
    ["BCR-08.2", "Is the confidentiality, integrity, and availability of the backup ensured?", "Yes", "CSP-owned",
     "Backups are encrypted.", ""],
    ["BCR-08.3", "Can backups be restored appropriately for resiliency?", "NA", "CSP-owned", "", ""],
    ["BCR-09.1", "Is a disaster response plan established?", "Yes", "CSP-owned", "Tested annually.", ""],
    ["DSP-19.1", "Are physical data locations, including where data is backed up, documented?", "Yes",
     "CSP-owned", "Yes.", ""],
], sheet_name="CAIQv4.0.2")
CAIQ_V31 = make_xlsx([
    ["Control Group", "CGID", "Question ID", "Control Specification", "Consensus Assessment Questions",
     "Consensus Assessment Answers", "", "", "Notes"],
    ["", "", "", "", "", "Yes", "No", "Not Applicable", ""],
    ["BCR", "BCR-11", "BCR-11.4", "", "Do you have backup or redundancy mechanisms in place?", "", "x", "", ""],
], sheet_name="CAIQ")


def test_caiq_v4_backup_questions():
    found = {a.question_id: a for a in read_caiq(CAIQ_V4)}
    assert set(found) == {"BCR-08.1", "BCR-08.2", "BCR-08.3"}  # only business-continuity backup questions
    assert (found["BCR-08.1"].answer, found["BCR-08.3"].answer) == ("yes", "na")
    assert found["BCR-08.1"].ownership == "Shared CSP and CSC"
    assert found["BCR-08.1"].customer_part == "Customers back up their own exports."


def test_caiq_v31_marked_answers():
    (a,) = read_caiq(CAIQ_V31)
    assert (a.question_id, a.answer) == ("BCR-11.4", "no")


def test_not_a_caiq_gives_nothing():
    assert read_caiq(make_xlsx([["Name", "Value"], ["backups", "daily"]])) == []


class StarFetcher:
    def __init__(self, content):
        self.content, self.urls = content, []

    def fetch(self, url):
        self.urls.append(url)
        return FetchResult("captured", url, url, 200,
                           "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", self.content)


def star_csv(*rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["company_key", "service_name", "service_url", "caiq_url"])
    w.writerows(rows)
    return buf.getvalue().encode()


def import_star(sf, store, content=CAIQ_V4, url=CAIQ_URL):
    job = CsaStarJob(store, StarFetcher(content))
    return run_import(sf, store, job, star_csv(["acme", "Acme Cloud", "", url]), source_url="file:///star.csv")


def test_star_import_records_caiq_answers(session_factory, store, companies):
    assert import_star(session_factory, store).status == "succeeded"
    star = [r for r in rows(session_factory) if r.basis == "csa_star_caiq"]
    by_q = {(r.caiq_question_id, r.frequency_class): r for r in star}
    assert set(by_q) == {("BCR-08.1", "daily"), ("BCR-08.2", None)}  # NA answer gives no row
    daily = by_q["BCR-08.1", "daily"]
    assert (daily.interval_minutes, daily.retention_days, daily.scope) == (1440, 30, "own_practice")
    assert daily.source_ref == CAIQ_URL and daily.claim_id is None and daily.verification_status == "claimed"
    assert daily.service_name == "Acme Cloud" and daily.control_ownership == "Shared CSP and CSC"
    assert daily.quote.startswith("BCR-08.1 Are backups performed periodically? Answer: Yes.")
    with session_factory() as s:
        (src,) = s.execute(text("SELECT sources FROM company_backup_frequencies WHERE frequency_class = 'daily'")).one()
    assert src == "csa_star_caiq"
    assert import_star(session_factory, store).rows_unchanged == 1  # repeat import adds nothing


def test_star_no_answer_and_customer_owned(session_factory, store, companies):
    customer = make_xlsx([V4_HEADER, ["BCR-08.1", "Are backups performed periodically?", "Yes", "CSC-owned",
                                      "Customers schedule their own backups.", ""]])
    import_star(session_factory, store, CAIQ_V31)
    import_star(session_factory, store, customer, CAIQ_URL.replace("AbC123", "Xyz789"))
    star = {r.caiq_question_id: r for r in rows(session_factory) if r.basis == "csa_star_caiq"}
    assert star["BCR-11.4"].assertion == "negated" and star["BCR-11.4"].caiq_answer == "no"
    assert star["BCR-08.1"].scope == "customer_responsibility"  # the customer's job is not the provider's practice


def test_star_rejects_links_off_the_registry(session_factory, store, companies):
    run = import_star(session_factory, store, url="https://acme.example/caiq.xlsx")
    assert run.rows_rejected == 1
    assert not [r for r in rows(session_factory) if r.basis == "csa_star_caiq"]
