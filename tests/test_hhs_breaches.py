"""HHS OCR healthcare breach reports (issue 3.3). Synthetic CSVs and a mocked portal; nothing is contacted."""
# ruff: noqa: F811 - pytest fixtures imported from test_exposure

import csv
import io

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from cyber_risk_intelligence.evidence import read_evidence
from cyber_risk_intelligence.incidents import (
    HhsBreachJob,
    HhsClient,
    HhsUnavailable,
    match_candidates,
    review_candidate,
)
from cyber_risk_intelligence.incidents.__main__ import summary
from cyber_risk_intelligence.ingest import run_import
from cyber_risk_intelligence.ingest.framework import IngestionFailed
from cyber_risk_intelligence.models import (
    EvidenceVersion,
    HealthcareBreachCompanyCandidate,
    HealthcareBreachRecord,
    IngestionError,
)

from . import factories as f
from .test_exposure import store  # noqa: F401 - fixture

# The real export names two columns by internal JSF ids, which is why the job maps columns by position.
HEADER = ["Name of Covered Entity", "State", "Covered Entity Type", "Individuals Affected",
          "UIPanel@1a2b3c", "Type of Breach", "Location of Breached Information", "UIPanel@4d5e6f",
          "Web Description"]


def report(name="Acme Health Plan", state="TX", people="12,345", submitted="03/15/2026",
           kind="Hacking/IT Incident", location="Network Server, Email", ba="No", desc=""):
    return [name, state, "Health Plan", people, submitted, kind, location, ba, desc]


def hhs_csv(*rows):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(HEADER)
    w.writerows(rows)
    return out.getvalue().encode()


def load(sf, store, content, which="investigation"):
    job = HhsBreachJob(which)
    run = run_import(sf, store, job, content, source_url="https://ocrportal.hhs.gov/ocr/breach/breach_report_hip.jsf")
    return run, job


def test_reports_are_stored_with_evidence_and_a_repeat_changes_nothing(session_factory, store):
    content = hhs_csv(report(), report("Valley Clinic", "ca", "", "11/02/2025", "Theft", "Laptop", "Yes"))
    run, _ = load(session_factory, store, content)
    assert (run.status, run.rows_inserted) == ("succeeded", 2)
    with session_factory() as s:
        r = s.scalar(select(HealthcareBreachRecord).where(HealthcareBreachRecord.entity_name == "Acme Health Plan"))
        assert (r.state, r.individuals_affected, str(r.submitted_on)) == ("TX", 12345, "2026-03-15")
        assert r.breach_types == ["Hacking/IT Incident"] and r.locations == ["Email", "Network Server"]
        assert (r.business_associate_present, r.list_status, r.same_day_seq, r.ambiguous_identity) == \
            (False, "under_investigation", 1, False)
        assert r.web_description is None and r.revisions is None
        assert r.evidence_version_id == run.input_evidence_version_id
        assert read_evidence(s, store, s.get(EvidenceVersion, r.evidence_version_id)) == content
        v = s.scalar(select(HealthcareBreachRecord).where(HealthcareBreachRecord.entity_name == "Valley Clinic"))
        assert (v.state, v.individuals_affected, v.business_associate_present) == ("CA", None, True)  # blank = unknown

    again, _ = load(session_factory, store, content)
    assert (again.rows_unchanged, again.rows_inserted, again.rows_updated) == (2, 0, 0)
    with session_factory() as s:
        assert s.scalar(select(func.count()).select_from(HealthcareBreachRecord)) == 2


def test_an_updated_count_or_list_is_a_revision_not_a_new_incident(session_factory, store):
    first, _ = load(session_factory, store, hhs_csv(report()))
    later, job = load(session_factory, store, hhs_csv(report(people="98,765", desc="Ransomware attack.")), "archive")
    assert (later.rows_updated, later.rows_inserted) == (1, 0)
    assert job.changes == {"individuals_affected": 1, "web_description": 1, "list_status": 1}
    with session_factory() as s:
        assert s.scalar(select(func.count()).select_from(HealthcareBreachRecord)) == 1
        r = s.scalar(select(HealthcareBreachRecord))
        assert (r.individuals_affected, r.list_status, r.web_description) == (98765, "archived", "Ransomware attack.")
        assert (r.first_seen_run_id, r.last_seen_run_id) == (first.id, later.id)
        assert r.evidence_version_id == later.input_evidence_version_id
        (rev,) = r.revisions
        assert rev["individuals_affected"] == 12345 and rev["list_status"] == "under_investigation"
        assert rev["web_description"] is None and rev["evidence_version_id"] == first.input_evidence_version_id
        assert "state" not in rev  # only the fields that changed


def test_reports_sharing_entity_state_and_date_are_kept_apart_and_flagged(session_factory, store):
    run, _ = load(session_factory, store, hhs_csv(report(people="600"), report(people="900"),
                                                  report(submitted="03/16/2026")))
    assert run.rows_inserted == 3
    with session_factory() as s:
        rows = s.scalars(select(HealthcareBreachRecord).order_by(HealthcareBreachRecord.id)).all()
        assert [(r.same_day_seq, r.ambiguous_identity, r.individuals_affected) for r in rows] == \
            [(1, True, 600), (2, True, 900), (1, False, 12345)]
        assert rows[0].incident_key.endswith("|TX|2026-03-15|1") and rows[1].incident_key.endswith("|2")


def test_bad_rows_are_rejected_or_kept_as_unknown(session_factory, store):
    run, _ = load(session_factory, store, hhs_csv(report(), report("No Date Clinic", submitted="2026-03-15"),
                                                  report("", submitted="01/01/2026"),
                                                  report("Odd Count Clinic", people="about 500")))
    assert (run.rows_inserted, run.rows_rejected) == (2, 2)
    with session_factory() as s:
        rules = {e.code for e in s.scalars(select(IngestionError).where(IngestionError.run_id == run.id))}
        assert {"submitted_on_valid", "entity_name_required"} <= rules
        odd = s.scalar(select(HealthcareBreachRecord).where(HealthcareBreachRecord.entity_name == "Odd Count Clinic"))
        assert odd.individuals_affected is None  # not a count = unknown, never guessed


def test_a_file_that_is_not_the_hhs_export_fails(session_factory, store):
    with pytest.raises(IngestionFailed):
        load(session_factory, store, b"name,domain\nAcme,acme.example\n")
    with pytest.raises(ValueError):
        HhsBreachJob("everything")


def test_name_matches_are_unverified_candidates_until_a_source_confirms(session_factory, store):
    with session_factory() as s:
        f.company(s, "acme", "Acme")
        f.company(s, "beta-health", "Beta Health")
        s.commit()
    load(session_factory, store, hhs_csv(
        report("Acme"), report("Acme Corporation Health Plan", submitted="01/10/2026"),
        report("Acme Valley Clinic", submitted="02/10/2026"),  # one-word name + an ordinary word: no match
        report("Beta Health Partners of Ohio", "OH", submitted="02/11/2026")))
    with session_factory() as s:
        assert match_candidates(s) == 3
        assert match_candidates(s) == 0  # idempotent
        found = {(c.matched_name, c.match_basis, c.status) for c in s.scalars(select(HealthcareBreachCompanyCandidate))}
        assert found == {("acme", "exact_name", "unverified"), ("acme", "name_prefix", "unverified"),
                         ("beta health", "name_prefix", "unverified")}
        cand = s.scalar(select(HealthcareBreachCompanyCandidate).where(
            HealthcareBreachCompanyCandidate.match_basis == "exact_name"))
        with pytest.raises(ValueError, match="source"):
            review_candidate(s, cand.id, "confirmed", "")
        with pytest.raises(ValueError, match="status"):
            review_candidate(s, cand.id, "maybe", "https://example.org/press-release")
        c = review_candidate(s, cand.id, "confirmed", "https://example.org/press-release", "company notice")
        assert (c.status, c.review_source_url) == ("confirmed", "https://example.org/press-release")
        assert c.reviewed_at is not None

    with session_factory() as s:  # the database itself refuses a decision without a source
        other = s.scalar(select(HealthcareBreachCompanyCandidate).where(
            HealthcareBreachCompanyCandidate.status == "unverified"))
        other.status = "rejected"
        with pytest.raises(IntegrityError):
            s.commit()


def test_summary_reports_counts_and_candidates(session_factory, store, capsys):
    summary(session_factory)
    assert "No HHS breach reports imported yet" in capsys.readouterr().out
    with session_factory() as s:
        f.company(s, "acme", "Acme")
        s.commit()
    load(session_factory, store, hhs_csv(report("Acme"), report("Other Clinic", people="")))
    with session_factory() as s:
        match_candidates(s)
    summary(session_factory)
    out = capsys.readouterr().out
    assert "2 (2 under investigation, 0 archived)" in out and "12,345 people affected" in out
    assert "1 without a count" in out and "unverified" in out and "not when the breach happened" in out


FRONT = ("<form id=\"ocrForm\"><a href=\"#\" onclick=\"mojarra.jsfcljs(document.getElementById('ocrForm'),"
         "{'ocrForm:j_idt20':'ocrForm:j_idt20'},'');return false\"><span>View HIPAA Breach Reports</span></a>"
         "<input type=\"hidden\" name=\"javax.faces.ViewState\" value=\"vs1\"/></form>")
REPORT = ("<form id=\"ocrForm\"><a href=\"#\" onclick=\"mojarra.jsfcljs(document.getElementById('ocrForm'),"
          "{'ocrForm:j_idt31':'ocrForm:j_idt31'},'');return false\"><img src=\"xls.png\" title=\"Export as Excel\"/></a>"
          "<a href=\"#\" onclick=\"mojarra.jsfcljs(document.getElementById('ocrForm'),"
          "{'ocrForm:j_idt32':'ocrForm:j_idt32'},'');return false\"><img src=\"csv.png\" title=\"Export as CSV\"/></a>"
          "<input type=\"hidden\" name=\"javax.faces.ViewState\" value=\"vs2\"/></form>")


def portal(export_status=200, calls=None):
    def handler(request):
        if calls is not None:
            calls.append((request.method, request.url.path))
        if request.method == "GET":
            return httpx.Response(200, html=FRONT)
        if b"j_idt20" in request.content:
            return httpx.Response(200, html=REPORT)
        if b"j_idt32" in request.content:
            if export_status != 200:
                return httpx.Response(export_status, text="error")
            return httpx.Response(200, content=hhs_csv(report()), headers={"content-type": "text/csv"})
        return httpx.Response(200, content=b"PK", headers={"content-type": "application/vnd.ms-excel"})
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_client_posts_the_portal_form_and_picks_the_csv_export():
    calls = []
    url, content = HhsClient(portal(calls=calls), retries=1, backoff_s=0).download("investigation")
    assert content == hhs_csv(report()) and url.endswith("breach_frontpage.jsf")
    assert [m for m, _ in calls] == ["GET", "POST", "POST"]


def test_client_failure_is_reported_and_retried():
    calls = []
    with pytest.raises(HhsUnavailable, match="investigation list not downloaded"):
        HhsClient(portal(export_status=503, calls=calls), retries=2, backoff_s=0).download("investigation")
    assert len(calls) == 6  # two full attempts
