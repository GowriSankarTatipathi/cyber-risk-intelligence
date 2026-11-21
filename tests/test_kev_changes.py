"""KEV change events (issue 12.1). Synthetic catalogs; nothing is contacted."""
# ruff: noqa: F811 - pytest fixtures imported from test_exposure

from sqlalchemy import func, select

from cyber_risk_intelligence.ingest import run_import
from cyber_risk_intelligence.models import KevChangeEvent, KevEntry
from cyber_risk_intelligence.vulnerabilities.__main__ import kev_changes
from cyber_risk_intelligence.vulnerabilities.kev import KevJob, record_removals

from .test_exposure import store  # noqa: F401 - fixtures
from .test_kev import catalog, entry


def load(sf, store, content):
    job = KevJob()
    run = run_import(sf, store, job, content, source_url="https://www.cisa.gov/kev.json")
    with sf() as s:
        removed = record_removals(s, run.id)
    return run, job, removed


def events(sf, **where):
    with sf() as s:
        q = select(KevChangeEvent).order_by(KevChangeEvent.id)
        for k, v in where.items():
            q = q.where(getattr(KevChangeEvent, k) == v)
        return s.scalars(q).all()


def test_first_catalog_is_baseline_and_an_unchanged_catalog_adds_nothing(session_factory, store):
    first = catalog(entry(), entry("CVE-2025-0002"))
    _, job, _ = load(session_factory, store, first)
    assert job._baseline and job.changes == {"added": 0, "updated": 0}
    assert [(e.cve_id, e.change_type, e.baseline) for e in events(session_factory)] == [
        ("CVE-2026-0001", "added", True), ("CVE-2025-0002", "added", True)]
    load(session_factory, store, first)  # same file again
    load(session_factory, store, catalog(entry(), entry("CVE-2025-0002"), version="2026.11.21",
                                         released="2026-11-21T17:00:00Z"))  # new release, same content
    assert len(events(session_factory)) == 2


def test_a_revised_required_action_is_one_traceable_update(session_factory, store):
    load(session_factory, store, catalog(entry()))
    revised = catalog(entry(requiredAction="Disconnect the device; patching is not possible."),
                      version="2026.11.21", released="2026-11-21T17:00:00Z")
    run, job, _ = load(session_factory, store, revised)
    assert job.changes["updated"] == 1
    (e,) = events(session_factory, change_type="updated")
    assert e.changed_fields == ["required_action"] and not e.baseline
    assert e.previous_values == {"required_action": "Apply updates per vendor instructions."}
    assert e.new_values == {"required_action": "Disconnect the device; patching is not possible."}
    assert e.evidence_version_id == run.input_evidence_version_id and e.ingestion_run_id == run.id
    with session_factory() as s:
        assert s.scalar(select(func.count()).select_from(KevEntry)) == 1  # not duplicated
    load(session_factory, store, revised)
    assert len(events(session_factory, change_type="updated")) == 1  # the same release again: no new event


def test_additions_removals_and_returns(session_factory, store, capsys):
    load(session_factory, store, catalog(entry(), entry("CVE-2025-0002")))
    _, job, removed = load(session_factory, store, catalog(entry(), entry("CVE-2026-0003", dateAdded="2026-11-21"),
                                                           version="2026.11.21", released="2026-11-21T17:00:00Z"))
    assert (job.changes["added"], removed) == (1, 1)
    assert [e.cve_id for e in events(session_factory, change_type="added", baseline=False)] == ["CVE-2026-0003"]
    assert [e.cve_id for e in events(session_factory, change_type="removed")] == ["CVE-2025-0002"]
    _, _, again = load(session_factory, store, catalog(entry(), entry("CVE-2026-0003", dateAdded="2026-11-21"),
                                                       version="2026.11.21", released="2026-11-21T17:00:00Z"))
    assert again == 0  # removal recorded once
    _, job, _ = load(session_factory, store, catalog(entry(), entry("CVE-2025-0002"), entry("CVE-2026-0003",
                                                     dateAdded="2026-11-21"),
                                                     version="2026.11.22", released="2026-11-22T17:00:00Z"))
    assert job.changes["added"] == 1  # back in the catalog
    kev_changes(session_factory)
    out = capsys.readouterr().out
    assert "CVE-2026-0003" in out and "removed" in out and "CVE-2025-0002" in out


def test_an_older_catalog_adds_no_events(session_factory, store):
    load(session_factory, store, catalog(entry(), version="2026.11.21", released="2026-11-21T17:00:00Z"))
    load(session_factory, store, catalog(entry(requiredAction="Old text"), version="2026.11.20",
                                         released="2026-11-20T17:00:00Z"))
    assert [e.change_type for e in events(session_factory)] == ["added"]
