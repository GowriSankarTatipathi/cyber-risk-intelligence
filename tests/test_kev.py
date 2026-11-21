"""CISA KEV catalog (issue 5.1). Synthetic catalogs and a mocked download; nothing is contacted."""
# ruff: noqa: F811 - pytest fixtures imported from test_exposure

import json

import httpx
import pytest
from sqlalchemy import func, select, text

from cyber_risk_intelligence.ingest import run_import
from cyber_risk_intelligence.ingest.framework import IngestionFailed
from cyber_risk_intelligence.models import IngestionError, KevCatalogRelease, KevEntry
from cyber_risk_intelligence.vulnerabilities import KevClient, KevJob, KevUnavailable
from cyber_risk_intelligence.vulnerabilities.__main__ import kev_summary

from .test_exposure import DB, DNS, MX, acme, collect, store  # noqa: F401 - fixtures


def entry(cve="CVE-2026-0001", **kw):
    e = {"cveID": cve, "vendorProject": "Microsoft", "product": "IIS", "vulnerabilityName": "IIS RCE",
         "dateAdded": "2026-11-01", "shortDescription": "Remote code execution.",
         "requiredAction": "Apply updates per vendor instructions.", "dueDate": "2026-11-22",
         "knownRansomwareCampaignUse": "Known", "notes": "https://example.test/advisory", "cwes": ["CWE-787"]}
    e.update(kw)
    return {k: v for k, v in e.items() if v is not None}


def catalog(*entries, version="2026.11.20", released="2026-11-20T17:48:39.1516Z"):
    return json.dumps({"title": "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion": version,
                       "dateReleased": released, "count": len(entries), "vulnerabilities": list(entries)}).encode()


def load(sf, store, content):
    return run_import(sf, store, KevJob(), content, source_url="https://www.cisa.gov/kev.json")


def test_import_is_traceable_and_a_repeat_changes_nothing(session_factory, store):
    content = catalog(entry(), entry("CVE-2025-12345", vendorProject="Fortinet", product="FortiOS", dueDate=None,
                                     knownRansomwareCampaignUse="Unknown", cwes=None))
    run = load(session_factory, store, content)
    assert (run.status, run.rows_inserted) == ("succeeded", 2)
    with session_factory() as s:
        rel = s.scalars(select(KevCatalogRelease)).one()
        assert (rel.catalog_version, rel.entry_count, rel.date_released.year) == ("2026.11.20", 2, 2026)
        assert rel.evidence_version_id == run.input_evidence_version_id  # the stored snapshot of the whole file
        e = s.scalar(select(KevEntry).where(KevEntry.cve_id == "CVE-2026-0001"))
        assert (e.vendor_project, e.product, str(e.date_added), e.known_ransomware_use) == (
            "Microsoft", "IIS", "2026-11-01", "Known")
        assert e.required_action.startswith("Apply") and e.cwes == ["CWE-787"]
        assert e.first_seen_release_id == e.last_seen_release_id == rel.id
        assert e.evidence_version_id == rel.evidence_version_id
        fortinet = s.scalar(select(KevEntry).where(KevEntry.cve_id == "CVE-2025-12345"))
        assert fortinet.due_date is None and fortinet.cwes is None  # not given = unknown, not invented

    again = load(session_factory, store, content)
    assert (again.status, again.rows_unchanged, again.rows_inserted, again.rows_updated) == ("succeeded", 2, 0, 0)
    assert again.data_version_id == run.data_version_id
    with session_factory() as s:
        assert s.scalar(select(func.count()).select_from(KevCatalogRelease)) == 1
        assert s.scalar(select(func.count()).select_from(KevEntry)) == 2


def test_bad_entries_are_quarantined_with_errors(session_factory, store):
    run = load(session_factory, store, catalog(
        entry(), entry("CVE-26-1"), entry("CVE-2026-0002", vendorProject=""), entry("CVE-2026-0003", dateAdded=None),
        entry("CVE-2026-0004", requiredAction=" "), entry("CVE-2026-0005", dateAdded="20 Nov 2026"),
        entry("CVE-2026-0006", dueDate="soon", knownRansomwareCampaignUse="Maybe")))
    assert (run.status, run.rows_inserted, run.rows_rejected) == ("partial", 2, 5)
    with session_factory() as s:
        codes = sorted(s.scalars(select(IngestionError.code).where(IngestionError.run_id == run.id)))
        assert codes == ["cve_id_valid", "date_added_valid", "date_added_valid", "required_action_required",
                         "vendor_required"]
        odd = s.scalar(select(KevEntry).where(KevEntry.cve_id == "CVE-2026-0006"))
        assert odd.due_date is None and odd.known_ransomware_use is None  # warnings: kept, value left unknown
        assert s.scalar(select(func.count()).select_from(KevEntry)) == 2


def test_a_catalog_without_version_or_entries_fails_the_run(session_factory, store):
    with pytest.raises(IngestionFailed):
        load(session_factory, store, json.dumps({"vulnerabilities": [entry()]}).encode())
    with pytest.raises(IngestionFailed):
        load(session_factory, store, b'{"catalogVersion": "x", "dateReleased": "2026-11-20T00:00:00Z"}')
    with session_factory() as s:
        assert s.scalar(select(func.count()).select_from(KevEntry)) == 0


def test_new_release_updates_values_and_keeps_history(session_factory, store, capsys):
    first = load(session_factory, store, catalog(entry(), entry("CVE-2024-0007")))
    second = load(session_factory, store, catalog(
        entry(requiredAction="Apply updates or discontinue use."), entry("CVE-2026-0008"),
        version="2026.11.21", released="2026-11-21T15:00:00Z"))
    assert (second.rows_updated, second.rows_inserted) == (1, 1)
    with session_factory() as s:
        r1, r2 = s.scalars(select(KevCatalogRelease).order_by(KevCatalogRelease.date_released)).all()
        e = s.scalar(select(KevEntry).where(KevEntry.cve_id == "CVE-2026-0001"))
        assert (e.first_seen_release_id, e.last_seen_release_id) == (r1.id, r2.id)
        assert e.required_action == "Apply updates or discontinue use."
        assert e.evidence_version_id == second.input_evidence_version_id != first.input_evidence_version_id
        gone = s.scalar(select(KevEntry).where(KevEntry.cve_id == "CVE-2024-0007"))
        assert gone.last_seen_release_id == r1.id  # left the catalog: kept, not deleted

    # an older file imported afterwards doesn't roll the values back
    old = load(session_factory, store, catalog(entry(), version="2026.11.19", released="2026-11-19T15:00:00Z"))
    assert old.rows_unchanged == 1
    with session_factory() as s:
        e = s.scalar(select(KevEntry).where(KevEntry.cve_id == "CVE-2026-0001"))
        r0 = s.scalar(select(KevCatalogRelease).where(KevCatalogRelease.catalog_version == "2026.11.19"))
        assert e.required_action == "Apply updates or discontinue use." and e.first_seen_release_id == r0.id

    kev_summary(session_factory)
    out = capsys.readouterr().out
    assert "KEV catalog 2026.11.21" in out and "2 entries in it" in out
    assert "1 stored entries are no longer in the latest catalog" in out


def mock(answers, calls):
    def handler(request):
        calls.append(str(request.url))
        a = answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return httpx.Response(a, content=catalog(entry()) if a == 200 else b"busy")
    return KevClient(httpx.Client(transport=httpx.MockTransport(handler)), backoff_s=0)


def test_download_retries_a_rate_limit_then_gives_up():
    calls = []
    assert json.loads(mock([429, 503, 200], calls).fetch())["catalogVersion"] == "2026.11.20"
    assert len(calls) == 3
    with pytest.raises(KevUnavailable, match="HTTP 429"):
        mock([429, 429, 429], []).fetch()
    with pytest.raises(KevUnavailable, match="ConnectTimeout"):
        mock([httpx.ConnectTimeout("timed out")] * 3, []).fetch()
    calls = []
    with pytest.raises(KevUnavailable, match="HTTP 404"):
        mock([404, 200], calls).fetch()
    assert len(calls) == 1  # a missing file is not retried


def test_exposure_cves_matched_to_kev(session_factory, store, acme, capsys):
    db = {**DB, "198.51.100.1": (200, {**DB["198.51.100.1"][1], "vulns": ["CVE-2026-0001"]})}
    collect(session_factory, store, DNS, db, MX)  # own IP 192.0.2.10 and the CDN IP both list CVE-2026-0001
    kev_summary(session_factory)
    assert "No KEV catalog imported yet" in capsys.readouterr().out

    load(session_factory, store, catalog(entry(), entry("CVE-2025-9999")))
    with session_factory() as s:
        rows = s.execute(text("SELECT host, attribution, cve_id, in_latest_catalog FROM indexed_exposure_kev_matches "
                              "ORDER BY host")).all()
    assert [tuple(r) for r in rows] == [("acme.example", "company_only", "CVE-2026-0001", True),
                                        ("www.acme.example", "cdn", "CVE-2026-0001", True)]
    kev_summary(session_factory)
    out = capsys.readouterr().out
    assert "1 host/CVE pairs, 1 distinct CVEs, 1 companies" in out
    assert "acme.example" in out and "CVE-2026-0001" in out and "Known" in out
    assert "www.acme.example" not in out  # the CDN's IP is not the company's
    assert "1 more IP/CVE pairs are on CDN or shared IPs" in out
