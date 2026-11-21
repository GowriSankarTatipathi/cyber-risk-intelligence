"""NVD records, CVSS and CWE (issue 5.3). Synthetic NVD answers through a mocked client; nothing is contacted."""
# ruff: noqa: F811 - pytest fixtures imported from test_exposure

import csv
import io
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import httpx
import pytest
from sqlalchemy import select, text, update

from cyber_risk_intelligence.ingest import run_import
from cyber_risk_intelligence.ingest.framework import IngestionFailed
from cyber_risk_intelligence.models import (
    CvssScore,
    Vulnerability,
    VulnerabilityWeakness,
)
from cyber_risk_intelligence.vulnerabilities.__main__ import nvd_summary, priority
from cyber_risk_intelligence.vulnerabilities.nvd import (
    NvdClient,
    NvdJob,
    NvdKeyRejected,
    affected,
    cvss_rows,
    impact_class,
    targets_csv,
)

from .test_epss import epss_file
from .test_epss import load as load_epss
from .test_exposure import DB, DNS, MX, acme, collect, store  # noqa: F401 - fixtures
from .test_kev import catalog, entry
from .test_kev import load as load_kev

V31_RCE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V31_DOS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
V31_XSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"


def metric(version, vector, score, source="nvd@nist.gov", kind="Primary", severity="CRITICAL"):
    data = {"version": version, "vectorString": vector, "baseScore": score}
    if version != "2.0":
        data["baseSeverity"] = severity
    m = {"source": source, "type": kind, "cvssData": data, "exploitabilityScore": 3.9, "impactScore": 5.9}
    if version == "2.0":
        m["baseSeverity"] = severity
    return m


def record(cve, metrics=None, status="Analyzed", cwes=("CWE-787",), modified="2026-11-01T10:00:00.000"):
    return {"id": cve, "sourceIdentifier": "cna@example.test", "published": "2026-01-02T03:04:05.678",
            "lastModified": modified, "vulnStatus": status,
            "descriptions": [{"lang": "es", "value": "Desbordamiento"}, {"lang": "en", "value": f"{cve} overflow."}],
            "metrics": metrics or {},
            "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary",
                            "description": [{"lang": "en", "value": c} for c in cwes]}],
            "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [
                {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"},
                {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"}]}]}],
            "references": [{"url": "https://example.test/advisory", "source": "cna@example.test", "tags": ["Vendor Advisory"]}]}


def nvd(routes, calls=None, api_key=""):
    """routes: CVE -> record dict, an int status, or a list of answers in turn."""
    def handler(request):
        cve = request.url.params["cveId"]
        if calls is not None:
            calls.append((cve, request.headers.get("apiKey")))
        answer = routes.get(cve)
        if isinstance(answer, list):
            answer = answer.pop(0)
        if isinstance(answer, int):
            return httpx.Response(answer, text="busy")
        items = [{"cve": answer}] if answer else []
        return httpx.Response(200, json={"totalResults": len(items), "timestamp": datetime.now(UTC).isoformat(),
                                         "vulnerabilities": items})
    return NvdClient(httpx.Client(transport=httpx.MockTransport(handler)), api_key=api_key, pause=0, backoff_s=0)


def cves_csv(*cves):
    return ("cve_id\n" + "".join(c + "\n" for c in cves)).encode()


def run(sf, store, client, *cves):
    job = NvdJob(store, client)
    return run_import(sf, store, job, cves_csv(*cves), source_url="db:tracked_cves"), job


def test_cvss_versions_stay_separate_and_labelled():
    rows = cvss_rows({
        "cvssMetricV31": [metric("3.1", V31_RCE, 9.8), metric("3.1", V31_DOS, 7.5, source="cna@example.test",
                                                              kind="Secondary", severity="HIGH")],
        "cvssMetricV40": [metric("4.0", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3)],
        "cvssMetricV2": [metric("2.0", "AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5, severity="HIGH")],
        "cvssMetricV30": [{"source": "x", "cvssData": {"version": "3.0"}}],  # no vector or score: not a score
        "ssvcV203": [{"source": "cisa"}],
    })
    assert sorted((r["cvss_version"], r["source"], r["base_score"]) for r in rows) == [
        ("2.0", "nvd@nist.gov", Decimal("7.5")), ("3.1", "cna@example.test", Decimal("7.5")),
        ("3.1", "nvd@nist.gov", Decimal("9.8")), ("4.0", "nvd@nist.gov", Decimal("9.3"))]
    assert next(r for r in rows if r["cvss_version"] == "2.0")["base_severity"] == "HIGH"


def test_impact_class():
    assert impact_class(V31_RCE) == "remote"
    assert impact_class(V31_DOS) == "dos_only"
    assert impact_class(V31_XSS) == "needs_user"
    assert impact_class("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H") == "local"
    assert impact_class("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N") == "dos_only"
    assert impact_class("AV:N/AC:L/Au:N/C:P/I:P/A:P") == "remote"
    assert impact_class(None) == "unscored"


def test_affected_products_walk_nested_configurations():
    configs = [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:jquery:jquery:*:*:*:*:*:*:*:*"}],
                           "nodes": [{"cpeMatch": [{"vulnerable": True,
                                                    "criteria": "cpe:2.3:a:oracle:weblogic:12.2:*:*:*:*:*:*:*"},
                                                   {"vulnerable": False, "criteria": "cpe:2.3:o:x:y:1:*"}]}]}]}]
    assert affected(configs) == (["jquery:jquery", "oracle:weblogic"], 2)


def test_records_are_stored_with_scores_weaknesses_and_missingness(session_factory, store):
    routes = {"CVE-2026-0001": record("CVE-2026-0001", {"cvssMetricV31": [metric("3.1", V31_RCE, 9.8)],
                                                         "cvssMetricV2": [metric("2.0", "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                                                                                 7.5, severity="HIGH")]}),
              "CVE-2026-0002": record("CVE-2026-0002", status="Awaiting Analysis", cwes=("NVD-CWE-noinfo",)),
              "CVE-2026-0003": None}
    r, job = run(session_factory, store, nvd(routes), "CVE-2026-0001", "cve-2026-0002", "CVE-2026-0003", "CVE-26-4")
    assert (r.status, r.rows_inserted, r.rows_rejected) == ("partial", 3, 1)
    assert job.tally == {"found": 2, "not_found": 1, "lookup_failed": 0}
    with session_factory() as s:
        v = s.scalar(select(Vulnerability).where(Vulnerability.cve_id == "CVE-2026-0001"))
        assert (v.outcome, v.vuln_status, v.description, v.affected_products, v.affected_cpe_count) == (
            "found", "Analyzed", "CVE-2026-0001 overflow.", ["apache:http_server"], 1)
        assert v.published_at.tzinfo is not None and v.references[0]["tags"] == ["Vendor Advisory"]
        assert v.evidence_version_id is not None
        scores = s.scalars(select(CvssScore).where(CvssScore.vulnerability_id == v.id)
                           .order_by(CvssScore.cvss_version)).all()
        assert [(x.cvss_version, x.base_score, x.vector_string) for x in scores] == [
            ("2.0", Decimal("7.5"), "AV:N/AC:L/Au:N/C:P/I:P/A:P"), ("3.1", Decimal("9.8"), V31_RCE)]
        assert all(x.evidence_version_id == v.evidence_version_id for x in scores)
        unscored = s.scalar(select(Vulnerability).where(Vulnerability.cve_id == "CVE-2026-0002"))
        assert unscored.vuln_status == "Awaiting Analysis"
        assert s.scalars(select(CvssScore).where(CvssScore.vulnerability_id == unscored.id)).all() == []
        assert s.scalars(select(VulnerabilityWeakness.cwe_id)
                         .where(VulnerabilityWeakness.vulnerability_id == unscored.id)).all() == ["NVD-CWE-noinfo"]
        missing = s.scalar(select(Vulnerability).where(Vulnerability.cve_id == "CVE-2026-0003"))
        assert (missing.outcome, missing.evidence_version_id) == ("not_found", None)
        sev = {x.cve_id: x for x in s.execute(text("SELECT * FROM vulnerability_severity"))}
        assert (sev["CVE-2026-0001"].cvss_version, sev["CVE-2026-0001"].base_score) == ("3.1", Decimal("9.8"))
        assert sev["CVE-2026-0001"].cwes == ["CWE-787"]
        assert sev["CVE-2026-0002"].base_score is None and sev["CVE-2026-0002"].cwes is None  # explicit: no score

    again, _ = run(session_factory, store, nvd(routes), "CVE-2026-0001", "CVE-2026-0002")
    assert again.rows_unchanged == 2  # the NVD answer's own timestamp differs, the record doesn't


def test_a_changed_record_replaces_scores_and_a_failed_lookup_keeps_them(session_factory, store):
    run(session_factory, store, nvd({"CVE-2026-0001": record("CVE-2026-0001", {
        "cvssMetricV31": [metric("3.1", V31_RCE, 9.8)]})}), "CVE-2026-0001")
    changed = record("CVE-2026-0001", {"cvssMetricV31": [metric("3.1", V31_DOS, 7.5, severity="HIGH")]},
                     modified="2026-11-15T00:00:00.000")
    r, _ = run(session_factory, store, nvd({"CVE-2026-0001": changed}), "CVE-2026-0001")
    assert r.rows_updated == 1
    with session_factory() as s:
        v = s.scalar(select(Vulnerability))
        assert [x.vector_string for x in s.scalars(select(CvssScore))] == [V31_DOS]
        kept = v.evidence_version_id

    calls = []
    r, job = run(session_factory, store, nvd({"CVE-2026-0001": [403, 403, 503]}, calls), "CVE-2026-0001")
    assert job.tally["lookup_failed"] == 1 and len(calls) == 3  # rate limit (403) and 503 are retried
    with session_factory() as s:
        v = s.scalar(select(Vulnerability))
        assert (v.outcome, v.evidence_version_id) == ("found", kept)  # what we knew stays
        assert s.scalar(select(CvssScore.vector_string)) == V31_DOS


def test_a_failed_first_lookup_is_recorded_and_retried(session_factory, store, acme):
    db = {**DB, "192.0.2.10": (200, {**DB["192.0.2.10"][1], "vulns": ["CVE-2026-0001", "CVE-2025-0005"]})}
    collect(session_factory, store, DNS, db, MX)
    load_kev(session_factory, store, catalog(entry("CVE-2024-0007")))
    calls = []
    client = nvd({"CVE-2026-0001": record("CVE-2026-0001"), "CVE-2025-0005": [500, 500, 500],
                  "CVE-2024-0007": record("CVE-2024-0007")}, calls, api_key="test-key")
    with session_factory() as s:
        content = targets_csv(s)
    # exposure CVEs first (newest first), then KEV-only ones
    assert [row["cve_id"] for row in csv.DictReader(io.StringIO(content.decode()))] == [
        "CVE-2026-0001", "CVE-2025-0005", "CVE-2024-0007"]
    job = NvdJob(store, client)
    run_import(session_factory, store, job, content, source_url="db:tracked_cves")
    assert {k for _, k in calls} == {"test-key"}  # the key travels as a header only
    with session_factory() as s:
        assert s.scalar(select(Vulnerability.outcome).where(Vulnerability.cve_id == "CVE-2025-0005")) == "lookup_failed"
        assert targets_csv(s) == b"cve_id\r\nCVE-2025-0005\r\n"  # only the failed one is asked again
        s.execute(update(Vulnerability).values(retrieved_at=datetime.now(UTC) - timedelta(days=40)))
        s.commit()
        assert targets_csv(s).count(b"CVE-") == 3  # stale records are refreshed
        assert targets_csv(s, limit=1).count(b"CVE-") == 1


def test_client_pause_depends_on_the_key():
    assert NvdClient(httpx.Client(), api_key="").pause == 6.5
    assert NvdClient(httpx.Client(), api_key="k").pause == 0.7
    # an unknown CVE is a 200 with no results; a bare 404 says nothing about the CVE
    assert nvd({"CVE-2026-0009": None}).cve("CVE-2026-0009").outcome == "not_found"
    assert nvd({"CVE-2026-0009": 404}).cve("CVE-2026-0009").outcome == "lookup_failed"


def test_a_rejected_api_key_stops_the_run_and_records_nothing(session_factory, store):
    def handler(request):
        return httpx.Response(404, headers={"message": "Invalid apiKey."})
    client = NvdClient(httpx.Client(transport=httpx.MockTransport(handler)), api_key="wrong", pause=0, backoff_s=0)
    with pytest.raises(IngestionFailed) as failed:
        run(session_factory, store, client, "CVE-2026-0001", "CVE-2026-0002")
    assert isinstance(failed.value.__cause__, NvdKeyRejected) and "Invalid apiKey" in str(failed.value.__cause__)
    with session_factory() as s:
        assert s.scalars(select(Vulnerability)).all() == []


def test_cves_nvd_did_not_find_are_asked_again(session_factory, store, acme):
    db = {**DB, "192.0.2.10": (200, {**DB["192.0.2.10"][1], "vulns": ["CVE-2026-0001"]})}
    collect(session_factory, store, DNS, db, MX)
    run(session_factory, store, nvd({"CVE-2026-0001": None}), "CVE-2026-0001")
    with session_factory() as s:
        assert s.scalar(select(Vulnerability.outcome)) == "not_found"
        assert targets_csv(s).count(b"CVE-2026-0001") == 1
    run(session_factory, store, nvd({"CVE-2026-0001": record("CVE-2026-0001")}), "CVE-2026-0001")
    with session_factory() as s:
        assert s.scalar(select(Vulnerability.outcome)) == "found" and targets_csv(s) == b"cve_id\r\n"


def test_priority_ranks_kev_then_what_the_cve_allows(session_factory, store, acme, capsys):
    cves = ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005"]
    db = {**DB, "192.0.2.10": (200, {**DB["192.0.2.10"][1], "vulns": cves})}
    collect(session_factory, store, DNS, db, MX)
    load_kev(session_factory, store, catalog(entry("CVE-2026-0004")))
    with session_factory() as s:
        from cyber_risk_intelligence.vulnerabilities import tracked_cves

        scope = tracked_cves(s)
    load_epss(session_factory, store, epss_file(("CVE-2026-0001", "0.9", "0.99"), ("CVE-2026-0002", "0.99", "0.999"),
                                                ("CVE-2026-0003", "0.5", "0.9"), ("CVE-2026-0004", "0.01", "0.5")),
              scope=scope)
    routes = {"CVE-2026-0001": record("CVE-2026-0001", {"cvssMetricV31": [metric("3.1", V31_RCE, 9.8)]}),
              "CVE-2026-0002": record("CVE-2026-0002", {"cvssMetricV31": [metric("3.1", V31_DOS, 7.5)]}),
              "CVE-2026-0003": record("CVE-2026-0003", {"cvssMetricV31": [metric("3.1", V31_XSS, 6.1)]}),
              "CVE-2026-0004": record("CVE-2026-0004", {"cvssMetricV31": [metric("3.1", V31_DOS, 5.3)]})}
    run(session_factory, store, nvd(routes), "CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004")
    priority(session_factory)
    out = capsys.readouterr().out
    lines = [x for x in out.splitlines() if x.startswith("acme ") and "CVE-" in x]
    # KEV first; then remote above user-action above DoS, even though the DoS has the higher EPSS
    # (an unscored CVE sits above denial of service: its impact is unknown, not known to be small)
    assert [x.split()[1] for x in lines] == ["CVE-2026-0004", "CVE-2026-0001", "CVE-2026-0003", "CVE-2026-0005",
                                             "CVE-2026-0002"]
    assert "KEV*" in lines[0] and "remote" in lines[1] and "v3.1 9.8" in lines[1] and "no NVD" in lines[3]
    rollup = next(x for x in out.splitlines() if x.startswith("acme ") and "CVE-" not in x).split()
    assert rollup[1:5] == ["5", "1", "1", "0"]  # CVEs, KEV, remote critical, remote high
    assert "1 leads have no NVD record yet" in out
    nvd_summary(session_factory)
    assert "4 found, 0 not in NVD, 0 lookups failed, 1 not looked up yet" in capsys.readouterr().out


def test_an_example_password_in_a_description_is_kept_but_a_real_token_is_not(session_factory, store):
    quoted = record("CVE-2023-25717")
    quoted["descriptions"] = [{"lang": "en", "value": "RCE as demonstrated by a "
                               "/forms/doLogin?login_username=admin&password=password$(curl substring."}]
    leaked = record("CVE-2026-0009")
    leaked["descriptions"] = [{"lang": "en", "value": "Key " + "AKIA" + "ABCDEFGHIJKLMNOP" + " shipped in builds."}]
    r, _ = run(session_factory, store, nvd({"CVE-2023-25717": quoted, "CVE-2026-0009": leaked}),
               "CVE-2023-25717", "CVE-2026-0009")
    assert (r.rows_inserted, r.rows_rejected) == (1, 1)
    with session_factory() as s:
        kept = s.scalar(select(Vulnerability).where(Vulnerability.cve_id == "CVE-2023-25717"))
        assert kept.outcome == "found" and "password=password" in kept.description
        assert s.scalar(select(Vulnerability).where(Vulnerability.cve_id == "CVE-2026-0009")) is None
        err = s.execute(text("SELECT code FROM ingestion_errors WHERE row_key = 'CVE-2026-0009'")).scalar()
        assert err == "withheld"
