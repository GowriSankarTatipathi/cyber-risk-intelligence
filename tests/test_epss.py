"""FIRST EPSS daily scores (issue 5.2). Synthetic files and a mocked download; nothing is contacted."""
# ruff: noqa: F811 - pytest fixtures imported from test_exposure

import gzip
from datetime import date
from decimal import Decimal

import httpx
import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError

from cyber_risk_intelligence.evidence import record_evidence
from cyber_risk_intelligence.ingest import run_import
from cyber_risk_intelligence.ingest.framework import IngestionFailed
from cyber_risk_intelligence.models import (
    EpssScore,
    EvidenceObject,
    EvidenceVersion,
    IngestionError,
)
from cyber_risk_intelligence.vulnerabilities import (
    EpssClient,
    EpssJob,
    EpssUnavailable,
    tracked_cves,
)
from cyber_risk_intelligence.vulnerabilities.__main__ import epss_summary

from . import factories as f
from .test_exposure import DB, DNS, MX, acme, collect, store  # noqa: F401 - fixtures
from .test_kev import catalog, entry
from .test_kev import load as load_kev


def epss_file(*rows, day="2026-11-20", model="v2026.06.15", gz=True):
    body = f"#model_version:{model},score_date:{day}T12:03:05Z\ncve,epss,percentile\n"
    body += "".join(f"{c},{e},{p}\n" for c, e, p in rows)
    return gzip.compress(body.encode()) if gz else body.encode()


def load(sf, store, content, scope=None):
    job = EpssJob(scope)
    return run_import(sf, store, job, content, source_url="https://epss.empiricalsecurity.com/x.csv.gz"), job


ROWS = [("CVE-2026-0001", "0.97", "0.9998"), ("CVE-2025-0002", "0.00043", "0.11"), ("CVE-1999-0001", "0.04753", "0.9209")]


def test_only_tracked_cves_are_stored_and_the_whole_file_is_kept(session_factory, store):
    run, job = load(session_factory, store, epss_file(*ROWS), scope={"cve-2026-0001", "CVE-2025-0002", "CVE-2024-9999"})
    assert (run.status, run.rows_inserted, job.rows_in_file) == ("succeeded", 2, 3)
    assert job.score_date == date(2026, 11, 20) and job.model_version == "v2026.06.15"
    with session_factory() as s:
        top = s.scalar(select(EpssScore).where(EpssScore.cve_id == "CVE-2026-0001"))
        assert (top.epss, top.percentile, top.score_date) == (Decimal("0.97"), Decimal("0.9998"), date(2026, 11, 20))
        assert top.evidence_version_id == run.input_evidence_version_id
        obj = s.get(EvidenceObject, s.get(EvidenceVersion, top.evidence_version_id).evidence_object_id)
        assert obj.media_type == "application/gzip"
        # CVE-2024-9999 isn't in the file: no row, so its score stays unknown (not zero)
        assert sorted(s.scalars(select(EpssScore.cve_id))) == ["CVE-2025-0002", "CVE-2026-0001"]

    again, _ = load(session_factory, store, epss_file(*ROWS), scope={"CVE-2026-0001", "CVE-2025-0002"})
    assert (again.rows_unchanged, again.rows_inserted) == (2, 0)


def test_two_dates_for_one_cve_coexist(session_factory, store):
    load(session_factory, store, epss_file(*ROWS))
    load(session_factory, store, epss_file(("CVE-2026-0001", "0.5", "0.99"), day="2026-11-21"))
    with session_factory() as s:
        scores = s.execute(select(EpssScore.score_date, EpssScore.epss).where(EpssScore.cve_id == "CVE-2026-0001")
                           .order_by(EpssScore.score_date)).all()
        assert [tuple(x) for x in scores] == [(date(2026, 11, 20), Decimal("0.97")), (date(2026, 11, 21), Decimal("0.5"))]
        latest = s.execute(text("SELECT score_date, epss FROM latest_epss_scores WHERE cve_id = 'CVE-2026-0001'")).one()
        assert tuple(latest) == (date(2026, 11, 21), Decimal("0.5"))
        assert s.scalar(select(func.count()).select_from(EpssScore)) == 4


def test_values_outside_zero_to_one_are_rejected(session_factory, store):
    run, _ = load(session_factory, store, epss_file(
        ("CVE-2026-0001", "1.2", "0.5"), ("CVE-2026-0002", "0.1", "-0.01"), ("CVE-2026-0003", "abc", "0.5"),
        ("CVE-2026-0004", "NaN", "0.5"), ("CVE-26-5", "0.1", "0.5"), ("CVE-2026-0006", "1", "0"), gz=False))
    assert (run.status, run.rows_inserted, run.rows_rejected) == ("partial", 1, 5)
    with session_factory() as s:
        codes = sorted(s.scalars(select(IngestionError.code).where(IngestionError.run_id == run.id)))
        assert codes == ["cve_id_valid", "epss_in_range", "epss_in_range", "epss_in_range", "percentile_in_range"]
        assert s.scalars(select(EpssScore.cve_id)).all() == ["CVE-2026-0006"]


def test_the_database_refuses_an_out_of_range_score(session, store):
    version = record_evidence(session, store, source=f.source(session), source_url="https://x.test/e", content=b"x",
                              media_type="text/plain")
    session.add(EpssScore(cve_id="CVE-2026-0001", score_date=date(2026, 11, 20), epss=Decimal("1.5"),
                          percentile=Decimal("0.5"), evidence_version_id=version.id))
    with pytest.raises(IntegrityError, match="epss_range"):
        session.flush()


def test_a_file_without_the_score_date_line_fails_the_run(session_factory, store):
    with pytest.raises(IngestionFailed):
        load(session_factory, store, b"cve,epss,percentile\nCVE-2026-0001,0.1,0.2\n")
    with session_factory() as s:
        assert s.scalar(select(func.count()).select_from(EpssScore)) == 0


def mock(answers, calls):
    def handler(request):
        calls.append(request.url.path)
        a = answers.pop(0)
        if isinstance(a, Exception):
            raise a
        if a == 302:
            return httpx.Response(302, headers={"location": "epss_scores-2026-11-20.csv.gz"})
        return httpx.Response(a, content=epss_file(*ROWS) if a == 200 else b"busy")
    return EpssClient(httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True), backoff_s=0)


def test_download():
    calls = []
    url, content = mock([302, 200], calls).fetch()
    assert url.endswith("/epss_scores-2026-11-20.csv.gz") and gzip.decompress(content).startswith(b"#model_version")
    calls = []
    mock([429, 503, 200], calls).fetch(date(2026, 11, 19))
    assert calls == ["/epss_scores-2026-11-19.csv.gz"] * 3
    calls = []
    with pytest.raises(EpssUnavailable, match="HTTP 404"):
        mock([404, 200], calls).fetch(date(2030, 1, 1))  # not published yet: not retried
    assert len(calls) == 1
    with pytest.raises(EpssUnavailable, match="ConnectTimeout"):
        mock([httpx.ConnectTimeout("timed out")] * 3, []).fetch()


def test_summary_ranks_own_ip_cves_known_exploited_first(session_factory, store, acme, capsys):
    db = {**DB, "192.0.2.10": (200, {**DB["192.0.2.10"][1], "vulns": ["CVE-2026-0001", "CVE-2025-0002",
                                                                        "CVE-2024-0003"]}),
          "198.51.100.1": (200, {**DB["198.51.100.1"][1], "vulns": ["CVE-1999-0001"]})}
    collect(session_factory, store, DNS, db, MX)  # 192.0.2.10 is acme's own IP; 198.51.100.1 is a CDN
    load_kev(session_factory, store, catalog(entry("CVE-2025-0002")))
    with session_factory() as s:
        assert tracked_cves(s) == {"CVE-2026-0001", "CVE-2025-0002", "CVE-2024-0003", "CVE-1999-0001"}
        scope = tracked_cves(s)
    load(session_factory, store, epss_file(*ROWS), scope=scope)
    epss_summary(session_factory)
    out = capsys.readouterr().out
    assert "3 tracked CVEs scored" in out and "1 tracked CVEs have no score that day" in out
    lines = [x for x in out.splitlines() if x.startswith("acme ")]
    # KEV first (even with a low EPSS), then by EPSS; an unscored CVE last with "?"
    assert [x.split()[1] for x in lines] == ["CVE-2025-0002", "CVE-2026-0001", "CVE-2024-0003"]
    assert "yes" in lines[0] and "0.9700" in lines[1] and "?" in lines[2]
    assert "CVE-1999-0001" not in out  # only on the CDN's IP
    assert "not a probability of loss" in out
