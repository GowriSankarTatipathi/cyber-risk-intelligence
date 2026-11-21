"""EPSS history (issue 12.2): daily collection log, gaps, corrections, backfill. Mocked downloads only."""
# ruff: noqa: F811 - pytest fixtures imported from test_exposure

import re
from datetime import date
from decimal import Decimal

import httpx
from sqlalchemy import select

from cyber_risk_intelligence.models import EpssCollectionRun, EpssScore
from cyber_risk_intelligence.vulnerabilities.__main__ import (
    epss_coverage,
    epss_history,
    epss_trends,
)
from cyber_risk_intelligence.vulnerabilities.epss import (
    EpssClient,
    backfill,
    collect_day,
)

from .test_epss import epss_file
from .test_exposure import acme, store  # noqa: F401 - fixtures

SCOPE = {"CVE-2026-0001"}


def client(files, calls=None):
    """files: day 'YYYY-MM-DD' -> bytes or an int status."""
    def handler(request):
        if calls is not None:
            calls.append(str(request.url))
        day = re.search(r"(\d{4}-\d{2}-\d{2})", str(request.url))
        answer = files.get(day[1] if day else "current", 404)
        if isinstance(answer, list):
            answer = answer.pop(0)
        return httpx.Response(answer) if isinstance(answer, int) else httpx.Response(200, content=answer)
    return EpssClient(httpx.Client(transport=httpx.MockTransport(handler)), backoff_s=0)


def day_file(day, epss="0.5", pct="0.9"):
    return epss_file(("CVE-2026-0001", epss, pct), ("CVE-2025-0099", "0.1", "0.5"), day=day)


def scores(sf):
    with sf() as s:
        return [(x.score_date, x.epss) for x in s.scalars(select(EpssScore).order_by(EpssScore.score_date))]


def attempts(sf):
    with sf() as s:
        return [(a.score_date, a.outcome) for a in s.scalars(select(EpssCollectionRun).order_by(EpssCollectionRun.id))]


def test_refetching_a_day_is_idempotent(session_factory, store):
    files = {"2026-11-18": day_file("2026-11-18")}
    a1, r1, _ = collect_day(session_factory, store, SCOPE, date(2026, 11, 18), client(files))
    a2, r2, _ = collect_day(session_factory, store, SCOPE, date(2026, 11, 18), client(files))
    assert (a1.outcome, a2.outcome, r1.rows_inserted, r2.rows_unchanged) == ("imported", "imported", 1, 1)
    assert a1.evidence_version_id == a2.evidence_version_id and a1.rows_in_file == 2 and a1.rows_stored == 1
    assert scores(session_factory) == [(date(2026, 11, 18), Decimal("0.5"))]


def test_a_missing_release_is_a_gap_not_a_copied_score(session_factory, store, capsys):
    files = {"2026-11-17": day_file("2026-11-17", "0.4"), "2026-11-19": day_file("2026-11-19", "0.6"),
             "2026-11-18": 404}
    got = list(backfill(session_factory, store, SCOPE, date(2026, 11, 17), date(2026, 11, 19), client(files), pause=0))
    assert [(a.score_date, a.outcome) for a in got] == [
        (date(2026, 11, 17), "imported"), (date(2026, 11, 18), "not_published"), (date(2026, 11, 19), "imported")]
    assert scores(session_factory) == [(date(2026, 11, 17), Decimal("0.4")), (date(2026, 11, 19), Decimal("0.6"))]
    epss_coverage(session_factory)
    assert "1 gap days: 2026-11-18 (not_published)" in capsys.readouterr().out

    calls = []
    again = list(backfill(session_factory, store, SCOPE, date(2026, 11, 17), date(2026, 11, 19),
                          client(files, calls), pause=0))
    assert [a.score_date for a in again] == [date(2026, 11, 18)] and len(calls) == 1  # only the gap is retried


def test_rate_limits_and_errors_are_failed_attempts_with_nothing_stored(session_factory, store):
    files = {"2026-11-18": [429, 503, 429], "2026-11-19": b"<html>not an epss file</html>"}
    a, run, _ = collect_day(session_factory, store, SCOPE, date(2026, 11, 18), client(files))
    assert (a.outcome, run) == ("failed", None) and "429" in a.message
    a, run, _ = collect_day(session_factory, store, SCOPE, date(2026, 11, 19), client(files))
    assert a.outcome == "failed" and "not an EPSS file" in a.message
    assert scores(session_factory) == []


def test_a_republished_day_keeps_the_correction(session_factory, store, capsys):
    collect_day(session_factory, store, SCOPE, date(2026, 11, 18), client({"2026-11-18": day_file("2026-11-18", "0.5")}))
    collect_day(session_factory, store, SCOPE, date(2026, 11, 18), client({"2026-11-18": day_file("2026-11-18", "0.7")}))
    with session_factory() as s:
        row = s.scalar(select(EpssScore))
        assert row.epss == Decimal("0.7") and row.corrections[0]["epss"] == "0.500000000"
    epss_history(session_factory, "cve-2026-0001")
    assert "1 earlier value(s) corrected" in capsys.readouterr().out


def test_a_day_without_a_date_takes_the_files_own_date(session_factory, store):
    a, _, job = collect_day(session_factory, store, SCOPE, None, client({"current": day_file("2026-11-20")}))
    assert (a.score_date, a.outcome, job.score_date) == (date(2026, 11, 20), "imported", date(2026, 11, 20))
    assert attempts(session_factory) == [(date(2026, 11, 20), "imported")]


def test_trends_show_rising_cves_on_own_ips(session_factory, store, acme, capsys):
    from .test_exposure import DB, DNS, MX, collect

    db = {**DB, "192.0.2.10": (200, {**DB["192.0.2.10"][1], "vulns": ["CVE-2026-0001"]})}
    collect(session_factory, store, DNS, db, MX)
    files = {"2026-11-17": day_file("2026-11-17", "0.10"), "2026-11-19": day_file("2026-11-19", "0.65")}
    list(backfill(session_factory, store, SCOPE, date(2026, 11, 17), date(2026, 11, 19), client(files), pause=0))
    epss_trends(session_factory, days=30)
    out = capsys.readouterr().out
    line = next(x for x in out.splitlines() if x.startswith("CVE-2026-0001"))
    assert "+0.5500" in line and "acme" in line
