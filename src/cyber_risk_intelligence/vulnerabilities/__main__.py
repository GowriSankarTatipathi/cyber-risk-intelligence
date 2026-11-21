"""Command line for issue 5.

    python -m cyber_risk_intelligence.vulnerabilities kev collect [--file catalog.json]
        # download CISA's KEV catalog (or import a saved copy) into kev_entries
    python -m cyber_risk_intelligence.vulnerabilities kev summary
    python -m cyber_risk_intelligence.vulnerabilities kev changes [--days 30]
        # CVEs CISA added, changed or removed in the releases we imported (first catalog = baseline)
        # the catalog we hold, and which CVEs Shodan inferred on companies' own IPs are in KEV
    python -m cyber_risk_intelligence.vulnerabilities epss collect [--date 2026-11-20] [--file f.csv.gz] [--all]
        # FIRST EPSS scores for the day, stored for the tracked CVEs (exposure CVEs + KEV)
    python -m cyber_risk_intelligence.vulnerabilities epss summary
    python -m cyber_risk_intelligence.vulnerabilities epss backfill --from 2026-10-01 [--to 2026-11-20] [--refetch]
        # past days' scores for the tracked CVEs; days FIRST never published are recorded as gaps
    python -m cyber_risk_intelligence.vulnerabilities epss trends [--days 30]
        # tracked CVEs on companies' own IPs whose EPSS rose most over the period
    python -m cyber_risk_intelligence.vulnerabilities epss history --cve CVE-2021-40438
        # companies' own-IP CVE leads, known-exploited first, then by EPSS
    python -m cyber_risk_intelligence.vulnerabilities nvd collect [--refresh-days 30] [--limit N]
        # NVD CVSS scores, CWE weaknesses and affected products for the tracked CVEs (NVD_API_KEY speeds it up)
    python -m cyber_risk_intelligence.vulnerabilities nvd summary
    python -m cyber_risk_intelligence.vulnerabilities priority
        # companies' own-IP CVE leads ranked: KEV, then what the CVE allows (remote > user action > DoS), CVSS, EPSS

An EPSS score is about the CVE, not a company: never a company's probability of loss.

A CVE Shodan inferred from a software version is a lead, not a confirmed vulnerability, and KEV only
says the CVE was exploited somewhere. A match means "ask about this", not "this company is breached".
"""

import argparse
import sys
from datetime import UTC, date, datetime
from pathlib import Path

from sqlalchemy import text

from ..db import make_engine, make_session_factory
from ..evidence import store_from_env
from ..ingest import run_import
from ..ingest.framework import IngestionFailed
from .epss import backfill, collect_day, tracked_cves
from .kev import KEV_URL, KevClient, KevJob, KevUnavailable, record_removals

OWN = "('company_only', 'unknown')"
LATEST_EXPOSURE = ("SELECT * FROM (SELECT x.*, max(x.ingestion_run_id) OVER (PARTITION BY x.domain_id) AS last_run "
                   "FROM indexed_host_lookups x) y WHERE ingestion_run_id IS NOT DISTINCT FROM last_run")


def kev_summary(sf) -> None:
    with sf() as s:
        rel = s.execute(text(
            "SELECT id, catalog_version, date_released, entry_count FROM kev_catalog_releases "
            "ORDER BY date_released DESC, id DESC LIMIT 1")).first()
        if rel is None:
            print("No KEV catalog imported yet: run  python -m cyber_risk_intelligence.vulnerabilities kev collect")
            return
        n = s.execute(text(
            "SELECT count(*) AS stored, count(*) FILTER (WHERE last_seen_release_id = :r) AS current, "
            "count(*) FILTER (WHERE last_seen_release_id = :r AND known_ransomware_use = 'Known') AS ransomware, "
            "count(*) FILTER (WHERE last_seen_release_id = :r AND date_added > CAST(:d AS date) - 30) AS recent "
            "FROM kev_entries"), {"r": rel.id, "d": rel.date_released.date()}).one()
        matches = s.execute(text(
            f"SELECT c.company_key, m.host, host(m.ip) AS ip, m.cve_id, m.vendor_project, m.product, "
            f"m.known_ransomware_use, m.date_added FROM indexed_exposure_kev_matches m "
            f"JOIN companies c ON c.id = m.company_id WHERE m.attribution IN {OWN} AND m.in_latest_catalog "
            f"ORDER BY c.company_key, m.cve_id, m.host")).all()
        elsewhere = s.scalar(text(
            f"SELECT count(DISTINCT (ip, cve_id)) FROM indexed_exposure_kev_matches "
            f"WHERE attribution NOT IN {OWN} AND in_latest_catalog"))
    print(f"KEV catalog {rel.catalog_version} (released {rel.date_released:%Y-%m-%d %H:%M} UTC, "
          f"CISA count {rel.entry_count}): {n.current} entries in it, {n.ransomware} with known ransomware use, "
          f"{n.recent} added in the 30 days before release.")
    if n.stored > n.current:
        print(f"{n.stored - n.current} stored entries are no longer in the latest catalog (kept for history).")
    if not matches:
        print("\nNo KEV CVEs among the CVEs Shodan inferred on companies' own IPs "
              "(or exposure collect has not run yet).")
    else:
        companies = sorted({m.company_key for m in matches})
        print(f"\nKEV CVEs among the CVEs Shodan inferred on companies' own IPs: {len(matches)} host/CVE pairs, "
              f"{len({m.cve_id for m in matches})} distinct CVEs, {len(companies)} companies.")
        print(f"{'company':36} {'host':40} {'ip':16} {'cve':16} {'ransomware':10} vendor / product")
        for m in matches:
            print(f"{m.company_key:36} {m.host[:40]:40} {m.ip:16} {m.cve_id:16} {m.known_ransomware_use or '?':10} "
                  f"{m.vendor_project} {m.product}"[:160])
    print(f"\n{elsewhere} more IP/CVE pairs are on CDN or shared IPs and are not counted against any company.")
    print("Shodan infers CVEs from software versions (unverified, no scan date); KEV means the CVE was exploited "
          "somewhere, not that this company was. Treat each row as a question for the company.")


def kev_changes(sf, days: int = 30) -> None:
    with sf() as s:
        rows = s.execute(text(
            f"SELECT e.change_type, e.cve_id, e.changed_fields, e.previous_values, e.new_values, e.date_added, "
            f"r.catalog_version, r.date_released, k.vendor_project, k.product, k.known_ransomware_use, "
            f"(SELECT string_agg(DISTINCT c.company_key, ', ') FROM indexed_exposure_kev_matches m "
            f" JOIN companies c ON c.id = m.company_id WHERE m.cve_id = e.cve_id AND m.attribution IN {OWN}) "
            f"AS companies "
            f"FROM kev_change_events e JOIN kev_catalog_releases r ON r.id = e.release_id "
            f"JOIN kev_entries k ON k.id = e.kev_entry_id "
            f"WHERE NOT e.baseline AND e.detected_at > now() - make_interval(days => :d) "
            f"ORDER BY r.date_released DESC, e.change_type, e.cve_id"), {"d": days}).all()
        baseline = s.scalar(text("SELECT count(*) FROM kev_change_events WHERE baseline"))
    if not rows:
        print(f"No KEV changes detected in the last {days} days"
              + (f" ({baseline} baseline entries from the first catalog)." if baseline else
                 ": run  kev collect  regularly (e.g. daily) to build the change feed."))
        return
    print(f"KEV changes detected in the last {days} days ({len(rows)}):")
    print(f"{'change':8} {'cve':16} {'release':11} {'ransomware':10} {'on own IPs of':24} vendor / product / what changed")
    for r in rows:
        what = f"{r.vendor_project} {r.product}"
        if r.change_type == "updated":
            what += "; " + ", ".join(f"{f}: {r.previous_values.get(f)!r} -> {r.new_values.get(f)!r}"
                                     for f in r.changed_fields or [])
        print(f"{r.change_type:8} {r.cve_id:16} {r.catalog_version[:11]:11} {r.known_ransomware_use or '?':10} "
              f"{(r.companies or '')[:24]:24} {what}"[:220])
    print("'on own IPs of' = companies whose latest exposure lookup lists the CVE (Shodan's inference): ask them first.")


def epss_summary(sf) -> None:
    with sf() as s:
        day = s.execute(text("SELECT score_date, max(model_version) AS model, count(*) AS n FROM epss_scores "
                             "GROUP BY score_date ORDER BY score_date DESC LIMIT 1")).first()
        if day is None:
            print("No EPSS scores imported yet: run  python -m cyber_risk_intelligence.vulnerabilities epss collect")
            return
        days = s.scalar(text("SELECT count(DISTINCT score_date) FROM epss_scores"))
        tracked = sorted(tracked_cves(s))
        scored = s.scalar(text("SELECT count(*) FROM epss_scores WHERE score_date = :d AND cve_id = ANY(:c)"),
                          {"d": day.score_date, "c": tracked}) or 0
        rows = s.execute(text(
            f"SELECT c.company_key, x.cve_id, count(DISTINCT x.ip) AS ips, min(x.host) AS host, e.epss, e.percentile, "
            f"e.score_date, k.cve_id IS NOT NULL AS kev, k.known_ransomware_use "
            f"FROM (SELECT l.company_id, l.host, l.ip, upper(v) AS cve_id FROM ({LATEST_EXPOSURE}) l "
            f"      CROSS JOIN LATERAL jsonb_array_elements_text(l.potential_vulns) AS v "
            f"      WHERE l.outcome = 'found' AND l.attribution IN {OWN}) x "
            f"JOIN companies c ON c.id = x.company_id "
            f"LEFT JOIN latest_epss_scores e ON e.cve_id = x.cve_id "
            f"LEFT JOIN kev_entries k ON k.cve_id = x.cve_id "
            f"GROUP BY c.company_key, x.cve_id, e.epss, e.percentile, e.score_date, k.cve_id, k.known_ransomware_use "
            f"ORDER BY (k.cve_id IS NOT NULL) DESC, e.epss DESC NULLS LAST, c.company_key LIMIT 300")).all()
    missing = len(tracked) - scored
    print(f"EPSS scores for {day.score_date} (model {day.model}): {day.n} tracked CVEs scored; "
          f"{days} scoring day(s) stored. {missing} tracked CVEs have no score that day (unknown, not zero).")
    if not rows:
        print("\nNo CVEs inferred on companies' own IPs (or exposure collect has not run yet).")
    else:
        print("\nCVEs Shodan inferred on companies' own IPs, known-exploited first, then by EPSS (top 300):")
        print(f"{'company':36} {'cve':16} {'KEV':4} {'ransomware':10} {'epss':>7} {'pctile':>7} {'IPs':>3}  example host")
        for r in rows:
            epss = f"{r.epss:.4f}" if r.epss is not None else "?"
            pct = f"{r.percentile:.3f}" if r.percentile is not None else "?"
            print(f"{r.company_key:36} {r.cve_id:16} {'yes' if r.kev else '':4} {r.known_ransomware_use or '':10} "
                  f"{epss:>7} {pct:>7} {r.ips:>3}  {r.host[:40]}")
    print("EPSS = estimated probability of exploitation activity against the CVE anywhere in the next 30 days "
          "(FIRST). It is about the CVE, not the company, and is not a probability of loss. "
          "Shodan's CVEs are inferred from software versions and unverified.")
    epss_coverage(sf)


def _import(sf, job, content: bytes, url: str):
    try:
        return run_import(sf, store_from_env(), job, content, source_url=url)
    except IngestionFailed as exc:
        print(f"{exc}. See ingestion_errors (run_id = {exc.run_id}).")
        return None


def _collect_kev(sf, args) -> int:
    if args.file:
        content, url = args.file.read_bytes(), args.file.resolve().as_uri()
    else:
        try:
            content, url = KevClient().fetch(), KEV_URL
        except KevUnavailable as exc:
            print(f"{exc}. Nothing was imported; the catalog already stored is unchanged.")
            return 2
    job = KevJob()
    r = _import(sf, job, content, url)
    if r is None:
        return 2
    with sf() as s:
        removed = record_removals(s, r.id)
    print(f"run {r.id} {r.status}: catalog {job.catalog.get('catalog_version')}, {r.rows_seen} entries, "
          f"{r.rows_inserted} new, {r.rows_updated} changed, {r.rows_unchanged} unchanged, {r.rows_rejected} rejected")
    if job._baseline:
        print("First catalog imported: its entries are the baseline (no change events to alert on).")
    else:
        print(f"Changes since the previous release: {job.changes.get('added', 0)} added, "
              f"{job.changes.get('updated', 0)} updated, {removed} removed "
              f"(details:  python -m cyber_risk_intelligence.vulnerabilities kev changes)")
    if r.rows_rejected:
        print(f"Rejected entries are in ingestion_errors (run_id = {r.id}).")
    kev_summary(sf)
    return 0 if r.status == "succeeded" else 2


def _epss_scope(sf, args):
    with sf() as s:
        scope = None if args.all else tracked_cves(s)
    if scope is not None and not scope:
        print("No CVEs to track yet: run  exposure collect  and/or  vulnerabilities kev collect  first "
              "(or pass --all to store every CVE's score).")
    return scope


def _collect_epss(sf, args) -> int:
    scope = _epss_scope(sf, args)
    if scope is not None and not scope:
        return 2
    content = url = None
    if args.file:
        content, url = args.file.read_bytes(), args.file.resolve().as_uri()
    attempt, r, job = collect_day(sf, store_from_env(), scope, args.date, content=content, url=url)
    if r is None:
        print(f"EPSS {args.date or 'latest'} {attempt.outcome}: {attempt.message}. Nothing was imported; stored "
              f"scores are unchanged" + (" (a gap for that day)." if attempt.outcome == "not_published" else "."))
        return 2
    print(f"run {r.id} {r.status}: EPSS {job.score_date} (model {job.model_version}), {job.rows_in_file} CVEs in the "
          f"file, {r.rows_seen} tracked: {r.rows_inserted} new, {r.rows_updated} changed, {r.rows_unchanged} unchanged, "
          f"{r.rows_rejected} rejected")
    epss_summary(sf)
    return 0 if r.status == "succeeded" else 2


def _backfill_epss(sf, args) -> int:
    if not args.start:
        print("epss backfill needs --from YYYY-MM-DD")
        return 2
    scope = _epss_scope(sf, args)
    if scope is not None and not scope:
        return 2
    end = args.end or datetime.now(UTC).date()
    days = (end - args.start).days + 1
    print(f"EPSS backfill {args.start} .. {end} ({days} days; about 3 MB stored per day, 2 s between downloads).")
    tally: dict[str, int] = {}
    for attempt in backfill(sf, store_from_env(), scope, args.start, end, refetch=args.refetch):
        tally[attempt.outcome] = tally.get(attempt.outcome, 0) + 1
        extra = f" {attempt.rows_stored} tracked scores" if attempt.outcome == "imported" else f" {attempt.message}"
        print(f"  {attempt.score_date} {attempt.outcome}{extra}"[:160])
    print("done: " + (", ".join(f"{k} {v}" for k, v in sorted(tally.items())) or "every day already imported"))
    epss_coverage(sf)
    return 0 if not tally.get("failed") else 2


def epss_coverage(sf) -> None:
    with sf() as s:
        span = s.execute(text("SELECT min(score_date) AS a, max(score_date) AS b, count(DISTINCT score_date) AS n "
                              "FROM epss_collection_runs WHERE outcome = 'imported'")).one()
        if span.n == 0:
            print("No EPSS day imported through the collection log yet.")
            return
        gaps = s.execute(text(
            "SELECT d::date AS day, (SELECT string_agg(DISTINCT r.outcome, '/') FROM epss_collection_runs r "
            " WHERE r.score_date = d::date) AS tried "
            "FROM generate_series(CAST(:a AS date), CAST(:b AS date), interval '1 day') d "
            "WHERE NOT EXISTS (SELECT 1 FROM epss_collection_runs r WHERE r.score_date = d::date "
            "                  AND r.outcome = 'imported') ORDER BY 1"), {"a": span.a, "b": span.b}).all()
    print(f"EPSS history: {span.n} days imported from {span.a} to {span.b}; {len(gaps)} gap days"
          + (": " + ", ".join(f"{g.day} ({g.tried or 'not tried'})" for g in gaps[:15]) if gaps else "."))
    if len(gaps) > 15:
        print(f"  ... and {len(gaps) - 15} more. Gaps are never filled with another day's score.")


def epss_trends(sf, days: int = 30, limit: int = 40) -> None:
    with sf() as s:
        rows = s.execute(text(
            f"WITH own AS (SELECT DISTINCT c.company_key, upper(v) AS cve_id "
            f"  FROM ({LATEST_EXPOSURE}) l CROSS JOIN LATERAL jsonb_array_elements_text(l.potential_vulns) v "
            f"  JOIN companies c ON c.id = l.company_id WHERE l.outcome = 'found' AND l.attribution IN {OWN}), "
            f"w AS (SELECT cve_id, score_date, epss, "
            f"  first_value(epss) OVER (PARTITION BY cve_id ORDER BY score_date) AS first_epss, "
            f"  first_value(score_date) OVER (PARTITION BY cve_id ORDER BY score_date) AS first_day, "
            f"  row_number() OVER (PARTITION BY cve_id ORDER BY score_date DESC) AS rn "
            f"  FROM epss_scores WHERE score_date > (SELECT max(score_date) FROM epss_scores) - :d) "
            f"SELECT w.cve_id, w.first_day, w.first_epss, w.score_date AS last_day, w.epss AS last_epss, "
            f"  w.epss - w.first_epss AS rise, string_agg(DISTINCT own.company_key, ', ') AS companies, "
            f"  k.cve_id IS NOT NULL AS kev "
            f"FROM w JOIN own ON own.cve_id = w.cve_id LEFT JOIN kev_entries k ON k.cve_id = w.cve_id "
            f"WHERE w.rn = 1 AND w.score_date > w.first_day "
            f"GROUP BY w.cve_id, w.first_day, w.first_epss, w.score_date, w.epss, k.cve_id "
            f"ORDER BY rise DESC, w.epss DESC LIMIT :n"), {"d": days, "n": limit}).all()
    if not rows:
        print(f"Not enough EPSS history for trends over {days} days: collect daily or run  epss backfill.")
        return
    print(f"EPSS change over the last {days} days for CVEs on companies' own IPs (biggest rise first):")
    print(f"{'cve':16} {'KEV':4} {'from':10} {'epss':>7} {'to':10} {'epss':>7} {'change':>8}  companies")
    for r in rows:
        print(f"{r.cve_id:16} {'yes' if r.kev else '':4} {r.first_day!s:10} {r.first_epss:>7.4f} {r.last_day!s:10} "
              f"{r.last_epss:>7.4f} {r.rise:>+8.4f}  {r.companies}"[:200])
    print("A rise means FIRST's model sees more exploitation activity likely for the CVE; it is about the CVE, "
          "not the company.")


def epss_history(sf, cve: str) -> None:
    with sf() as s:
        rows = s.execute(text("SELECT score_date, epss, percentile, model_version, corrections FROM epss_scores "
                              "WHERE cve_id = :c ORDER BY score_date"), {"c": cve.upper()}).all()
    if not rows:
        print(f"No EPSS scores stored for {cve.upper()} (not tracked, or no day collected yet).")
        return
    print(f"EPSS history for {cve.upper()} ({len(rows)} days; days not listed were not collected or not published):")
    for r in rows:
        fix = f"  ({len(r.corrections)} earlier value(s) corrected)" if r.corrections else ""
        print(f"  {r.score_date} {r.epss:.5f}  percentile {r.percentile:.4f}  model {r.model_version}{fix}")


def nvd_summary(sf) -> None:
    with sf() as s:
        tracked = sorted(tracked_cves(s))
        rows = s.execute(text("SELECT outcome, vuln_status, count(*) AS n FROM vulnerabilities "
                              "WHERE cve_id = ANY(:c) GROUP BY 1, 2 ORDER BY 3 DESC"), {"c": tracked}).all()
        versions = s.execute(text(
            "SELECT cvss_version, count(DISTINCT vulnerability_id) AS n FROM cvss_scores x "
            "JOIN vulnerabilities v ON v.id = x.vulnerability_id WHERE v.cve_id = ANY(:c) GROUP BY 1 ORDER BY 1"),
            {"c": tracked}).all()
        unscored = s.scalar(text(
            "SELECT count(*) FROM vulnerabilities v WHERE v.cve_id = ANY(:c) AND v.outcome = 'found' "
            "AND NOT EXISTS (SELECT 1 FROM cvss_scores x WHERE x.vulnerability_id = v.id)"), {"c": tracked})
    by_outcome: dict[str, int] = {}
    for r in rows:
        by_outcome[r.outcome] = by_outcome.get(r.outcome, 0) + r.n
    looked = sum(by_outcome.values())
    print(f"NVD records for {len(tracked)} tracked CVEs: {by_outcome.get('found', 0)} found, "
          f"{by_outcome.get('not_found', 0)} not in NVD, {by_outcome.get('lookup_failed', 0)} lookups failed, "
          f"{len(tracked) - looked} not looked up yet.")
    status = ", ".join(f"{r.vuln_status}: {r.n}" for r in rows if r.outcome == "found")
    if status:
        print(f"NVD status: {status}")
    if versions:
        print("CVEs with a CVSS score, by version: " + ", ".join(f"v{r.cvss_version}: {r.n}" for r in versions)
              + f"; found but unscored: {unscored} (kept as unscored, not guessed)")


CLASS_ORDER = {"remote": 0, "local": 1, "needs_user": 2, "unscored": 3, "dos_only": 4}


def priority(sf, limit: int = 300) -> None:
    """Companies' own-IP CVE leads ranked: known-exploited first, then what the CVE lets an attacker
    do (remote data access above user-action bugs above denial of service), then CVSS, then EPSS."""
    from .nvd import impact_class

    with sf() as s:
        rows = s.execute(text(
            f"SELECT c.company_key, x.cve_id, count(DISTINCT x.ip) AS ips, min(x.host) AS host, "
            f"e.epss, k.cve_id IS NOT NULL AS kev, k.known_ransomware_use, "
            f"v.outcome, v.vuln_status, p.cvss_version, p.base_score, p.base_severity, p.vector_string, p.cwes "
            f"FROM (SELECT l.company_id, l.host, l.ip, upper(cv) AS cve_id FROM ({LATEST_EXPOSURE}) l "
            f"      CROSS JOIN LATERAL jsonb_array_elements_text(l.potential_vulns) AS cv "
            f"      WHERE l.outcome = 'found' AND l.attribution IN {OWN}) x "
            f"JOIN companies c ON c.id = x.company_id "
            f"LEFT JOIN latest_epss_scores e ON e.cve_id = x.cve_id "
            f"LEFT JOIN kev_entries k ON k.cve_id = x.cve_id "
            f"LEFT JOIN vulnerabilities v ON v.cve_id = x.cve_id "
            f"LEFT JOIN vulnerability_severity p ON p.cve_id = x.cve_id "
            f"GROUP BY c.company_key, x.cve_id, e.epss, k.cve_id, k.known_ransomware_use, v.outcome, v.vuln_status, "
            f"p.cvss_version, p.base_score, p.base_severity, p.vector_string, p.cwes")).all()
    if not rows:
        print("No CVEs inferred on companies' own IPs (or exposure collect has not run yet).")
        return
    leads = []
    for r in rows:
        kind = impact_class(r.vector_string)
        if r.vuln_status == "Rejected":
            kind = "rejected"
        leads.append((r, kind))
    leads.sort(key=lambda x: (not x[0].kev, CLASS_ORDER.get(x[1], 5), -(x[0].base_score or -1), -(x[0].epss or -1),
                              x[0].company_key))
    no_nvd = sum(1 for r, _ in leads if r.outcome != "found")
    per: dict[str, dict] = {}
    for r, kind in leads:
        p = per.setdefault(r.company_key, {"kev": 0, "critical": 0, "high": 0, "cves": 0, "epss": 0.0})
        p["cves"] += 1
        p["kev"] += bool(r.kev)
        if kind == "remote" and r.base_score is not None and r.base_score >= 7:
            p["critical" if r.base_score >= 9 else "high"] += 1
        p["epss"] = max(p["epss"], float(r.epss or 0))
    print(f"{'company':36} {'CVEs':>5} {'KEV':>4} {'remote crit':>11} {'remote high':>11} {'max epss':>8}")
    for key, p in sorted(per.items(), key=lambda kv: (-kv[1]["kev"], -kv[1]["critical"], -kv[1]["high"], kv[0])):
        print(f"{key:36} {p['cves']:>5} {p['kev']:>4} {p['critical']:>11} {p['high']:>11} {p['epss']:>8.4f}")
    print(f"\nTop {min(limit, len(leads))} of {len(leads)} company/CVE leads, ranked:")
    print(f"{'company':28} {'cve':16} {'KEV':4} {'kind':10} {'cvss':10} {'sev':8} {'epss':>6}  {'cwe':14} host")
    for r, kind in leads[:limit]:
        cvss = f"v{r.cvss_version} {r.base_score}" if r.base_score is not None else ("no NVD" if r.outcome != "found"
                                                                                    else "unscored")
        epss = f"{r.epss:.3f}" if r.epss is not None else "?"
        kev = ("KEV*" if r.known_ransomware_use == "Known" else "KEV") if r.kev else ""
        cwe = ",".join(r.cwes or [])[:14]
        print(f"{r.company_key[:28]:28} {r.cve_id:16} {kev:4} {kind:10} {cvss:10} {(r.base_severity or '')[:8]:8} "
              f"{epss:>6}  {cwe:14} {r.host[:40]}")
    if no_nvd:
        print(f"\n{no_nvd} leads have no NVD record yet: run  python -m cyber_risk_intelligence.vulnerabilities nvd collect")
    print("KEV* = known ransomware use. kind (from the CVSS vector): remote = over the network, no user action, can read "
          "or change data; local = needs local access; needs_user = someone must click/open something; dos_only = can "
          "only slow or stop a service. CVSS shows its version; scores of different versions are not merged. "
          "All CVEs are Shodan's inference from software versions: questions for the company, not confirmed findings.")


def _collect_nvd(sf, args) -> int:
    from .nvd import NvdJob, targets_csv

    with sf() as s:
        content = targets_csv(s, refresh_days=args.refresh_days, limit=args.limit)
    todo = content.count(b"\n") - 1
    if todo <= 0:
        print("Every tracked CVE has a recent NVD record; nothing to look up.")
        nvd_summary(sf)
        return 0
    job = NvdJob(store_from_env())
    minutes = max(1, round(todo * job.client.pause / 60))
    keyed = "with" if job.client.api_key else "without"
    print(f"Looking up {todo} CVEs in NVD {keyed} an API key (about {minutes} min; exposure CVEs first). "
          f"Progress is saved every 50 CVEs; if stopped, run again to continue.")
    if not job.client.api_key and todo > 100:
        print("Tip: a free NVD API key (NVD_API_KEY in .env) makes this about 10 times faster.")
    try:
        r = run_import(sf, store_from_env(), job, content, source_url="db:tracked_cves")
    except IngestionFailed as exc:
        from .nvd import NvdKeyRejected

        if isinstance(exc.__cause__, NvdKeyRejected):
            print(f"{exc.__cause__}. Nothing was recorded for the CVEs. A new key works only after you click the "
                  "activation link in NVD's email; check NVD_API_KEY in .env for a typo, or remove that line to "
                  "run without a key (slower).")
        else:
            print(f"{exc}. See ingestion_errors (run_id = {exc.run_id}).")
        return 2
    print(f"run {r.id} {r.status}: {r.rows_seen} CVEs, {job.tally['found']} found, {job.tally['not_found']} not in NVD, "
          f"{job.tally['lookup_failed']} lookups failed (retried next run); {r.rows_inserted} new, "
          f"{r.rows_updated} changed, {r.rows_unchanged} unchanged")
    nvd_summary(sf)
    return 0 if r.status == "succeeded" else 2


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m cyber_risk_intelligence.vulnerabilities")
    p.add_argument("dataset", choices=("kev", "epss", "nvd", "priority"))
    p.add_argument("command", nargs="?", choices=("collect", "summary", "changes", "backfill", "trends", "history"),
                   default="summary")
    p.add_argument("--from", dest="start", type=date.fromisoformat, help="epss backfill: first day")
    p.add_argument("--to", dest="end", type=date.fromisoformat, help="epss backfill: last day (default: today)")
    p.add_argument("--refetch", action="store_true", help="epss backfill: also days already imported")
    p.add_argument("--cve", help="epss history: the CVE")
    p.add_argument("--days", type=int, default=30, help="kev changes: how far back to list")
    p.add_argument("--file", type=Path, help="kev/epss collect: import a saved copy instead of downloading it")
    p.add_argument("--date", type=date.fromisoformat, help="epss collect: the scoring day (default: latest)")
    p.add_argument("--all", action="store_true",
                   help="epss collect: store every CVE's score, not only the tracked ones (about 400k rows)")
    p.add_argument("--refresh-days", type=int, default=30, help="nvd collect: look up again records older than this")
    p.add_argument("--limit", type=int, help="nvd collect: at most this many CVEs this run")
    args = p.parse_args(argv)
    sf = make_session_factory(make_engine())
    if args.dataset == "priority":
        priority(sf)
        return 0
    if args.command == "changes":
        if args.dataset != "kev":
            p.error("changes is only for kev")
        kev_changes(sf, args.days)
        return 0
    if args.command in ("backfill", "trends", "history"):
        if args.dataset != "epss":
            p.error(f"{args.command} is only for epss")
        if args.command == "backfill":
            return _backfill_epss(sf, args)
        if args.command == "trends":
            epss_trends(sf, args.days)
        elif not args.cve:
            p.error("epss history needs --cve")
        else:
            epss_history(sf, args.cve)
        return 0
    if args.command == "summary":
        {"kev": kev_summary, "epss": epss_summary, "nvd": nvd_summary}[args.dataset](sf)
        return 0
    return {"kev": _collect_kev, "epss": _collect_epss, "nvd": _collect_nvd}[args.dataset](sf, args)


if __name__ == "__main__":
    sys.exit(main())
