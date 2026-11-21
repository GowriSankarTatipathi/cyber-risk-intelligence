"""Command line for issue 5.

    python -m cyber_risk_intelligence.vulnerabilities kev collect [--file catalog.json]
        # download CISA's KEV catalog (or import a saved copy) into kev_entries
    python -m cyber_risk_intelligence.vulnerabilities kev summary
        # the catalog we hold, and which CVEs Shodan inferred on companies' own IPs are in KEV
    python -m cyber_risk_intelligence.vulnerabilities epss collect [--date 2026-11-20] [--file f.csv.gz] [--all]
        # FIRST EPSS scores for the day, stored for the tracked CVEs (exposure CVEs + KEV)
    python -m cyber_risk_intelligence.vulnerabilities epss summary
        # companies' own-IP CVE leads, known-exploited first, then by EPSS

An EPSS score is about the CVE, not a company: never a company's probability of loss.

A CVE Shodan inferred from a software version is a lead, not a confirmed vulnerability, and KEV only
says the CVE was exploited somewhere. A match means "ask about this", not "this company is breached".
"""

import argparse
import sys
from datetime import date
from pathlib import Path

from sqlalchemy import text

from ..db import make_engine, make_session_factory
from ..evidence import store_from_env
from ..ingest import run_import
from ..ingest.framework import IngestionFailed
from .epss import EpssClient, EpssJob, EpssUnavailable, tracked_cves
from .kev import KEV_URL, KevClient, KevJob, KevUnavailable

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
    print(f"run {r.id} {r.status}: catalog {job.catalog.get('catalog_version')}, {r.rows_seen} entries, "
          f"{r.rows_inserted} new, {r.rows_updated} changed, {r.rows_unchanged} unchanged, {r.rows_rejected} rejected")
    if r.rows_rejected:
        print(f"Rejected entries are in ingestion_errors (run_id = {r.id}).")
    kev_summary(sf)
    return 0 if r.status == "succeeded" else 2


def _collect_epss(sf, args) -> int:
    with sf() as s:
        scope = None if args.all else tracked_cves(s)
    if scope is not None and not scope:
        print("No CVEs to track yet: run  exposure collect  and/or  vulnerabilities kev collect  first "
              "(or pass --all to store every CVE's score).")
        return 2
    if args.file:
        content, url = args.file.read_bytes(), args.file.resolve().as_uri()
    else:
        try:
            url, content = EpssClient().fetch(args.date)
        except EpssUnavailable as exc:
            print(f"{exc}. Nothing was imported; stored scores are unchanged.")
            return 2
    job = EpssJob(scope)
    r = _import(sf, job, content, url)
    if r is None:
        return 2
    print(f"run {r.id} {r.status}: EPSS {job.score_date} (model {job.model_version}), {job.rows_in_file} CVEs in the "
          f"file, {r.rows_seen} tracked: {r.rows_inserted} new, {r.rows_updated} changed, {r.rows_unchanged} unchanged, "
          f"{r.rows_rejected} rejected")
    epss_summary(sf)
    return 0 if r.status == "succeeded" else 2


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m cyber_risk_intelligence.vulnerabilities")
    p.add_argument("dataset", choices=("kev", "epss"))
    p.add_argument("command", choices=("collect", "summary"))
    p.add_argument("--file", type=Path, help="collect: import a saved copy instead of downloading it")
    p.add_argument("--date", type=date.fromisoformat, help="epss collect: the scoring day (default: latest)")
    p.add_argument("--all", action="store_true",
                   help="epss collect: store every CVE's score, not only the tracked ones (about 400k rows)")
    args = p.parse_args(argv)
    sf = make_session_factory(make_engine())
    if args.command == "summary":
        (kev_summary if args.dataset == "kev" else epss_summary)(sf)
        return 0
    return (_collect_kev if args.dataset == "kev" else _collect_epss)(sf, args)


if __name__ == "__main__":
    sys.exit(main())
