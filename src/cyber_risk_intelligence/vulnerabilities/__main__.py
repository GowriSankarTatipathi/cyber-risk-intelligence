"""Command line for issue 5.

    python -m cyber_risk_intelligence.vulnerabilities kev collect [--file catalog.json]
        # download CISA's KEV catalog (or import a saved copy) into kev_entries
    python -m cyber_risk_intelligence.vulnerabilities kev summary
        # the catalog we hold, and which CVEs Shodan inferred on companies' own IPs are in KEV

A CVE Shodan inferred from a software version is a lead, not a confirmed vulnerability, and KEV only
says the CVE was exploited somewhere. A match means "ask about this", not "this company is breached".
"""

import argparse
import sys
from pathlib import Path

from sqlalchemy import text

from ..db import make_engine, make_session_factory
from ..evidence import store_from_env
from ..ingest import run_import
from ..ingest.framework import IngestionFailed
from .kev import KEV_URL, KevClient, KevJob, KevUnavailable

OWN = "('company_only', 'unknown')"


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


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m cyber_risk_intelligence.vulnerabilities")
    p.add_argument("dataset", choices=("kev",))
    p.add_argument("command", choices=("collect", "summary"))
    p.add_argument("--file", type=Path, help="collect: import a saved copy of the catalog instead of downloading it")
    args = p.parse_args(argv)
    sf = make_session_factory(make_engine())
    if args.command == "summary":
        kev_summary(sf)
        return 0
    if args.file:
        content, url = args.file.read_bytes(), args.file.resolve().as_uri()
    else:
        try:
            content, url = KevClient().fetch(), KEV_URL
        except KevUnavailable as exc:
            print(f"{exc}. Nothing was imported; the catalog already stored is unchanged.")
            return 2
    store = store_from_env()
    job = KevJob()
    try:
        r = run_import(sf, store, job, content, source_url=url)
    except IngestionFailed as exc:
        print(f"{exc}. See ingestion_errors (run_id = {exc.run_id}).")
        return 2
    print(f"run {r.id} {r.status}: catalog {job.catalog.get('catalog_version')}, {r.rows_seen} entries, "
          f"{r.rows_inserted} new, {r.rows_updated} changed, {r.rows_unchanged} unchanged, {r.rows_rejected} rejected")
    if r.rows_rejected:
        print(f"Rejected entries are in ingestion_errors (run_id = {r.id}).")
    kev_summary(sf)
    return 0 if r.status == "succeeded" else 2


if __name__ == "__main__":
    sys.exit(main())
