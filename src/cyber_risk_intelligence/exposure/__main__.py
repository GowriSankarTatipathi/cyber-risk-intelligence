"""Command line for issue 10.3.

    python -m cyber_risk_intelligence.exposure collect   # Shodan InternetDB for every known company host
    python -m cyber_risk_intelligence.exposure summary   # per company: IPs, attribution, ports, potential CVEs

Only IPs that aren't CDN or shared hosting say something about the company; the summary keeps
those apart. Ports and CVEs are what Shodan indexed (no scan date), not verified findings.
"""

import argparse
import sys
from collections import Counter

from sqlalchemy import text

from ..db import make_engine, make_session_factory
from ..email_security.job import targets_csv
from ..evidence import store_from_env
from ..ingest import run_import
from .job import IndexedExposureJob

LATEST = ("WITH l AS (SELECT x.*, max(x.ingestion_run_id) OVER (PARTITION BY x.domain_id) AS last_run "
          "FROM indexed_host_lookups x) SELECT * FROM l WHERE ingestion_run_id IS NOT DISTINCT FROM last_run")


def summary(sf) -> None:
    with sf() as s:
        rows = s.execute(text(
            f"SELECT c.company_key, l.outcome, l.attribution, host(l.ip) AS ip, "
            f"coalesce(jsonb_array_length(l.potential_vulns), 0) AS vulns, "
            f"(SELECT string_agg(o.port || coalesce('/' || o.service_hint, ''), ' ' ORDER BY o.port) "
            f" FROM indexed_service_observations o WHERE o.lookup_id = l.id AND o.sensitive) AS sensitive "
            f"FROM ({LATEST}) l JOIN companies c ON c.id = l.company_id ORDER BY c.company_key, l.host")).all()
    per: dict[str, dict] = {}
    for r in rows:
        p = per.setdefault(r.company_key, {"ips": set(), "attr": Counter(), "failed": 0, "vulns": 0, "sensitive": set()})
        if r.outcome in ("dns_failed", "lookup_failed"):
            p["failed"] += 1
        if r.ip:
            p["ips"].add(r.ip)
        if r.attribution:
            p["attr"][r.attribution] += 1
        if r.attribution in ("company_only", "unknown"):
            p["vulns"] = max(p["vulns"], r.vulns)
            if r.sensitive:
                p["sensitive"].update(f"{r.ip}:{x}" for x in r.sensitive.split())
    print(f"{'company':36} {'IPs':>4} {'cdn':>4} {'shared':>6} {'own?':>5} {'failed':>6} {'CVEs*':>5}  sensitive ports*")
    for key, p in per.items():
        own = p["attr"]["company_only"] + p["attr"]["unknown"]
        print(f"{key:36} {len(p['ips']):>4} {p['attr']['cdn']:>4} {p['attr']['shared']:>6} {own:>5} {p['failed']:>6} "
              f"{p['vulns']:>5}  {' '.join(sorted(p['sensitive']))[:70]}")
    tally = Counter(r.attribution or r.outcome for r in rows)
    print(", ".join(f"{k}: {v}" for k, v in tally.most_common()) or "no lookups yet")
    print("* only IPs that are not a CDN or shared host (own? = company_only or no host name known). "
          "Indexed by Shodan, not verified; CVEs are inferred from software versions.")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m cyber_risk_intelligence.exposure")
    p.add_argument("command", choices=("collect", "summary"))
    args = p.parse_args(argv)
    sf = make_session_factory(make_engine())
    if args.command == "summary":
        summary(sf)
        return 0
    with sf() as s:
        content = targets_csv(s)
    store = store_from_env()
    r = run_import(sf, store, IndexedExposureJob(store), content, source_url="db:company_domains")
    print(f"run {r.id} {r.status}: {r.rows_seen} domains, {r.rows_inserted} with new records, "
          f"{r.rows_unchanged} same as last time, {r.rows_updated} with failed lookups, {r.rows_rejected} rejected")
    summary(sf)
    return 0 if r.status == "succeeded" else 2


if __name__ == "__main__":
    sys.exit(main())
