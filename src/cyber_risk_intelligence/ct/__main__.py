"""Command line for issue 10.1.

    python -m cyber_risk_intelligence.ct collect    # search CT logs for every known company domain
    python -m cyber_risk_intelligence.ct targets    # print the company_key,domain list it uses
    python -m cyber_risk_intelligence.ct summary    # per company domain: latest search, certificates, hostnames

Or run on your own list:  python -m cyber_risk_intelligence.ingest run ct targets.csv
Cert Spotter answers 100 certificates per page in well under a second; crt.sh is the fallback.
"""

import argparse
import sys
from collections import Counter

from sqlalchemy import text

from ..db import make_engine, make_session_factory
from ..evidence import store_from_env
from ..ingest import run_import
from .job import CtJob, targets_csv


def summary(sf) -> None:
    with sf() as s:
        rows = s.execute(text(
            "SELECT c.company_key, d.name, l.outcome, coalesce(l.certificate_count::text, '') AS certs, "
            "(SELECT count(DISTINCT h.hostname) FILTER (WHERE NOT h.is_wildcard) FROM company_certificate_hostnames h "
            " WHERE h.domain_id = d.id) AS hosts, "
            "(SELECT count(DISTINCT h.hostname) FILTER (WHERE h.is_wildcard) FROM company_certificate_hostnames h "
            " WHERE h.domain_id = d.id) AS wild, coalesce(l.message, '') AS msg "
            "FROM latest_ct_lookups l JOIN domains d ON d.id = l.domain_id "
            "JOIN company_domains cd ON cd.domain_id = d.id AND cd.valid_to IS NULL "
            "JOIN companies c ON c.id = cd.company_id ORDER BY c.company_key, d.name")).all()
    print(f"{'company':32} {'domain':30} {'outcome':14} {'certs':>6} {'hostnames':>9} {'wildcards':>9}")
    for r in rows:
        print(f"{r.company_key:32} {r.name:30} {r.outcome:14} {r.certs:>6} {r.hosts:9} {r.wild:9} {r.msg[:60]}")
    print(", ".join(f"{k}: {v}" for k, v in Counter(r.outcome for r in rows).most_common()) or "no CT lookups yet")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m cyber_risk_intelligence.ct")
    p.add_argument("command", choices=("collect", "targets", "summary"))
    args = p.parse_args(argv)
    sf = make_session_factory(make_engine())
    if args.command == "targets":
        with sf() as s:
            sys.stdout.write(targets_csv(s).decode())
        return 0
    if args.command == "summary":
        summary(sf)
        return 0
    store = store_from_env()
    with sf() as s:
        content = targets_csv(s)
    r = run_import(sf, store, CtJob(store), content, source_url="db:company_domains")
    print(f"run {r.id} {r.status}: {r.rows_seen} domains, {r.rows_inserted} with new certificates, "
          f"{r.rows_unchanged} unchanged, {r.rows_updated} failed lookups, {r.rows_rejected} rejected")
    summary(sf)
    return 0 if r.status == "succeeded" else 2


if __name__ == "__main__":
    sys.exit(main())
