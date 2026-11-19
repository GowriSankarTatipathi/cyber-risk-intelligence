"""Command line for issue 23.1.

    python -m cyber_risk_intelligence.email_security spf       # look up SPF for every known company domain
    python -m cyber_risk_intelligence.email_security targets   # print the company_key,domain list it uses
    python -m cyber_risk_intelligence.email_security summary   # latest SPF result per domain

Load domains first:  python -m cyber_risk_intelligence.ingest run company-domains company_domains.csv
"""

import argparse
import sys
from collections import Counter

from sqlalchemy import text

from ..db import make_engine, make_session_factory
from ..evidence import store_from_env
from ..ingest import run_import
from .job import SpfJob, targets_csv


def summary(sf) -> None:
    with sf() as s:
        rows = s.execute(text(
            "SELECT c.company_key, d.name, o.status, coalesce(o.all_qualifier, '') AS q, "
            "coalesce(o.dns_lookup_terms::text, '') AS n, coalesce(jsonb_array_length(o.problems), 0) AS p "
            "FROM latest_spf_observations o JOIN domains d ON d.id = o.domain_id "
            "LEFT JOIN companies c ON c.id = o.company_id ORDER BY c.company_key, d.name")).all()
    print(f"{'company':28} {'domain':32} {'status':14} {'all':9} lookups problems")
    for r in rows:
        print(f"{r.company_key or '':28} {r.name:32} {r.status:14} {r.q:9} {r.n:7} {r.p}")
    print(", ".join(f"{k}: {v}" for k, v in Counter(r.status for r in rows).most_common()) or "no SPF lookups yet")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m cyber_risk_intelligence.email_security")
    p.add_argument("command", choices=("spf", "targets", "summary"))
    args = p.parse_args(argv)
    sf = make_session_factory(make_engine())
    if args.command == "summary":
        summary(sf)
        return 0
    with sf() as s:
        content = targets_csv(s)
    if args.command == "targets":
        sys.stdout.write(content.decode())
        return 0
    if content.count(b"\n") <= 1:
        print("no company domains yet; import them with: ingest run company-domains <file.csv>", file=sys.stderr)
        return 1
    store = store_from_env()
    r = run_import(sf, store, SpfJob(store), content, source_url="db:company_domains")
    print(f"run {r.id} {r.status}: {r.rows_seen} domains, {r.rows_inserted} new answers, "
          f"{r.rows_unchanged} same as last time, {r.rows_rejected} rejected")
    summary(sf)
    return 0 if r.status == "succeeded" else 2


if __name__ == "__main__":
    sys.exit(main())
