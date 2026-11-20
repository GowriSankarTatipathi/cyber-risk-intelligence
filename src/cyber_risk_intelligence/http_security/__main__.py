"""Command line for issue 1.2.

    python -m cyber_risk_intelligence.http_security collect   # check every known company website
    python -m cyber_risk_intelligence.http_security summary   # per host: HTTPS redirect and header results
    python -m cyber_risk_intelligence.http_security targets   # print the company_key,domain list it uses
"""

import argparse
import sys
from collections import Counter

from sqlalchemy import text

from ..db import make_engine, make_session_factory
from ..email_security.job import targets_csv
from ..evidence import store_from_env
from ..ingest import run_import
from .assess import GRADED
from .job import HttpSecurityJob

_SHORT = {"strict-transport-security": "HSTS", "content-security-policy": "CSP", "x-frame-options": "XFO",
          "x-content-type-options": "XCTO", "referrer-policy": "Referrer"}


def summary(sf) -> None:
    with sf() as s:
        checks = s.execute(text(
            "SELECT c.company_key, k.id, k.host, k.outcome, k.http_redirect, coalesce(k.message, '') AS msg "
            "FROM latest_http_security_checks k JOIN company_domains cd ON cd.domain_id = k.domain_id "
            "AND cd.valid_to IS NULL JOIN companies c ON c.id = cd.company_id "
            "WHERE k.ingestion_run_id IS NOT DISTINCT FROM (SELECT max(x.ingestion_run_id) "
            "FROM http_security_checks x WHERE x.domain_id = k.domain_id) "
            "ORDER BY c.company_key, k.host")).all()
        results = {}
        for check_id, header, result in s.execute(text(
                "SELECT o.check_id, o.header, o.result FROM http_security_observations o "
                "WHERE o.check_id IN (SELECT id FROM latest_http_security_checks)")):
            results[(check_id, header)] = result
    print(f"{'company':32} {'host':30} {'http->https':12} " + " ".join(f"{_SHORT[h]:9}" for h in GRADED))
    tally: Counter = Counter()
    for r in checks:
        if r.outcome != "answered":
            print(f"{r.company_key:32} {r.host:30} {'':12} request failed: {r.msg[:60]}")
            tally["request_failed"] += 1
            continue
        redirect = {"redirects_to_https": "yes", "no_redirect": "NO", "redirects_elsewhere": "other",
                    "request_failed": "?"}[r.http_redirect]
        cells = [results.get((r.id, h), "?") for h in GRADED]
        tally.update(f"{_SHORT[h]} {c}" for h, c in zip(GRADED, cells, strict=True))
        print(f"{r.company_key:32} {r.host:30} {redirect:12} " + " ".join(f"{c:9}" for c in cells))
    print(", ".join(f"{k}: {v}" for k, v in sorted(tally.items())) or "no header checks yet")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m cyber_risk_intelligence.http_security")
    p.add_argument("command", choices=("collect", "summary", "targets"))
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
    store = store_from_env()
    r = run_import(sf, store, HttpSecurityJob(store), content, source_url="db:company_domains")
    print(f"run {r.id} {r.status}: {r.rows_seen} domains, {r.rows_inserted} with new header evidence, "
          f"{r.rows_unchanged} same as last time, {r.rows_updated} unreachable, {r.rows_rejected} rejected")
    summary(sf)
    return 0 if r.status == "succeeded" else 2


if __name__ == "__main__":
    sys.exit(main())
