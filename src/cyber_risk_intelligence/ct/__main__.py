"""Command line for issue 10.1.

    python -m cyber_risk_intelligence.ct collect    # search CT logs for every known company domain
    python -m cyber_risk_intelligence.ct targets    # print the company_key,domain list it uses
    python -m cyber_risk_intelligence.ct summary    # per company domain: latest search, certificates, hostnames
    python -m cyber_risk_intelligence.ct website    # the certificate each company website presents (domain and www.)

Or run on your own list:  python -m cyber_risk_intelligence.ingest run ct targets.csv
Cert Spotter answers 100 certificates per page in well under a second; crt.sh is the fallback.
``collect`` goes in two passes: every domain that can be answered without waiting for a rate limit
first, then the ones left over (the big ones), which wait for Cert Spotter and carry on where they stopped.
"""

import argparse
import csv
import io
import sys
from collections import Counter

from sqlalchemy import text

from ..db import make_engine, make_session_factory
from ..evidence import store_from_env
from ..ingest import run_import
from .job import CtJob, targets_csv
from .website import WebsiteCertificateJob


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


def website_summary(sf) -> None:
    with sf() as s:
        rows = s.execute(text(
            "SELECT c.company_key, w.host, w.outcome, coalesce(w.message, '') AS msg, "
            "coalesce(replace(substring(w.issuer_name from 'O=((?:\\\\,|[^,])+)'), '\\', ''), w.issuer_name, '') "
            "AS issuer, "
            "w.not_after::date AS expires, (w.not_after::date - current_date) AS days_left "
            "FROM latest_website_certificates w JOIN company_domains cd ON cd.domain_id = w.domain_id "
            "AND cd.valid_to IS NULL JOIN companies c ON c.id = cd.company_id "
            # only hosts asked in the domain's latest run, so a host no longer asked drops out
            "WHERE w.ingestion_run_id IS NOT DISTINCT FROM (SELECT max(x.ingestion_run_id) "
            "FROM website_certificate_checks x WHERE x.domain_id = w.domain_id) "
            "ORDER BY c.company_key, w.host")).all()
    print(f"{'company':32} {'host':34} {'outcome':12} {'issuer':28} {'expires':10} {'days':>5}")
    for r in rows:
        print(f"{r.company_key:32} {r.host:34} {r.outcome:12} {r.issuer[:28]:28} {r.expires or ''!s:10} "
              f"{'' if r.days_left is None else r.days_left:>5} {r.msg[:50]}")
    print(", ".join(f"{k}: {v}" for k, v in Counter(r.outcome for r in rows).most_common()) or "no website checks yet")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m cyber_risk_intelligence.ct")
    p.add_argument("command", choices=("collect", "targets", "summary", "website", "website-summary"))
    args = p.parse_args(argv)
    sf = make_session_factory(make_engine())
    if args.command == "targets":
        with sf() as s:
            sys.stdout.write(targets_csv(s).decode())
        return 0
    if args.command == "summary":
        summary(sf)
        return 0
    if args.command == "website-summary":
        website_summary(sf)
        return 0
    store = store_from_env()
    with sf() as s:
        content = targets_csv(s)
    if args.command == "website":
        r = run_import(sf, store, WebsiteCertificateJob(store), content, source_url="db:company_domains")
        print(f"run {r.id} {r.status}: {r.rows_seen} domains, {r.rows_inserted} with a new certificate, "
              f"{r.rows_unchanged} same as last time, {r.rows_updated} unreachable, {r.rows_rejected} rejected")
        website_summary(sf)
        return 0 if r.status == "succeeded" else 2
    quick = CtJob(store, defer=True)
    r = run_import(sf, store, quick, content, source_url="db:company_domains")
    report(r, len(quick.deferred))
    ok = r.status == "succeeded"
    if quick.deferred:
        print(f"now the {len(quick.deferred)} domains left for later: "
              + ", ".join(d for _, d in quick.deferred))
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["company_key", "domain"])
        w.writerows(quick.deferred)
        r = run_import(sf, store, CtJob(store, clients=quick.clients), buf.getvalue().encode(),
                       source_url="db:company_domains (deferred)")
        report(r, 0)
        ok = ok and r.status == "succeeded"
    summary(sf)
    return 0 if ok else 2


def report(r, deferred: int) -> None:
    print(f"run {r.id} {r.status}: {r.rows_seen} domains, {r.rows_inserted} with new certificates, "
          f"{r.rows_unchanged - deferred} unchanged, {r.rows_updated} failed lookups, {r.rows_rejected} rejected"
          + (f", {deferred} left for later" if deferred else ""))


if __name__ == "__main__":
    sys.exit(main())
