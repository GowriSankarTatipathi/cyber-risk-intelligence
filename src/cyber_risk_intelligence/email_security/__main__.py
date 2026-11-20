"""Command line for issues 23.1, 23.2, 23.3 and 23.4.

    python -m cyber_risk_intelligence.email_security spf       # look up SPF for every known company domain
    python -m cyber_risk_intelligence.email_security dmarc     # look up DMARC for every known company domain
    python -m cyber_risk_intelligence.email_security dkim [--selectors published.csv]
        # DKIM keys at selectors known from public evidence (SPF-named providers, plus the CSV:
        # company_key,domain,selector,source_url)
    python -m cyber_risk_intelligence.email_security mta-sts   # MTA-STS record + policy file, TLS reporting record
    python -m cyber_risk_intelligence.email_security targets   # print the company_key,domain list they use
    python -m cyber_risk_intelligence.email_security summary [spf|dmarc|dkim|mta-sts]   # latest result per domain

Load domains first:  python -m cyber_risk_intelligence.ingest run company-domains company_domains.csv
"""

import argparse
import csv
import sys
from collections import Counter

from sqlalchemy import text

from ..db import make_engine, make_session_factory
from ..evidence import store_from_env
from ..ingest import run_import
from .dkim import KnownSelector
from .job import DkimJob, DmarcJob, MtaStsJob, SpfJob, targets_csv


def spf_summary(sf) -> None:
    with sf() as s:
        rows = s.execute(text(
            "SELECT c.company_key, d.name, o.status, coalesce(o.all_qualifier, '') AS q, "
            "coalesce(o.dns_lookup_terms::text, '') AS n, coalesce(jsonb_array_length(o.problems), 0) AS p "
            "FROM latest_spf_observations o JOIN domains d ON d.id = o.domain_id "
            "LEFT JOIN companies c ON c.id = o.company_id ORDER BY c.company_key, d.name")).all()
    print(f"{'company':36} {'domain':32} {'status':14} {'all':9} lookups problems")
    for r in rows:
        print(f"{r.company_key or '':36} {r.name:32} {r.status:14} {r.q:9} {r.n:7} {r.p}")
    print(", ".join(f"{k}: {v}" for k, v in Counter(r.status for r in rows).most_common()) or "no SPF lookups yet")


def dmarc_summary(sf) -> None:
    with sf() as s:
        rows = s.execute(text(
            "SELECT c.company_key, d.name, o.status, coalesce(o.dmarc_policy, '') AS p, "
            "coalesce(o.dmarc_subdomain_policy, '') AS sp, coalesce(o.dmarc_pct::text, '') AS pct, "
            "coalesce(left(o.dkim_alignment, 1) || '/' || left(o.spf_alignment, 1), '') AS al, "
            "CASE o.policy_source WHEN 'organizational_domain' THEN 'inherited' ELSE '' END AS src, "
            "coalesce(jsonb_array_length(o.aggregate_report_uris), 0) AS rua "
            "FROM latest_dmarc_observations o JOIN domains d ON d.id = o.domain_id "
            "LEFT JOIN companies c ON c.id = o.company_id ORDER BY c.company_key, d.name")).all()
    print(f"{'company':36} {'domain':32} {'status':14} {'policy':11} {'subdomain':11} pct  dkim/spf rua from")
    for r in rows:
        print(f"{r.company_key or '':36} {r.name:32} {r.status:14} {r.p:11} {r.sp:11} {r.pct:4} {r.al:8} "
              f"{r.rua:3} {r.src}")
    print(", ".join(f"{k}: {v}" for k, v in Counter(r.status for r in rows).most_common()) or "no DMARC lookups yet")
    print(", ".join(f"p={k}: {v}" for k, v in Counter(r.p for r in rows if r.p).most_common()))


def dkim_summary(sf) -> None:
    with sf() as s:
        rows = s.execute(text(
            "WITH latest AS (SELECT e.*, max(e.ingestion_run_id) OVER (PARTITION BY e.domain_id) AS last_run "
            "FROM dkim_evidence e) "
            "SELECT c.company_key, d.name, coalesce(l.selector, '') AS sel, l.outcome, "
            "coalesce(l.key_type || ' ' || l.key_bits, '') AS key, coalesce(l.problem, '') AS problem, "
            "coalesce(substring(l.selector_evidence from 'authorizes ([^(]+) \\('), "
            "CASE l.selector_source WHEN 'published' THEN 'published' END, '') AS via "
            "FROM latest l JOIN domains d ON d.id = l.domain_id LEFT JOIN companies c ON c.id = l.company_id "
            "WHERE l.ingestion_run_id IS NOT DISTINCT FROM l.last_run ORDER BY c.company_key, d.name, l.selector")).all()
    print(f"{'company':36} {'domain':30} {'selector':12} {'outcome':18} {'key':10} via")
    for r in rows:
        print(f"{r.company_key or '':36} {r.name:30} {r.sel:12} {r.outcome:18} {r.key:10} {r.via.strip()} {r.problem[:50]}")
    domains: dict = {}
    for r in rows:
        domains.setdefault(r.name, set()).add(r.outcome)
    status = Counter("key found" if "key_found" in o else "no known selector" if o == {"no_known_selector"}
                     else "unknown (no key at known selectors)" for o in domains.values())
    print(", ".join(f"{k}: {v}" for k, v in status.most_common()) or "no DKIM lookups yet")


def mta_sts_summary(sf) -> None:
    with sf() as s:
        rows = s.execute(text(
            "WITH m AS (SELECT o.*, row_number() OVER (PARTITION BY o.domain_id ORDER BY o.id DESC) AS n "
            "FROM mta_sts_observations o), t AS (SELECT o.*, row_number() OVER (PARTITION BY o.domain_id "
            "ORDER BY o.id DESC) AS n FROM tls_reporting_observations o) "
            "SELECT c.company_key, d.name, m.dns_status, m.policy_retrieval, coalesce(m.policy_status, '') AS ps, "
            "coalesce(m.mode, '') AS mode, coalesce(t.status, '') AS rpt, "
            "coalesce(m.problems ->> 0, m.message, '') AS problem "
            "FROM m JOIN domains d ON d.id = m.domain_id LEFT JOIN companies c ON c.id = m.company_id "
            "LEFT JOIN t ON t.domain_id = m.domain_id AND t.n = 1 WHERE m.n = 1 ORDER BY c.company_key, d.name")).all()
    print(f"{'company':36} {'domain':30} {'sts record':13} {'policy fetch':20} {'policy':8} {'mode':8} tls-rpt")
    for r in rows:
        print(f"{r.company_key or '':36} {r.name:30} {r.dns_status:13} {r.policy_retrieval:20} {r.ps:8} {r.mode:8} "
              f"{r.rpt:13} {r.problem[:50]}")
    modes = Counter(r.mode for r in rows if r.ps == "valid")
    print(", ".join(f"record {k}: {v}" for k, v in Counter(r.dns_status for r in rows).most_common())
          or "no MTA-STS lookups yet")
    print(", ".join(f"valid policy mode={k}: {v}" for k, v in modes.most_common()))
    print(", ".join(f"tls-rpt {k}: {v}" for k, v in Counter(r.rpt for r in rows).most_common()))


def published_selectors(path: str) -> dict[tuple[str, str], list[KnownSelector]]:
    """company_key,domain,selector,source_url rows: selectors seen in public sources."""
    out: dict[tuple[str, str], list[KnownSelector]] = {}
    with open(path, newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            if not (row.get("selector") and row.get("source_url")):
                continue  # a selector without a public source is not used
            key = (row["company_key"].strip(), row["domain"].strip().lower())
            out.setdefault(key, []).append(KnownSelector(row["selector"].strip(), "published",
                                                         f"published at {row['source_url'].strip()}",
                                                         row["source_url"].strip()))
    return out


JOBS = {"spf": (SpfJob, spf_summary), "dmarc": (DmarcJob, dmarc_summary), "dkim": (DkimJob, dkim_summary),
        "mta-sts": (MtaStsJob, mta_sts_summary)}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m cyber_risk_intelligence.email_security")
    p.add_argument("command", choices=(*JOBS, "targets", "summary"))
    p.add_argument("control", nargs="?", choices=tuple(JOBS), default="spf", help="for summary: spf, dmarc, dkim or mta-sts")
    p.add_argument("--selectors", help="dkim: CSV of company_key,domain,selector,source_url seen in public sources")
    args = p.parse_args(argv)
    sf = make_session_factory(make_engine())
    if args.command == "summary":
        JOBS[args.control][1](sf)
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
    job_cls, summary = JOBS[args.command]
    job = (DkimJob(store, published=published_selectors(args.selectors) if args.selectors else None)
           if job_cls is DkimJob else job_cls(store))
    r = run_import(sf, store, job, content, source_url="db:company_domains")
    print(f"run {r.id} {r.status}: {r.rows_seen} domains, {r.rows_inserted} new answers, "
          f"{r.rows_unchanged} same as last time, {r.rows_rejected} rejected")
    summary(sf)
    return 0 if r.status == "succeeded" else 2


if __name__ == "__main__":
    sys.exit(main())
