"""Command line for issue 10.3.

    python -m cyber_risk_intelligence.exposure collect [--side-hosts 40]
        # Shodan InternetDB for every company's website and own mail hosts, plus up to N side hosts
        # per domain named in its Certificate Transparency certificates (vpn., remote., owa. ...)
    python -m cyber_risk_intelligence.exposure side-hosts  # which CT names collect would pick (no lookups)
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
            f"SELECT c.company_key, l.host, l.host_role, l.name_hint, l.outcome, l.attribution, host(l.ip) AS ip, "
            f"l.cpes, (SELECT string_agg(o.port::text, ',' ORDER BY o.port) FROM indexed_service_observations o "
            f" WHERE o.lookup_id = l.id) AS ports, "
            f"coalesce(jsonb_array_length(l.potential_vulns), 0) AS vulns, "
            f"(SELECT string_agg(o.port || coalesce('/' || o.service_hint, ''), ' ' ORDER BY o.port) "
            f" FROM indexed_service_observations o WHERE o.lookup_id = l.id AND o.sensitive) AS sensitive "
            f"FROM ({LATEST}) l JOIN companies c ON c.id = l.company_id ORDER BY c.company_key, l.host")).all()
    per: dict[str, dict] = {}
    for r in rows:
        p = per.setdefault(r.company_key, {"ips": set(), "side": set(), "attr": {}, "failed": 0, "vulns": 0, "sensitive": set()})
        if r.outcome in ("dns_failed", "lookup_failed"):
            p["failed"] += 1
        if r.ip:
            p["ips"].add(r.ip)
            if r.host_role == "certificate_name":
                p["side"].add(r.host)
        if r.attribution:
            p["attr"].setdefault(r.attribution, set()).add(r.ip)  # an IP behind two hosts counts once
        if r.attribution in ("company_only", "unknown"):
            p["vulns"] = max(p["vulns"], r.vulns)
            if r.sensitive:
                p["sensitive"].update(f"{r.host}:{x}" for x in r.sensitive.split())
    print(f"{'company':36} {'side':>4} {'IPs':>4} {'cdn':>4} {'shared':>6} {'own*':>5} {'failed':>6} {'CVEs*':>5}  sensitive ports*")
    for key, p in per.items():
        n = {a: len(p["attr"].get(a, ())) for a in ("cdn", "shared", "company_only", "unknown")}
        print(f"{key:36} {len(p['side']):>4} {len(p['ips']):>4} {n['cdn']:>4} {n['shared']:>6} {n['company_only'] + n['unknown']:>5} "
              f"{p['failed']:>6} {p['vulns']:>5}  {' '.join(sorted(p['sensitive']))[:70]}")
    tally = Counter(r.attribution or r.outcome for r in {(r.ip or r.host, r.attribution, r.outcome): r
                                                        for r in rows}.values())
    print("distinct IPs: " + (", ".join(f"{k}: {v}" for k, v in tally.most_common()) or "no lookups yet"))
    print("side = hosts from CT certificates that resolved. "
          "IPs, cdn, shared and own count distinct IPs; failed counts lookups. * own = not a CDN or shared host "
          "(company_only, or no host name known); CVEs = most potential CVEs on one own IP; sensitive ports are on "
          "own IPs. Indexed by Shodan, not verified; CVEs are inferred from software versions.")
    notable = [r for r in rows if r.host_role == "certificate_name" and r.name_hint
               and r.attribution in ("company_only", "unknown")]
    if notable:
        print(f"\nside hosts on the company's own IPs whose name suggests a service ({len(notable)}):")
        print(f"{'company':36} {'host':40} {'ip':16} {'kind':14} {'ports':16} software")
        for r in notable[:300]:
            soft = " ".join(c.removeprefix("cpe:/").split(":", 1)[-1] for c in (r.cpes or [])[:3])
            print(f"{r.company_key:36} {r.host[:40]:40} {r.ip:16} {r.name_hint:14} {(r.ports or '')[:16]:16} {soft[:60]}")


def side_host_plan(sf, limit: int) -> tuple[int, int]:
    """Print, per company domain, how many CT names exist and which side hosts collect would pick.
    Nothing is looked up. Returns (domains with CT names, domains where side hosts would be picked)."""
    from datetime import UTC, datetime

    from ..ct.website import hosts_for
    from .side_hosts import RECENT, side_hosts

    with sf() as s:
        rows = s.execute(text(
            "SELECT c.company_key, d.id, d.name, "
            "(SELECT count(*) FROM certificate_hostnames h WHERE h.domain_id = d.id) AS names, "
            "(SELECT max(x.queried_at) FROM ct_lookups x WHERE x.domain_id = d.id) AS ct_at "
            "FROM company_domains cd JOIN companies c ON c.id = cd.company_id JOIN domains d ON d.id = cd.domain_id "
            "WHERE cd.valid_to IS NULL ORDER BY c.company_key, d.name")).all()
        print(f"{'company':36} {'domain':30} {'CT names':>8} {'picked':>6}  first picks (CT collected)")
        with_names = with_picks = 0
        for r in rows:
            picks = side_hosts(s, r.id, r.name, limit, set(hosts_for(r.name)))
            with_names += r.names > 0
            with_picks += bool(picks)
            first = " ".join(h.removesuffix("." + r.name) for h, _ in picks[:4])
            when = r.ct_at.date().isoformat() if r.ct_at else "never"
            print(f"{r.company_key:36} {r.name:30} {r.names:>8} {len(picks):>6}  {first[:50]} ({when})")
    since = (datetime.now(UTC) - RECENT).date()
    print(f"{len(rows)} domains: {with_names} have CT names, {with_picks} have side hosts to look up "
          f"(exact names under the domain, from certificates valid on or after {since}).")
    if with_names == 0:
        print("No CT names stored yet: run  python -m cyber_risk_intelligence.ct collect  first.")
    return with_names, with_picks


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m cyber_risk_intelligence.exposure")
    p.add_argument("command", choices=("collect", "summary", "side-hosts"))
    p.add_argument("--side-hosts", type=int, default=40,
                   help="collect: side hosts per domain from CT certificates (0 = website and mail hosts only)")
    args = p.parse_args(argv)
    sf = make_session_factory(make_engine())
    if args.command == "summary":
        summary(sf)
        return 0
    if args.command == "side-hosts":
        side_host_plan(sf, args.side_hosts)
        return 0
    with sf() as s:
        content = targets_csv(s)
    store = store_from_env()
    job = IndexedExposureJob(store, side_hosts=args.side_hosts)
    r = run_import(sf, store, job, content, source_url="db:company_domains")
    print(f"run {r.id} {r.status}: {r.rows_seen} domains, {r.rows_inserted} with new records, "
          f"{r.rows_unchanged} same as last time, {r.rows_updated} with failed lookups, {r.rows_rejected} rejected")
    print(f"side hosts from CT certificates: {job.side_hosts_asked} asked, for {job.domains_with_side_hosts} domains")
    if args.side_hosts and not job.side_hosts_asked:
        print("No side hosts were found in the stored CT data. See why with:  "
              "python -m cyber_risk_intelligence.exposure side-hosts")
    summary(sf)
    return 0 if r.status == "succeeded" else 2


if __name__ == "__main__":
    sys.exit(main())
