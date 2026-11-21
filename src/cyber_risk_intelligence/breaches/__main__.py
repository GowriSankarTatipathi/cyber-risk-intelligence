"""Command line for issue 11.1.

    python -m cyber_risk_intelligence.breaches collect [--file breaches.json]
        # download HIBP's public breach catalogue (or import a saved copy) into public_breach_metadata
    python -m cyber_risk_intelligence.breaches summary
        # the catalogue we hold and the breaches of sites on companies' own domains
    python -m cyber_risk_intelligence.breaches access
        # what HIBP offers, what needs a key or a verified domain, and what we therefore can't see
    python -m cyber_risk_intelligence.breaches infostealers [--limit N]
        # Hudson Rock's aggregate infostealer counts for every company domain (about 2 s per domain)
    python -m cyber_risk_intelligence.breaches infostealer-summary

A breach of a company's site is a public, dated event. It says nothing about the company's staff
accounts elsewhere, and a company with no breach listed may still have been breached.
"""

import argparse
import re
import sys
from pathlib import Path

from sqlalchemy import text

from ..db import make_engine, make_session_factory
from ..evidence import store_from_env
from ..ingest import run_import
from ..ingest.framework import IngestionFailed
from .hibp import CATALOGUE_URL, HibpBreachesJob, HibpClient, HibpUnavailable

_SUFFIX = re.compile(r"\b(inc|incorporated|corporation|corp|company|co|group|holdings|plc|ltd|the)\b\.?")


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", _SUFFIX.sub("", name.lower()))


def name_only_candidates(rows, companies) -> list[tuple[str, object]]:
    """Breaches whose title starts with a company's name but whose domain isn't one of that company's
    domains. They are not linked: the domain has to be confirmed as the company's first."""
    out = []
    for b in rows:
        title = _norm(b.title or b.name)
        for key, display in companies:
            k = _norm(display)
            if len(k) >= 4 and title.startswith(k):
                out.append((key, b))
    return out


def summary(sf) -> None:
    with sf() as s:
        latest = s.scalar(text("SELECT max(last_seen_run_id) FROM public_breach_metadata"))
        if latest is None:
            print("No HIBP catalogue imported yet: run  python -m cyber_risk_intelligence.breaches collect")
            return
        n = s.execute(text(
            "SELECT count(*) FILTER (WHERE last_seen_run_id = :r) AS current, "
            "count(*) FILTER (WHERE last_seen_run_id <> :r) AS removed, "
            "count(*) FILTER (WHERE last_seen_run_id = :r AND is_verified) AS verified, "
            "count(*) FILTER (WHERE last_seen_run_id = :r AND is_fabricated) AS fabricated, "
            "count(*) FILTER (WHERE last_seen_run_id = :r AND is_spam_list) AS spam, "
            "count(*) FILTER (WHERE last_seen_run_id = :r AND is_stealer_log) AS stealer, "
            "count(*) FILTER (WHERE last_seen_run_id = :r AND data_classes ? 'Passwords') AS passwords, "
            "count(*) FILTER (WHERE last_seen_run_id = :r AND domain IS NULL) AS no_domain "
            "FROM public_breach_metadata"), {"r": latest}).one()
        linked = s.execute(text(
            "SELECT c.company_key, v.* FROM company_public_breaches v JOIN companies c ON c.id = v.company_id "
            "ORDER BY c.company_key, v.breach_date DESC NULLS LAST, v.breach_name")).all()
        linked_ids = {(r.company_key, r.breach_id) for r in linked}
        companies = s.execute(text("SELECT company_key, display_name FROM companies ORDER BY company_key")).all()
        unlinked = s.execute(text(
            "SELECT id, name, title, domain, breach_date, pwn_count FROM public_breach_metadata "
            "WHERE last_seen_run_id = :r ORDER BY name"), {"r": latest}).all()
    print(f"HIBP breach catalogue: {n.current} breaches in the latest import ({n.verified} verified, "
          f"{n.fabricated} fabricated, {n.spam} spam lists, {n.stealer} stealer logs, {n.passwords} with passwords "
          f"among the data, {n.no_domain} with no domain).")
    if n.removed:
        print(f"{n.removed} stored breaches are no longer in HIBP's catalogue (kept for history).")
    if not linked:
        print("\nNo breach in the catalogue is of a site on a company's known domains.")
    else:
        print(f"\nBreaches of sites on companies' own domains: {len(linked)} breaches, "
              f"{len({r.company_key for r in linked})} companies.")
        print(f"{'company':28} {'breach':22} {'breached domain':24} {'date':10} {'accounts':>11} {'pw':3} flags")
        for r in linked:
            flags = ",".join(f for f, on in (("unverified", r.is_verified is False), ("fabricated", r.is_fabricated),
                                             ("spam_list", r.is_spam_list), ("sensitive", r.is_sensitive),
                                             ("removed", not r.in_latest_catalogue),
                                             ("subdomain", r.match_basis == "subdomain")) if on)
            accounts = f"{r.pwn_count:,}" if r.pwn_count is not None else "?"
            print(f"{r.company_key[:28]:28} {r.breach_name[:22]:22} {r.breached_domain[:24]:24} "
                  f"{r.breach_date or '?'!s:10} {accounts:>11} {'yes' if r.passwords_exposed else '':3} {flags}")
    candidates = [(k, b) for k, b in name_only_candidates(unlinked, companies) if (k, b.id) not in linked_ids]
    if candidates:
        print("\nNamed like a company, but the breached domain is not one of its known domains (NOT linked; add the "
              "domain to the company's domains only if a source confirms it is theirs):")
        for key, b in candidates:
            print(f"  {key:28} {b.name[:28]:28} {b.domain or '(no domain)':28} {b.breach_date or '?'}")
    print("\nThese are breaches of the company's own site or service (its customers' or users' records), as "
          "HIBP lists them. HIBP domain search (how many of a company's own email addresses appear in other "
          "breaches) needs a verified domain and is not used, so that exposure is unknown, not zero. "
          "A company with no breach here may still have had one. Data: Have I Been Pwned, CC BY 4.0.")


def access(sf) -> None:
    with sf() as s:
        rows = s.execute(text(
            "SELECT n.capability, n.endpoint, n.access, n.used, n.returns, n.limitation, n.checked_at "
            "FROM breach_source_access_notes n JOIN sources src ON src.id = n.source_id "
            "WHERE src.source_key = 'hibp' ORDER BY n.used DESC, n.access, n.capability")).all()
    if not rows:
        print("No access notes yet: they are written by  python -m cyber_risk_intelligence.breaches collect")
        return
    for r in rows:
        print(f"{r.capability} ({r.access}, {'used' if r.used else 'not used'}): {r.endpoint}\n"
              f"  gives: {r.returns}\n  for us: {r.limitation}")
    print(f"\nChecked {rows[0].checked_at:%Y-%m-%d} against https://haveibeenpwned.com/API/v3")


def infostealer_summary(sf) -> None:
    with sf() as s:
        n = s.execute(text(
            "SELECT count(*) AS domains, "
            "count(*) FILTER (WHERE l.outcome = 'found') AS found, "
            "count(*) FILTER (WHERE l.outcome = 'none_reported') AS none_reported, "
            "count(*) FILTER (WHERE l.id IS NULL AND f.id IS NOT NULL) AS failed_only, "
            "count(*) FILTER (WHERE l.id IS NULL AND f.id IS NULL) AS not_looked_up "
            "FROM (SELECT DISTINCT domain_id FROM company_domains WHERE valid_to IS NULL) d "
            "LEFT JOIN latest_aggregate_exposure l ON l.domain_id = d.domain_id "
            "LEFT JOIN LATERAL (SELECT id FROM aggregate_exposure_observations x WHERE x.domain_id = d.domain_id "
            "                   LIMIT 1) f ON true")).one()
        rows = s.execute(text(
            "SELECT c.company_key, l.domain_id, dm.name AS domain, l.employees, l.users, l.third_parties, "
            "l.last_employee_infection_at, l.employee_login_hosts, l.employee_password_strength, l.observed_at "
            "FROM latest_aggregate_exposure l JOIN companies c ON c.id = l.company_id "
            "JOIN domains dm ON dm.id = l.domain_id WHERE l.outcome = 'found' "
            "ORDER BY l.employees DESC NULLS LAST, l.users DESC NULLS LAST, c.company_key")).all()
    if not n.domains:
        print("No company domains yet.")
        return
    print(f"Infostealer counts (Hudson Rock) for {n.domains} company domains: {n.found} with infections, "
          f"{n.none_reported} none reported, {n.failed_only} only failed lookups (unknown), "
          f"{n.not_looked_up} not looked up yet.")
    if not rows:
        print("No infections reported yet (or infostealers has not run: "
              "python -m cyber_risk_intelligence.breaches infostealers).")
        return
    print(f"\n{'company':28} {'domain':26} {'employees':>9} {'users':>7} {'3rd pty':>7} {'last employee':13} "
          "weak emp pw  remote-access / identity login hosts")
    for r in rows:
        hosts = [h["host"] for h in r.employee_login_hosts or [] if h.get("hint") in ("remote_access", "identity")]
        pw = r.employee_password_strength or {}
        weak = (pw.get("too_weak") or 0) + (pw.get("weak") or 0)
        weak_s = f"{weak}/{pw['total']}" if pw.get("total") else ""
        last = f"{r.last_employee_infection_at:%Y-%m-%d}" if r.last_employee_infection_at else ""
        print(f"{r.company_key[:28]:28} {r.domain[:26]:26} {r.employees or 0:>9} {r.users or 0:>7} "
              f"{r.third_parties or 0:>7} {last:13} {weak_s:11}  {', '.join(hosts[:4])}"[:200])
    print("\nEmployees = infected computers with saved logins for the company's own staff login pages; users = "
          "customer login pages. Counts are Hudson Rock's, from computers infected by infostealer malware (often "
          "personal devices). They are leads to ask about (password resets, MFA, session revocation), not a "
          "breach of the company. 'None reported' is not proof of none. Source: Hudson Rock free tools, "
          "internal research use.")


def _collect_infostealers(sf, args) -> int:
    from .infostealers import InfostealerJob, targets_csv

    with sf() as s:
        content = targets_csv(s)
    if args.limit:
        lines = content.decode().splitlines()
        content = ("\n".join(lines[: args.limit + 1]) + "\n").encode()
    todo = content.count(b"\n") - 1
    if todo <= 0:
        print("No company domains to look up.")
        return 2
    print(f"Asking Hudson Rock's free domain search for {todo} domains, one at a time (about "
          f"{max(1, round(todo * 2.5 / 60))} min). Only counts and login host names are kept.")
    store = store_from_env()
    job = InfostealerJob(store)
    try:
        r = run_import(sf, store, job, content, source_url="db:company_domains")
    except IngestionFailed as exc:
        print(f"{exc}. See ingestion_errors (run_id = {exc.run_id}).")
        return 2
    print(f"run {r.id} {r.status}: {r.rows_seen} domains, {job.tally['found']} with infections, "
          f"{job.tally['none_reported']} none reported, {job.tally['lookup_failed']} lookups failed (unknown, "
          f"asked again next run), {r.rows_rejected} rejected")
    infostealer_summary(sf)
    return 0 if r.status == "succeeded" and not job.tally["lookup_failed"] else 2


def _collect(sf, args) -> int:
    if args.file:
        content, url = args.file.read_bytes(), args.file.resolve().as_uri()
    else:
        try:
            content, url = HibpClient().catalogue(), CATALOGUE_URL
        except HibpUnavailable as exc:
            print(f"{exc}. Nothing was imported; the catalogue already stored is unchanged.")
            return 2
    try:
        r = run_import(sf, store_from_env(), HibpBreachesJob(), content, source_url=url)
    except IngestionFailed as exc:
        print(f"{exc}. See ingestion_errors (run_id = {exc.run_id}).")
        return 2
    print(f"run {r.id} {r.status}: {r.rows_seen} breaches, {r.rows_inserted} new, {r.rows_updated} changed, "
          f"{r.rows_unchanged} unchanged, {r.rows_rejected} rejected")
    if r.rows_rejected:
        print(f"Rejected breaches are in ingestion_errors (run_id = {r.id}).")
    summary(sf)
    return 0 if r.status == "succeeded" else 2


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m cyber_risk_intelligence.breaches")
    p.add_argument("command", nargs="?", default="summary",
                   choices=("collect", "summary", "access", "infostealers", "infostealer-summary"))
    p.add_argument("--file", type=Path, help="collect: import a saved copy of the catalogue instead of downloading it")
    p.add_argument("--limit", type=int, help="infostealers: only the first N domains (for a trial run)")
    args = p.parse_args(argv)
    sf = make_session_factory(make_engine())
    if args.command == "collect":
        return _collect(sf, args)
    if args.command == "infostealers":
        return _collect_infostealers(sf, args)
    {"summary": summary, "access": access, "infostealer-summary": infostealer_summary}[args.command](sf)
    return 0


if __name__ == "__main__":
    sys.exit(main())
