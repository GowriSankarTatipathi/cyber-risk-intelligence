"""Command line for issue 3.3.

    python -m cyber_risk_intelligence.incidents hhs collect [--list investigation|archive|both] [--file f.csv]
        # export the HHS OCR breach lists (or import a CSV exported from the portal) and find company candidates
    python -m cyber_risk_intelligence.incidents hhs summary
    python -m cyber_risk_intelligence.incidents hhs candidates [--status unverified]
    python -m cyber_risk_intelligence.incidents hhs review ID --status confirmed|rejected --source URL [--note "..."]

A name match between an HHS report and one of our companies is only a candidate until a source confirms it.
"""

import argparse
import sys
from pathlib import Path

from sqlalchemy import text

from ..db import make_engine, make_session_factory
from ..evidence import store_from_env
from ..ingest import run_import
from ..ingest.framework import IngestionFailed
from .hhs import (
    HhsBreachJob,
    HhsClient,
    HhsUnavailable,
    match_candidates,
    review_candidate,
)


def summary(sf) -> None:
    with sf() as s:
        n = s.execute(text(
            "SELECT count(*) AS n, count(*) FILTER (WHERE list_status = 'under_investigation') AS inv, "
            "count(*) FILTER (WHERE list_status = 'archived') AS arc, sum(individuals_affected) AS people, "
            "min(submitted_on) AS first, max(submitted_on) AS last, "
            "count(*) FILTER (WHERE revisions IS NOT NULL) AS revised, "
            "count(*) FILTER (WHERE ambiguous_identity) AS ambiguous, "
            "count(*) FILTER (WHERE individuals_affected IS NULL) AS no_count "
            "FROM healthcare_breach_records")).one()
        if not n.n:
            print("No HHS breach reports imported yet: run  python -m cyber_risk_intelligence.incidents hhs collect")
            return
        types = s.execute(text(
            "SELECT t AS type, count(*) AS n, sum(individuals_affected) AS people FROM healthcare_breach_records, "
            "jsonb_array_elements_text(coalesce(breach_types, '[\"(none given)\"]')) t GROUP BY 1 ORDER BY 2 DESC")).all()
        cands = s.execute(text(
            "SELECT c.company_key, x.status, x.match_basis, x.id, r.entity_name, r.state, r.submitted_on, "
            "r.individuals_affected, r.breach_types FROM healthcare_breach_company_candidates x "
            "JOIN companies c ON c.id = x.company_id JOIN healthcare_breach_records r ON r.id = x.breach_record_id "
            "WHERE x.status <> 'rejected' ORDER BY x.status, c.company_key, r.submitted_on DESC")).all()
    print(f"HHS breach reports (500+ people): {n.n} ({n.inv} under investigation, {n.arc} archived), submitted "
          f"{n.first} to {n.last}, {n.people or 0:,} people affected in total. {n.revised} revised since first seen, "
          f"{n.ambiguous} share entity/state/date with another report, {n.no_count} without a count.")
    print("By type: " + "; ".join(f"{t.type} {t.n} ({(t.people or 0):,} people)" for t in types))
    if not cands:
        print("\nNo report matches one of our companies by name.")
    else:
        print(f"\nCompany candidates by name ({len(cands)}; unverified until a source confirms the identity):")
        print(f"{'id':>6} {'company':24} {'status':10} {'basis':11} {'submitted':10} {'people':>10}  entity (state) / type")
        for c in cands:
            people = f"{c.individuals_affected:,}" if c.individuals_affected is not None else "?"
            print(f"{c.id:>6} {c.company_key[:24]:24} {c.status:10} {c.match_basis:11} {c.submitted_on!s:10} "
                  f"{people:>10}  {c.entity_name} ({c.state}) / {', '.join(c.breach_types or [])}"[:200])
        print("Confirm or reject with a source:  python -m cyber_risk_intelligence.incidents hhs review ID "
              "--status confirmed --source https://...")
    print("Submission date = when the entity reported to HHS, not when the breach happened. Source: HHS OCR "
          "breach portal (public domain).")


def _collect(sf, args) -> int:
    lists = ["investigation", "archive"] if args.list == "both" else [args.list]
    if args.file and len(lists) != 1:
        print("--file needs --list investigation or --list archive (which list the CSV is)")
        return 2
    store, code = store_from_env(), 0
    for which in lists:
        if args.file:
            content, url = args.file.read_bytes(), args.file.resolve().as_uri()
        else:
            try:
                url, content = HhsClient().download(which)
            except HhsUnavailable as exc:
                print(f"{exc}. Nothing imported for that list; export the CSV from the portal and use --file.")
                code = 2
                continue
        job = HhsBreachJob(which)
        try:
            r = run_import(sf, store, job, content, source_url=url)
        except IngestionFailed as exc:
            print(f"{exc}. See ingestion_errors (run_id = {exc.run_id}).")
            code = 2
            continue
        changed = ", ".join(f"{k} {v}" for k, v in job.changes.most_common()) or "none"
        print(f"run {r.id} {r.status}: {which} list, {r.rows_seen} reports, {r.rows_inserted} new, {r.rows_updated} "
              f"revised (fields: {changed}), {r.rows_unchanged} unchanged, {r.rows_rejected} rejected")
        code = code or (0 if r.status == "succeeded" else 2)
    with sf() as s:
        print(f"{match_candidates(s)} new company candidates found by name.")
    summary(sf)
    return code


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m cyber_risk_intelligence.incidents")
    p.add_argument("dataset", choices=("hhs",))
    p.add_argument("command", nargs="?", choices=("collect", "summary", "candidates", "review"), default="summary")
    p.add_argument("id", nargs="?", type=int, help="review: the candidate id")
    p.add_argument("--list", choices=("investigation", "archive", "both"), default="both")
    p.add_argument("--file", type=Path, help="collect: a CSV exported from the portal")
    p.add_argument("--status", help="review: confirmed or rejected; candidates: filter")
    p.add_argument("--source", help="review: URL of the source that supports the decision")
    p.add_argument("--note")
    args = p.parse_args(argv)
    sf = make_session_factory(make_engine())
    if args.command == "collect":
        return _collect(sf, args)
    if args.command == "review":
        if args.id is None:
            p.error("review needs the candidate id")
        with sf() as s:
            try:
                c = review_candidate(s, args.id, args.status or "", args.source or "", args.note)
            except ValueError as exc:
                p.error(str(exc))
            print(f"candidate {c.id} is now {c.status} (source {c.review_source_url})")
        return 0
    if args.command == "candidates":
        with sf() as s:
            match_candidates(s)
    summary(sf)
    return 0


if __name__ == "__main__":
    sys.exit(main())
