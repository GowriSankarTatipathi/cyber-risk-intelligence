"""Command line: python -m cyber_risk_intelligence.ingest seed-companies path/to/file.csv"""

import argparse
import sys
from pathlib import Path

from ..db import make_engine, make_session_factory
from ..evidence import store_from_env
from .framework import IngestionFailed, retry_import, run_import
from .seed_companies import SeedCompaniesJob

JOBS = {"seed-companies": SeedCompaniesJob}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m cyber_risk_intelligence.ingest")
    sub = p.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="import a file")
    run.add_argument("job", choices=JOBS)
    run.add_argument("path", type=Path)
    run.add_argument("--source-url", help="where the file came from (default: file:// path)")
    retry = sub.add_parser("retry", help="retry a failed or partial run from its stored input")
    retry.add_argument("job", choices=JOBS)
    retry.add_argument("run_id", type=int)
    args = p.parse_args(argv)

    sf = make_session_factory(make_engine())
    store = store_from_env()
    job = JOBS[args.job]()
    try:
        if args.command == "run":
            url = args.source_url or args.path.resolve().as_uri()
            r = run_import(sf, store, job, args.path.read_bytes(), source_url=url)
        else:
            r = retry_import(sf, store, job, args.run_id)
    except IngestionFailed as exc:
        print(f"run {exc.run_id} FAILED: {exc.__cause__}", file=sys.stderr)
        return 1
    print(f"run {r.id} {r.status}: {r.rows_seen} rows, {r.rows_inserted} inserted, {r.rows_updated} updated, "
          f"{r.rows_unchanged} unchanged, {r.rows_rejected} rejected")
    with sf() as s:
        from sqlalchemy import select
        from ..models import IngestionError
        for e in s.scalars(select(IngestionError).where(IngestionError.run_id == r.id).limit(20)):
            print(f"  row {e.row_number} [{e.stage}/{e.code}] {e.message}")
    return 0 if r.status == "succeeded" else 2


if __name__ == "__main__":
    sys.exit(main())
