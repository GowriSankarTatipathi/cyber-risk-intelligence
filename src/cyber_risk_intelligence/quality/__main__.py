"""Command line: python -m cyber_risk_intelligence.quality [--evidence]"""

import argparse
import sys

from sqlalchemy import select

from ..db import make_engine, make_session_factory
from ..evidence import store_from_env
from ..models import ValidationFinding, ValidationResult
from .runner import run_validation


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m cyber_risk_intelligence.quality")
    p.add_argument("--evidence", action="store_true", help="also re-hash every stored evidence object")
    p.add_argument("--show", type=int, default=5, help="findings to print per check (default 5)")
    args = p.parse_args(argv)

    sf = make_session_factory(make_engine())
    run = run_validation(sf, store=store_from_env() if args.evidence else None)
    print(f"validation run {run.id}: {run.status.upper()} ({run.checks_run} checks, "
          f"{run.errors} with errors, {run.warnings} with warnings)")
    with sf() as s:
        for r in s.scalars(select(ValidationResult).where(ValidationResult.validation_run_id == run.id)
                           .order_by(ValidationResult.id)):
            mark = "ok " if r.rows_failed == 0 else {"error": "ERR", "warning": "WRN", "info": "inf"}[r.severity]
            print(f"  [{mark}] {r.rule}: {r.rows_failed} of {r.rows_checked}")
            if r.rows_failed:
                for f in s.scalars(select(ValidationFinding).where(
                        ValidationFinding.validation_run_id == run.id, ValidationFinding.check_name == r.rule)
                        .order_by(ValidationFinding.id).limit(args.show)):
                    print(f"        {f.table_name}#{f.record_id}: {f.message}")
    return {"passed": 0, "warnings": 0, "failed": 1}.get(run.status, 2)


if __name__ == "__main__":
    sys.exit(main())
