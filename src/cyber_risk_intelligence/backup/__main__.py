"""Command line for issue 2.1.

    python -m cyber_risk_intelligence.backup derive    # read backup schedules out of what 1.1 already collected
    python -m cyber_risk_intelligence.backup summary   # per company: the schedules each company states

CSA STAR CAIQ answers are imported with:
    python -m cyber_risk_intelligence.ingest run csa-star csa_star_targets.csv
"""

import argparse
import sys

from sqlalchemy import select, text

from ..db import make_engine, make_session_factory
from ..models import SecurityControlClaim
from .derive import CATEGORY, from_claim


def derive(sf) -> int:
    added = 0
    with sf() as s:
        for claim in s.scalars(select(SecurityControlClaim).where(SecurityControlClaim.control_category == CATEGORY)
                               .order_by(SecurityControlClaim.id)):
            added += len(from_claim(s, claim))
        s.commit()
    return added


def summary(sf) -> None:
    with sf() as s:
        rows = s.execute(text(
            "SELECT c.company_key, v.scope, coalesce(v.frequency_class, 'not stated') AS freq, "
            "v.shortest_interval_minutes AS mins, v.statements, v.sources, v.systems "
            "FROM company_backup_frequencies v JOIN companies c ON c.id = v.company_id "
            "ORDER BY c.company_key, v.scope, v.shortest_interval_minutes NULLS LAST")).all()
    print(f"{'company':28} {'scope':24} {'frequency':12} {'minutes':>8} statements {'sources':31} systems")
    for r in rows:
        mins = "" if r.mins is None else str(r.mins)
        print(f"{r.company_key:28} {r.scope:24} {r.freq:12} {mins:>8} {r.statements:10} {r.sources:31} {r.systems or ''}")
    print(f"{len(rows)} company/scope/frequency rows")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m cyber_risk_intelligence.backup")
    p.add_argument("command", choices=("derive", "summary"))
    args = p.parse_args(argv)
    sf = make_session_factory(make_engine())
    if args.command == "derive":
        print(f"added {derive(sf)} backup schedule rows")
    else:
        summary(sf)
    return 0


if __name__ == "__main__":
    sys.exit(main())
