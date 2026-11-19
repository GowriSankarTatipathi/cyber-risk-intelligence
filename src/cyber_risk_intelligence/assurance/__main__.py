"""Command line for issue 1.3.

    python -m cyber_risk_intelligence.assurance derive    # build certification rows from what 1.1 already collected
    python -m cyber_risk_intelligence.assurance summary   # per company: what is claimed, what a register confirms

Register entries are imported with:
    python -m cyber_risk_intelligence.ingest run assurance-directory registers.csv
"""

import argparse
import sys

from sqlalchemy import select, text

from ..db import make_engine, make_session_factory
from ..evidence import read_evidence, store_from_env
from ..models import EvidenceVersion, PageFetch, SecurityControlClaim
from ..models.controls import CollectionTarget
from .derive import from_claim, from_document


def derive(sf, store) -> tuple[int, int]:
    """Backfill from stored documents, then existing claims. Safe to repeat."""
    from ..collectors.trust_center.documents import detect_kind, document_text

    claims = docs = 0
    with sf() as s:
        rows = s.execute(select(PageFetch.evidence_version_id, CollectionTarget.company_id, CollectionTarget.url)
                         .join(CollectionTarget).where(PageFetch.outcome == "captured")
                         .where(PageFetch.evidence_version_id.is_not(None)).distinct())
        for version_id, company_id, url in rows:
            version = s.get(EvidenceVersion, version_id)
            content = read_evidence(s, store, version)
            kind = detect_kind(content, version.evidence_object.media_type, version.source_url)
            if kind not in (None, "html"):
                docs += len(from_document(s, company_id, version, document_text(content, kind), source_ref=url))
        s.flush()
        for claim in s.scalars(select(SecurityControlClaim).where(
                SecurityControlClaim.control_category == "compliance_certification")):
            claims += from_claim(s, claim) is not None
        s.commit()
    return claims, docs


def summary(sf) -> None:
    with sf() as s:
        rows = s.execute(text(
            "SELECT c.company_key, v.framework, coalesce(v.report_type, '') AS rt, v.status, v.validity, "
            "v.latest_valid_until, v.company_claims, v.company_documents, v.register_entries "
            "FROM company_assurance_summary v JOIN companies c ON c.id = v.company_id "
            "ORDER BY c.company_key, v.framework")).all()
    print(f"{'company':28} {'framework':16} {'type':8} {'status':16} {'validity':9} claims docs registers")
    for r in rows:
        print(f"{r.company_key:28} {r.framework:16} {r.rt:8} {r.status:16} {r.validity:9} "
              f"{r.company_claims:6} {r.company_documents:4} {r.register_entries:9}")
    print(f"{len(rows)} company/framework pairs")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m cyber_risk_intelligence.assurance")
    p.add_argument("command", choices=("derive", "summary"))
    args = p.parse_args(argv)
    sf = make_session_factory(make_engine())
    if args.command == "derive":
        claims, docs = derive(sf, store_from_env())
        print(f"added {claims} rows from claims and {docs} from published certificates/reports")
    else:
        summary(sf)
    return 0


if __name__ == "__main__":
    sys.exit(main())
