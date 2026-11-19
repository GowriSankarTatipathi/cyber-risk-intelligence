"""Turn 1.1 ``backup_and_recovery`` claims into ``backup_policy_claims`` rows.

One row per schedule a sentence states ("daily full backups and hourly
incrementals" gives two rows). A backup sentence that states no schedule gives
one row with the frequency left NULL (unknown). Sentences only about disaster
recovery or continuity plans, with no backup or recovery objective in them, are
not backup policies and give no row.

Re-running is safe: a row that already exists for the same sentence, capture and
schedule is not added again.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import SecurityControlClaim
from ..models.backup import BackupPolicyClaim
from .parse import read_backup_statement

CATEGORY = "backup_and_recovery"


def from_claim(s: Session, claim: SecurityControlClaim, source_ref: str | None = None) -> list[BackupPolicyClaim]:
    if claim.control_category != CATEGORY:
        return []
    st = read_backup_statement(claim.claim_text)
    if st is None:
        return []
    schedules = st.frequencies or [None]
    added = []
    for f in schedules:
        phrase = f.phrase if f else None
        exists = s.scalar(select(BackupPolicyClaim.id).where(
            BackupPolicyClaim.evidence_version_id == claim.evidence_version_id,
            BackupPolicyClaim.claim_hash == claim.claim_hash,
            BackupPolicyClaim.frequency_phrase.is_not_distinct_from(phrase)).limit(1))
        if exists is not None:
            continue
        row = BackupPolicyClaim(
            company_id=claim.company_id, legal_entity_id=claim.legal_entity_id, claim_id=claim.id,
            evidence_version_id=claim.evidence_version_id, source_ref=source_ref or claim.source_ref,
            quote=claim.claim_text, claim_hash=claim.claim_hash, section_heading=claim.section_heading,
            assertion=claim.assertion, scope=st.scope, covered_system=st.covered_system,
            frequency_class=f.frequency_class if f else None, interval_minutes=f.interval_minutes if f else None,
            frequency_phrase=phrase, methods=st.methods or None,
            retention_days=st.retention_days, retention_phrase=st.retention_phrase,
            rpo_minutes=st.rpo_minutes, rto_minutes=st.rto_minutes, objective_phrase=st.objective_phrase,
            page_updated_on=claim.page_updated_on, observed_at=claim.observed_at, verification_status="claimed",
        )
        s.add(row)
        added.append(row)
    return added
