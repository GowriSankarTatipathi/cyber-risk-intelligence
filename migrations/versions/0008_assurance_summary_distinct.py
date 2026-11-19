"""Count distinct statements in company_assurance_summary (issue 1.3 follow-up).

The same sentence captured on several runs is one statement, not several, so the
claim, document and register counts now count distinct wording / register records.

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-19
"""
from collections.abc import Sequence

from alembic import op

revision: str = '0008'
down_revision: str | None = '0007'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _view(counts: str) -> str:
    return f"""
CREATE OR REPLACE VIEW company_assurance_summary AS
SELECT a.company_id,
       a.kind,
       a.framework,
       a.report_type,
       CASE
         WHEN bool_or(a.verification_status = 'verified' AND a.directory_status = 'active'
                      AND (a.valid_until IS NULL OR a.valid_until >= current_date)) THEN 'verified'
         WHEN bool_or(a.verification_status = 'verified') THEN 'verified_lapsed'
         ELSE 'claimed'
       END AS status,
       CASE
         WHEN max(a.valid_until) IS NULL THEN 'unknown'
         WHEN max(a.valid_until) >= current_date THEN 'current'
         ELSE 'expired'
       END AS validity,
       max(a.valid_until) AS latest_valid_until,
       max(a.period_end) AS latest_period_end,
       bool_or(a.report_availability = 'public') AS public_report,
       bool_or(a.report_availability = 'gated') AS gated_report,
{counts}
       max(a.observed_at) AS last_observed_at
FROM security_assurances a
GROUP BY a.company_id, a.kind, a.framework, a.report_type
"""


DISTINCT_COUNTS = """\
       count(DISTINCT coalesce(a.quote, a.id::text)) FILTER (WHERE a.basis = 'company_claim') AS company_claims,
       count(DISTINCT coalesce(a.quote, a.id::text)) FILTER (WHERE a.basis = 'company_document') AS company_documents,
       count(DISTINCT coalesce(a.source_ref, '') || '|' || coalesce(a.certificate_number, ''))
         FILTER (WHERE a.basis = 'issuer_directory') AS register_entries,"""

ROW_COUNTS = """\
       count(*) FILTER (WHERE a.basis = 'company_claim') AS company_claims,
       count(*) FILTER (WHERE a.basis = 'company_document') AS company_documents,
       count(*) FILTER (WHERE a.basis = 'issuer_directory') AS register_entries,"""


def upgrade() -> None:
    op.execute(_view(DISTINCT_COUNTS))


def downgrade() -> None:
    op.execute(_view(ROW_COUNTS))
