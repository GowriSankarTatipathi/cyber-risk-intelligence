"""Backup answers from CSA STAR CAIQ self-assessments (issue 2.1 follow-up).

Adds ``basis`` to ``backup_policy_claims`` (``company_statement`` from the
company's own pages, ``csa_star_caiq`` from its CSA STAR Registry CAIQ), the CAIQ
question, answer, control ownership and service, and a ``sources`` column on the
``company_backup_frequencies`` view.

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-20
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0012'
down_revision: str | None = '0011'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_VIEW_BODY = """
       b.scope,
       b.frequency_class,
       min(b.interval_minutes) AS shortest_interval_minutes,
       count(DISTINCT b.claim_hash) AS statements,
       string_agg(DISTINCT b.covered_system, ', ' ORDER BY b.covered_system) AS systems,
       min(b.retention_days) AS shortest_retention_days,
       max(b.retention_days) AS longest_retention_days,
       min(b.rpo_minutes) AS best_rpo_minutes,
       min(b.rto_minutes) AS best_rto_minutes,
       max(b.page_updated_on) AS latest_page_updated_on,
       max(b.observed_at) AS last_observed_at{extra}
FROM backup_policy_claims b
WHERE b.assertion = 'affirmed'
GROUP BY b.company_id, b.scope, b.frequency_class
"""
NEW_VIEW = "CREATE VIEW company_backup_frequencies AS\nSELECT b.company_id," + _VIEW_BODY.format(
    extra=",\n       string_agg(DISTINCT b.basis, ', ' ORDER BY b.basis) AS sources")
OLD_VIEW = "CREATE VIEW company_backup_frequencies AS\nSELECT b.company_id," + _VIEW_BODY.format(extra="")


def upgrade() -> None:
    op.add_column('backup_policy_claims', sa.Column('basis', sa.Text(), server_default='company_statement', nullable=False))
    op.add_column('backup_policy_claims', sa.Column('caiq_question_id', sa.Text(), nullable=True))
    op.add_column('backup_policy_claims', sa.Column('caiq_answer', sa.Text(), nullable=True))
    op.add_column('backup_policy_claims', sa.Column('control_ownership', sa.Text(), nullable=True))
    op.add_column('backup_policy_claims', sa.Column('service_name', sa.Text(), nullable=True))
    op.create_check_constraint(op.f('ck_backup_policy_claims_basis'), 'backup_policy_claims',
                               "basis IN ('company_statement', 'csa_star_caiq')")
    op.create_check_constraint(op.f('ck_backup_policy_claims_caiq_question_id'), 'backup_policy_claims',
                               "(basis = 'csa_star_caiq') = (caiq_question_id IS NOT NULL)")
    op.create_check_constraint(op.f('ck_backup_policy_claims_caiq_answer'), 'backup_policy_claims',
                               "caiq_answer IS NULL OR caiq_answer IN ('yes', 'no')")
    op.create_check_constraint(op.f('ck_backup_policy_claims_claim_only_for_statements'), 'backup_policy_claims',
                               "basis = 'company_statement' OR claim_id IS NULL")
    op.execute("DROP VIEW company_backup_frequencies")
    op.execute(NEW_VIEW)


def downgrade() -> None:
    op.execute("DROP VIEW company_backup_frequencies")
    op.execute(OLD_VIEW)
    for name in ('claim_only_for_statements', 'caiq_answer', 'caiq_question_id', 'basis'):
        op.drop_constraint(op.f(f'ck_backup_policy_claims_{name}'), 'backup_policy_claims', type_='check')
    op.drop_column('backup_policy_claims', 'service_name')
    op.drop_column('backup_policy_claims', 'control_ownership')
    op.drop_column('backup_policy_claims', 'caiq_answer')
    op.drop_column('backup_policy_claims', 'caiq_question_id')
    op.drop_column('backup_policy_claims', 'basis')
