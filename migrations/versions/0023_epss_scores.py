"""FIRST EPSS daily scores (issue 5.2).

``epss_scores`` keeps one row per (CVE, scoring date): the probability of exploitation activity in
the next 30 days and its percentile, the model version, and the stored day's file as evidence. A new
day adds rows; earlier days stay. ``latest_epss_scores`` is each CVE's most recent score.
EPSS is about the CVE, never a company's probability of loss.

Revision ID: 0023
Revises: 0022
Create Date: 2026-11-21 01:30:50.143482
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0023'
down_revision: str | None = '0022'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('epss_scores',
    sa.Column('cve_id', sa.Text(), nullable=False),
    sa.Column('score_date', sa.Date(), nullable=False),
    sa.Column('epss', sa.Numeric(precision=12, scale=9), nullable=False),
    sa.Column('percentile', sa.Numeric(precision=12, scale=9), nullable=False),
    sa.Column('model_version', sa.Text(), nullable=True),
    sa.Column('scored_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('evidence_version_id', sa.BigInteger(), nullable=False),
    sa.Column('ingestion_run_id', sa.BigInteger(), nullable=True),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'", name=op.f('ck_epss_scores_cve_id_format')),
    sa.CheckConstraint('epss >= 0 AND epss <= 1', name=op.f('ck_epss_scores_epss_range')),
    sa.CheckConstraint('percentile >= 0 AND percentile <= 1', name=op.f('ck_epss_scores_percentile_range')),
    sa.ForeignKeyConstraint(['evidence_version_id'], ['evidence_versions.id'], name=op.f('fk_epss_scores_evidence_version_id_evidence_versions'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['ingestion_run_id'], ['ingestion_runs.id'], name=op.f('fk_epss_scores_ingestion_run_id_ingestion_runs'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_epss_scores')),
    sa.UniqueConstraint('cve_id', 'score_date', name='uq_epss_scores_cve_date')
    )
    op.create_index(op.f('ix_epss_scores_cve_id'), 'epss_scores', ['cve_id'], unique=False)
    op.create_index(op.f('ix_epss_scores_evidence_version_id'), 'epss_scores', ['evidence_version_id'], unique=False)
    op.create_index(op.f('ix_epss_scores_ingestion_run_id'), 'epss_scores', ['ingestion_run_id'], unique=False)
    op.execute("CREATE VIEW latest_epss_scores AS "
               "SELECT DISTINCT ON (cve_id) * FROM epss_scores ORDER BY cve_id, score_date DESC")


def downgrade() -> None:
    op.execute("DROP VIEW IF EXISTS latest_epss_scores")
    op.drop_index(op.f('ix_epss_scores_ingestion_run_id'), table_name='epss_scores')
    op.drop_index(op.f('ix_epss_scores_evidence_version_id'), table_name='epss_scores')
    op.drop_index(op.f('ix_epss_scores_cve_id'), table_name='epss_scores')
    op.drop_table('epss_scores')
