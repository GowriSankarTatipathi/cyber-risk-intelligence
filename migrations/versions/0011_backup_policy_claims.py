"""Published backup frequencies (issue 2.1).

Adds ``backup_policy_claims`` (one row per backup schedule a company states in
one sentence on its own pages; a backup sentence with no schedule keeps the
frequency NULL) and the ``company_backup_frequencies`` view (per company, scope
and frequency: how many statements, which systems, the shortest interval).

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-19
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0011'
down_revision: str | None = '0010'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# One row per company, scope and frequency class (NULL = backups mentioned, schedule not stated).
# Only affirmed statements; scope keeps product features and customer duties apart from the company's own practice.
VIEW = """
CREATE VIEW company_backup_frequencies AS
SELECT b.company_id,
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
       max(b.observed_at) AS last_observed_at
FROM backup_policy_claims b
WHERE b.assertion = 'affirmed'
GROUP BY b.company_id, b.scope, b.frequency_class
"""


def upgrade() -> None:
    op.create_table('backup_policy_claims',
    sa.Column('company_id', sa.BigInteger(), nullable=False),
    sa.Column('legal_entity_id', sa.BigInteger(), nullable=True),
    sa.Column('claim_id', sa.BigInteger(), nullable=True),
    sa.Column('evidence_version_id', sa.BigInteger(), nullable=False),
    sa.Column('source_ref', sa.Text(), nullable=True),
    sa.Column('quote', sa.Text(), nullable=False),
    sa.Column('claim_hash', sa.Text(), nullable=False),
    sa.Column('section_heading', sa.Text(), nullable=True),
    sa.Column('assertion', sa.Text(), server_default='affirmed', nullable=False),
    sa.Column('scope', sa.Text(), nullable=False),
    sa.Column('covered_system', sa.Text(), nullable=True),
    sa.Column('frequency_class', sa.Text(), nullable=True),
    sa.Column('interval_minutes', sa.Integer(), nullable=True),
    sa.Column('frequency_phrase', sa.Text(), nullable=True),
    sa.Column('methods', postgresql.JSONB(none_as_null=True, astext_type=sa.Text()), nullable=True),
    sa.Column('retention_days', sa.Integer(), nullable=True),
    sa.Column('retention_phrase', sa.Text(), nullable=True),
    sa.Column('rpo_minutes', sa.Integer(), nullable=True),
    sa.Column('rto_minutes', sa.Integer(), nullable=True),
    sa.Column('objective_phrase', sa.Text(), nullable=True),
    sa.Column('page_updated_on', sa.Date(), nullable=True),
    sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('verification_status', sa.Text(), server_default='claimed', nullable=False),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("assertion IN ('affirmed', 'negated')", name=op.f('ck_backup_policy_claims_assertion')),
    sa.CheckConstraint("frequency_class IS DISTINCT FROM 'continuous' OR interval_minutes IS NULL", name=op.f('ck_backup_policy_claims_continuous_has_no_interval')),
    sa.CheckConstraint("frequency_class IS NULL OR frequency_class IN ('continuous', 'sub_hourly', 'hourly', 'sub_daily', 'daily', 'weekly', 'monthly', 'other')", name=op.f('ck_backup_policy_claims_frequency_class')),
    sa.CheckConstraint("scope IN ('own_practice', 'product_capability', 'customer_responsibility')", name=op.f('ck_backup_policy_claims_scope')),
    sa.CheckConstraint('methods IS NULL OR methods <@ \'["full", "incremental", "differential", "snapshot", "replication"]\'::jsonb', name=op.f('ck_backup_policy_claims_methods')),
    sa.CheckConstraint("verification_status = 'claimed'", name=op.f('ck_backup_policy_claims_always_claimed')),
    sa.CheckConstraint('(frequency_class IS NULL) = (frequency_phrase IS NULL)', name=op.f('ck_backup_policy_claims_frequency_phrase')),
    sa.CheckConstraint('frequency_class IS NOT NULL OR interval_minutes IS NULL', name=op.f('ck_backup_policy_claims_interval_needs_frequency')),
    sa.CheckConstraint('interval_minutes IS NULL OR interval_minutes > 0', name=op.f('ck_backup_policy_claims_interval_minutes')),
    sa.CheckConstraint('length(trim(quote)) > 0', name=op.f('ck_backup_policy_claims_quote_not_blank')),
    sa.CheckConstraint('retention_days IS NULL OR retention_days > 0', name=op.f('ck_backup_policy_claims_retention_days')),
    sa.CheckConstraint('rpo_minutes IS NULL OR rpo_minutes >= 0', name=op.f('ck_backup_policy_claims_rpo_minutes')),
    sa.CheckConstraint('rto_minutes IS NULL OR rto_minutes >= 0', name=op.f('ck_backup_policy_claims_rto_minutes')),
    sa.ForeignKeyConstraint(['claim_id'], ['security_control_claims.id'], name=op.f('fk_backup_policy_claims_claim_id_security_control_claims'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['company_id'], ['companies.id'], name=op.f('fk_backup_policy_claims_company_id_companies'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['evidence_version_id'], ['evidence_versions.id'], name=op.f('fk_backup_policy_claims_evidence_version_id_evidence_versions'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['legal_entity_id'], ['legal_entities.id'], name=op.f('fk_backup_policy_claims_legal_entity_id_legal_entities'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_backup_policy_claims')),
    sa.UniqueConstraint('evidence_version_id', 'claim_hash', 'frequency_phrase', name='uq_backup_policy_claims_statement', postgresql_nulls_not_distinct=True)
    )
    op.create_index(op.f('ix_backup_policy_claims_claim_id'), 'backup_policy_claims', ['claim_id'], unique=False)
    op.create_index(op.f('ix_backup_policy_claims_company_id'), 'backup_policy_claims', ['company_id'], unique=False)
    op.create_index(op.f('ix_backup_policy_claims_evidence_version_id'), 'backup_policy_claims', ['evidence_version_id'], unique=False)
    op.create_index(op.f('ix_backup_policy_claims_frequency_class'), 'backup_policy_claims', ['frequency_class'], unique=False)
    op.create_index(op.f('ix_backup_policy_claims_legal_entity_id'), 'backup_policy_claims', ['legal_entity_id'], unique=False)
    op.execute(VIEW)


def downgrade() -> None:
    op.execute("DROP VIEW IF EXISTS company_backup_frequencies")
    op.drop_index(op.f('ix_backup_policy_claims_legal_entity_id'), table_name='backup_policy_claims')
    op.drop_index(op.f('ix_backup_policy_claims_frequency_class'), table_name='backup_policy_claims')
    op.drop_index(op.f('ix_backup_policy_claims_evidence_version_id'), table_name='backup_policy_claims')
    op.drop_index(op.f('ix_backup_policy_claims_company_id'), table_name='backup_policy_claims')
    op.drop_index(op.f('ix_backup_policy_claims_claim_id'), table_name='backup_policy_claims')
    op.drop_table('backup_policy_claims')
