"""SPF record collection (issue 23.1).

Adds ``dns_security_records`` (one row per public DNS query and how it ended),
``email_security_observations`` (what a lookup shows for SPF: present, missing,
multiple, invalid, no_domain or lookup_failed, with the parsed record) and the
``latest_spf_observations`` view (each domain's most recent SPF observation).

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-19
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0009'
down_revision: str | None = '0008'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


LATEST_SPF_VIEW = """
CREATE VIEW latest_spf_observations AS
SELECT DISTINCT ON (o.company_id, o.domain_id) o.*
FROM email_security_observations o
WHERE o.control = 'spf'
ORDER BY o.company_id, o.domain_id, o.observed_at DESC, o.id DESC
"""


def upgrade() -> None:
    op.create_table('dns_security_records',
    sa.Column('domain_id', sa.BigInteger(), nullable=False),
    sa.Column('query_name', sa.Text(), nullable=False),
    sa.Column('record_type', sa.Text(), nullable=False),
    sa.Column('resolver', sa.Text(), nullable=False),
    sa.Column('queried_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('outcome', sa.Text(), nullable=False),
    sa.Column('rcode', sa.Text(), nullable=True),
    sa.Column('message', sa.Text(), nullable=True),
    sa.Column('answers', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('ttl', sa.Integer(), nullable=True),
    sa.Column('evidence_version_id', sa.BigInteger(), nullable=True),
    sa.Column('ingestion_run_id', sa.BigInteger(), nullable=True),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("(outcome = 'answered') = (answers IS NOT NULL)", name=op.f('ck_dns_security_records_answers_only_when_answered')),
    sa.CheckConstraint("(outcome = 'lookup_failed') = (evidence_version_id IS NULL)", name=op.f('ck_dns_security_records_evidence_unless_failed')),
    sa.CheckConstraint("outcome IN ('answered', 'no_records', 'nxdomain', 'lookup_failed')", name=op.f('ck_dns_security_records_outcome')),
    sa.CheckConstraint("record_type IN ('TXT')", name=op.f('ck_dns_security_records_record_type')),
    sa.CheckConstraint('ttl IS NULL OR ttl >= 0', name=op.f('ck_dns_security_records_ttl')),
    sa.ForeignKeyConstraint(['domain_id'], ['domains.id'], name=op.f('fk_dns_security_records_domain_id_domains'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['evidence_version_id'], ['evidence_versions.id'], name=op.f('fk_dns_security_records_evidence_version_id_evidence_versions'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['ingestion_run_id'], ['ingestion_runs.id'], name=op.f('fk_dns_security_records_ingestion_run_id_ingestion_runs'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_dns_security_records'))
    )
    op.create_index(op.f('ix_dns_security_records_domain_id'), 'dns_security_records', ['domain_id'], unique=False)
    op.create_index(op.f('ix_dns_security_records_evidence_version_id'), 'dns_security_records', ['evidence_version_id'], unique=False)
    op.create_index(op.f('ix_dns_security_records_ingestion_run_id'), 'dns_security_records', ['ingestion_run_id'], unique=False)
    op.create_table('email_security_observations',
    sa.Column('company_id', sa.BigInteger(), nullable=True),
    sa.Column('domain_id', sa.BigInteger(), nullable=False),
    sa.Column('dns_record_id', sa.BigInteger(), nullable=False),
    sa.Column('control', sa.Text(), nullable=False),
    sa.Column('status', sa.Text(), nullable=False),
    sa.Column('record_text', sa.Text(), nullable=True),
    sa.Column('record_count', sa.Integer(), nullable=True),
    sa.Column('all_qualifier', sa.Text(), nullable=True),
    sa.Column('redirect', sa.Text(), nullable=True),
    sa.Column('mechanisms', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('modifiers', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('dns_lookup_terms', sa.Integer(), nullable=True),
    sa.Column('problems', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('evidence_version_id', sa.BigInteger(), nullable=True),
    sa.Column('source_ref', sa.Text(), nullable=True),
    sa.Column('verification_status', sa.Text(), server_default='observed', nullable=False),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("(status = 'lookup_failed') = (evidence_version_id IS NULL)", name=op.f('ck_email_security_observations_evidence_unless_failed')),
    sa.CheckConstraint("(status IN ('present', 'invalid', 'multiple')) = (record_text IS NOT NULL)", name=op.f('ck_email_security_observations_record_text_matches_status')),
    sa.CheckConstraint("all_qualifier IS NULL OR all_qualifier IN ('pass', 'fail', 'softfail', 'neutral')", name=op.f('ck_email_security_observations_all_qualifier')),
    sa.CheckConstraint("control IN ('spf')", name=op.f('ck_email_security_observations_control')),
    sa.CheckConstraint("status IN ('present', 'missing', 'multiple', 'invalid', 'no_domain', 'lookup_failed')", name=op.f('ck_email_security_observations_status')),
    sa.CheckConstraint("verification_status = 'observed'", name=op.f('ck_email_security_observations_verification_status')),
    sa.CheckConstraint('dns_lookup_terms IS NULL OR dns_lookup_terms >= 0', name=op.f('ck_email_security_observations_dns_lookup_terms')),
    sa.ForeignKeyConstraint(['company_id'], ['companies.id'], name=op.f('fk_email_security_observations_company_id_companies'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['dns_record_id'], ['dns_security_records.id'], name=op.f('fk_email_security_observations_dns_record_id_dns_security_records'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['domain_id'], ['domains.id'], name=op.f('fk_email_security_observations_domain_id_domains'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['evidence_version_id'], ['evidence_versions.id'], name=op.f('fk_email_security_observations_evidence_version_id_evidence_versions'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_email_security_observations')),
    sa.UniqueConstraint('dns_record_id', 'control', name='uq_email_security_observations_lookup_control')
    )
    op.create_index(op.f('ix_email_security_observations_company_id'), 'email_security_observations', ['company_id'], unique=False)
    op.create_index(op.f('ix_email_security_observations_dns_record_id'), 'email_security_observations', ['dns_record_id'], unique=False)
    op.create_index(op.f('ix_email_security_observations_domain_id'), 'email_security_observations', ['domain_id'], unique=False)
    op.create_index(op.f('ix_email_security_observations_evidence_version_id'), 'email_security_observations', ['evidence_version_id'], unique=False)
    op.execute(LATEST_SPF_VIEW)


def downgrade() -> None:
    op.execute("DROP VIEW IF EXISTS latest_spf_observations")
    op.drop_index(op.f('ix_email_security_observations_evidence_version_id'), table_name='email_security_observations')
    op.drop_index(op.f('ix_email_security_observations_domain_id'), table_name='email_security_observations')
    op.drop_index(op.f('ix_email_security_observations_dns_record_id'), table_name='email_security_observations')
    op.drop_index(op.f('ix_email_security_observations_company_id'), table_name='email_security_observations')
    op.drop_table('email_security_observations')
    op.drop_index(op.f('ix_dns_security_records_ingestion_run_id'), table_name='dns_security_records')
    op.drop_index(op.f('ix_dns_security_records_evidence_version_id'), table_name='dns_security_records')
    op.drop_index(op.f('ix_dns_security_records_domain_id'), table_name='dns_security_records')
    op.drop_table('dns_security_records')
