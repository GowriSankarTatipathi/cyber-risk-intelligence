"""MTA-STS and SMTP TLS reporting (issue 23.4).

``mta_sts_observations`` keeps, per domain and run, the ``_mta-sts`` DNS record, the policy fetch
(``https://mta-sts.<domain>/.well-known/mta-sts.txt``, only when DNS announces a policy) and what the
policy says. A failed lookup or fetch is kept apart from "no MTA-STS". ``tls_reporting_observations``
keeps the ``_smtp._tls`` record and its report addresses (recorded, never contacted).

Revision ID: 0018
Revises: 0017
Create Date: 2026-11-20 04:22:27.727274
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0018'
down_revision: str | None = '0017'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('mta_sts_observations',
    sa.Column('company_id', sa.BigInteger(), nullable=True),
    sa.Column('domain_id', sa.BigInteger(), nullable=False),
    sa.Column('dns_record_id', sa.BigInteger(), nullable=False),
    sa.Column('dns_status', sa.Text(), nullable=False),
    sa.Column('record_text', sa.Text(), nullable=True),
    sa.Column('sts_id', sa.Text(), nullable=True),
    sa.Column('policy_url', sa.Text(), nullable=False),
    sa.Column('policy_retrieval', sa.Text(), nullable=False),
    sa.Column('policy_http_status', sa.Integer(), nullable=True),
    sa.Column('policy_status', sa.Text(), nullable=True),
    sa.Column('mode', sa.Text(), nullable=True),
    sa.Column('mx_patterns', postgresql.JSONB(none_as_null=True, astext_type=sa.Text()), nullable=True),
    sa.Column('max_age', sa.Integer(), nullable=True),
    sa.Column('problems', postgresql.JSONB(none_as_null=True, astext_type=sa.Text()), nullable=True),
    sa.Column('message', sa.Text(), nullable=True),
    sa.Column('policy_evidence_version_id', sa.BigInteger(), nullable=True),
    sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('ingestion_run_id', sa.BigInteger(), nullable=True),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("(policy_retrieval = 'not_attempted') = (dns_status NOT IN ('present', 'invalid', 'multiple'))", name=op.f('ck_mta_sts_observations_fetch_only_when_announced')),
    sa.CheckConstraint("(policy_retrieval = 'retrieved') = (policy_evidence_version_id IS NOT NULL)", name=op.f('ck_mta_sts_observations_evidence_when_retrieved')),
    sa.CheckConstraint("(policy_retrieval = 'retrieved') = (policy_status IS NOT NULL)", name=op.f('ck_mta_sts_observations_status_when_retrieved')),
    sa.CheckConstraint("dns_status IN ('present', 'missing', 'invalid', 'multiple', 'lookup_failed')", name=op.f('ck_mta_sts_observations_dns_status')),
    sa.CheckConstraint("mode IS NULL OR mode IN ('enforce', 'testing', 'none')", name=op.f('ck_mta_sts_observations_mode')),
    sa.CheckConstraint("policy_retrieval IN ('retrieved', 'not_found', 'certificate_invalid', 'request_failed', 'not_attempted')", name=op.f('ck_mta_sts_observations_policy_retrieval')),
    sa.CheckConstraint("policy_status IS NULL OR policy_status IN ('valid', 'invalid')", name=op.f('ck_mta_sts_observations_policy_status')),
    sa.ForeignKeyConstraint(['company_id'], ['companies.id'], name=op.f('fk_mta_sts_observations_company_id_companies'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['dns_record_id'], ['dns_security_records.id'], name=op.f('fk_mta_sts_observations_dns_record_id_dns_security_records'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['domain_id'], ['domains.id'], name=op.f('fk_mta_sts_observations_domain_id_domains'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['ingestion_run_id'], ['ingestion_runs.id'], name=op.f('fk_mta_sts_observations_ingestion_run_id_ingestion_runs'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['policy_evidence_version_id'], ['evidence_versions.id'], name=op.f('fk_mta_sts_observations_policy_evidence_version_id_evidence_versions'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_mta_sts_observations'))
    )
    op.create_index(op.f('ix_mta_sts_observations_company_id'), 'mta_sts_observations', ['company_id'], unique=False)
    op.create_index(op.f('ix_mta_sts_observations_dns_record_id'), 'mta_sts_observations', ['dns_record_id'], unique=False)
    op.create_index(op.f('ix_mta_sts_observations_domain_id'), 'mta_sts_observations', ['domain_id'], unique=False)
    op.create_index(op.f('ix_mta_sts_observations_ingestion_run_id'), 'mta_sts_observations', ['ingestion_run_id'], unique=False)
    op.create_index(op.f('ix_mta_sts_observations_policy_evidence_version_id'), 'mta_sts_observations', ['policy_evidence_version_id'], unique=False)
    op.create_table('tls_reporting_observations',
    sa.Column('company_id', sa.BigInteger(), nullable=True),
    sa.Column('domain_id', sa.BigInteger(), nullable=False),
    sa.Column('dns_record_id', sa.BigInteger(), nullable=False),
    sa.Column('status', sa.Text(), nullable=False),
    sa.Column('record_text', sa.Text(), nullable=True),
    sa.Column('report_uris', postgresql.JSONB(none_as_null=True, astext_type=sa.Text()), nullable=True),
    sa.Column('problems', postgresql.JSONB(none_as_null=True, astext_type=sa.Text()), nullable=True),
    sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('evidence_version_id', sa.BigInteger(), nullable=True),
    sa.Column('ingestion_run_id', sa.BigInteger(), nullable=True),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("(status = 'lookup_failed') = (evidence_version_id IS NULL)", name=op.f('ck_tls_reporting_observations_evidence_unless_failed')),
    sa.CheckConstraint("status IN ('present', 'missing', 'invalid', 'multiple', 'lookup_failed')", name=op.f('ck_tls_reporting_observations_status')),
    sa.ForeignKeyConstraint(['company_id'], ['companies.id'], name=op.f('fk_tls_reporting_observations_company_id_companies'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['dns_record_id'], ['dns_security_records.id'], name=op.f('fk_tls_reporting_observations_dns_record_id_dns_security_records'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['domain_id'], ['domains.id'], name=op.f('fk_tls_reporting_observations_domain_id_domains'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['evidence_version_id'], ['evidence_versions.id'], name=op.f('fk_tls_reporting_observations_evidence_version_id_evidence_versions'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['ingestion_run_id'], ['ingestion_runs.id'], name=op.f('fk_tls_reporting_observations_ingestion_run_id_ingestion_runs'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_tls_reporting_observations'))
    )
    op.create_index(op.f('ix_tls_reporting_observations_company_id'), 'tls_reporting_observations', ['company_id'], unique=False)
    op.create_index(op.f('ix_tls_reporting_observations_dns_record_id'), 'tls_reporting_observations', ['dns_record_id'], unique=False)
    op.create_index(op.f('ix_tls_reporting_observations_domain_id'), 'tls_reporting_observations', ['domain_id'], unique=False)
    op.create_index(op.f('ix_tls_reporting_observations_evidence_version_id'), 'tls_reporting_observations', ['evidence_version_id'], unique=False)
    op.create_index(op.f('ix_tls_reporting_observations_ingestion_run_id'), 'tls_reporting_observations', ['ingestion_run_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_tls_reporting_observations_ingestion_run_id'), table_name='tls_reporting_observations')
    op.drop_index(op.f('ix_tls_reporting_observations_evidence_version_id'), table_name='tls_reporting_observations')
    op.drop_index(op.f('ix_tls_reporting_observations_domain_id'), table_name='tls_reporting_observations')
    op.drop_index(op.f('ix_tls_reporting_observations_dns_record_id'), table_name='tls_reporting_observations')
    op.drop_index(op.f('ix_tls_reporting_observations_company_id'), table_name='tls_reporting_observations')
    op.drop_table('tls_reporting_observations')
    op.drop_index(op.f('ix_mta_sts_observations_policy_evidence_version_id'), table_name='mta_sts_observations')
    op.drop_index(op.f('ix_mta_sts_observations_ingestion_run_id'), table_name='mta_sts_observations')
    op.drop_index(op.f('ix_mta_sts_observations_domain_id'), table_name='mta_sts_observations')
    op.drop_index(op.f('ix_mta_sts_observations_dns_record_id'), table_name='mta_sts_observations')
    op.drop_index(op.f('ix_mta_sts_observations_company_id'), table_name='mta_sts_observations')
    op.drop_table('mta_sts_observations')
