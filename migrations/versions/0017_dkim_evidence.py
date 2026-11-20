"""DKIM keys at selectors known from public evidence (issue 23.3).

``dkim_evidence`` keeps one row per selector asked (the DNS lookup is in ``dns_security_records``),
with how the selector is known: a provider the domain's SPF authorizes and that documents its
selectors, or a published source. A domain with no known selector gets one ``no_known_selector``
row: unknown, never "no DKIM".

Revision ID: 0017
Revises: 0016
Create Date: 2026-11-20 04:17:58.284030
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = '0017'
down_revision: str | None = '0016'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('dkim_evidence',
    sa.Column('company_id', sa.BigInteger(), nullable=True),
    sa.Column('domain_id', sa.BigInteger(), nullable=False),
    sa.Column('selector', sa.Text(), nullable=True),
    sa.Column('selector_source', sa.Text(), nullable=True),
    sa.Column('selector_evidence', sa.Text(), nullable=True),
    sa.Column('selector_source_url', sa.Text(), nullable=True),
    sa.Column('dns_record_id', sa.BigInteger(), nullable=True),
    sa.Column('outcome', sa.Text(), nullable=False),
    sa.Column('key_type', sa.Text(), nullable=True),
    sa.Column('key_bits', sa.Integer(), nullable=True),
    sa.Column('record_text', sa.Text(), nullable=True),
    sa.Column('problem', sa.Text(), nullable=True),
    sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('evidence_version_id', sa.BigInteger(), nullable=True),
    sa.Column('ingestion_run_id', sa.BigInteger(), nullable=True),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("(outcome = 'no_known_selector') = (selector IS NULL)", name=op.f('ck_dkim_evidence_selector_unless_none_known')),
    sa.CheckConstraint("outcome <> 'key_found' OR key_type IS NOT NULL", name=op.f('ck_dkim_evidence_key_type_when_found')),
    sa.CheckConstraint("outcome IN ('key_found', 'revoked', 'invalid', 'not_found', 'lookup_failed', 'no_known_selector')", name=op.f('ck_dkim_evidence_outcome')),
    sa.CheckConstraint("selector IS NULL OR selector ~ '^[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)*$'", name=op.f('ck_dkim_evidence_selector_label')),
    sa.CheckConstraint("selector_source IS NULL OR selector_source IN ('spf_provider', 'published')", name=op.f('ck_dkim_evidence_selector_source')),
    sa.CheckConstraint('(selector IS NULL) = (dns_record_id IS NULL)', name=op.f('ck_dkim_evidence_lookup_per_selector')),
    sa.CheckConstraint('(selector IS NULL) = (selector_source IS NULL)', name=op.f('ck_dkim_evidence_selector_has_source')),
    sa.ForeignKeyConstraint(['company_id'], ['companies.id'], name=op.f('fk_dkim_evidence_company_id_companies'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['dns_record_id'], ['dns_security_records.id'], name=op.f('fk_dkim_evidence_dns_record_id_dns_security_records'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['domain_id'], ['domains.id'], name=op.f('fk_dkim_evidence_domain_id_domains'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['evidence_version_id'], ['evidence_versions.id'], name=op.f('fk_dkim_evidence_evidence_version_id_evidence_versions'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['ingestion_run_id'], ['ingestion_runs.id'], name=op.f('fk_dkim_evidence_ingestion_run_id_ingestion_runs'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_dkim_evidence'))
    )
    op.create_index(op.f('ix_dkim_evidence_company_id'), 'dkim_evidence', ['company_id'], unique=False)
    op.create_index(op.f('ix_dkim_evidence_dns_record_id'), 'dkim_evidence', ['dns_record_id'], unique=False)
    op.create_index(op.f('ix_dkim_evidence_domain_id'), 'dkim_evidence', ['domain_id'], unique=False)
    op.create_index(op.f('ix_dkim_evidence_evidence_version_id'), 'dkim_evidence', ['evidence_version_id'], unique=False)
    op.create_index(op.f('ix_dkim_evidence_ingestion_run_id'), 'dkim_evidence', ['ingestion_run_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_dkim_evidence_ingestion_run_id'), table_name='dkim_evidence')
    op.drop_index(op.f('ix_dkim_evidence_evidence_version_id'), table_name='dkim_evidence')
    op.drop_index(op.f('ix_dkim_evidence_domain_id'), table_name='dkim_evidence')
    op.drop_index(op.f('ix_dkim_evidence_dns_record_id'), table_name='dkim_evidence')
    op.drop_index(op.f('ix_dkim_evidence_company_id'), table_name='dkim_evidence')
    op.drop_table('dkim_evidence')
