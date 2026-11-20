"""Indexed exposure from Shodan InternetDB (issue 10.3).

``indexed_host_lookups`` keeps one row per (company host, IP) per run: the outcome, Shodan's tags,
host names, software and inferred CVEs, and ``attribution`` (cdn / company_only / shared / unknown).
``indexed_service_observations`` keeps one row per indexed port. Indexed data, not verified; the
scan date is unknown because InternetDB gives none.

Revision ID: 0020
Revises: 0019
Create Date: 2026-11-20 05:35:50.693979
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0020'
down_revision: str | None = '0019'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('indexed_host_lookups',
    sa.Column('company_id', sa.BigInteger(), nullable=True),
    sa.Column('domain_id', sa.BigInteger(), nullable=False),
    sa.Column('host', sa.Text(), nullable=False),
    sa.Column('host_role', sa.Text(), nullable=False),
    sa.Column('ip', postgresql.INET(), nullable=True),
    sa.Column('source', sa.Text(), nullable=False),
    sa.Column('outcome', sa.Text(), nullable=False),
    sa.Column('attribution', sa.Text(), nullable=True),
    sa.Column('tags', postgresql.JSONB(none_as_null=True, astext_type=sa.Text()), nullable=True),
    sa.Column('hostnames', postgresql.JSONB(none_as_null=True, astext_type=sa.Text()), nullable=True),
    sa.Column('cpes', postgresql.JSONB(none_as_null=True, astext_type=sa.Text()), nullable=True),
    sa.Column('potential_vulns', postgresql.JSONB(none_as_null=True, astext_type=sa.Text()), nullable=True),
    sa.Column('source_scan_date', sa.Date(), nullable=True),
    sa.Column('message', sa.Text(), nullable=True),
    sa.Column('retrieved_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('evidence_version_id', sa.BigInteger(), nullable=True),
    sa.Column('ingestion_run_id', sa.BigInteger(), nullable=True),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("(ip IS NULL) = (outcome IN ('dns_failed', 'no_address'))", name=op.f('ck_indexed_host_lookups_ip_unless_unresolved')),
    sa.CheckConstraint("(outcome = 'found') = (attribution IS NOT NULL)", name=op.f('ck_indexed_host_lookups_attribution_when_found')),
    sa.CheckConstraint("(outcome = 'found') = (evidence_version_id IS NOT NULL)", name=op.f('ck_indexed_host_lookups_evidence_when_found')),
    sa.CheckConstraint("attribution IS NULL OR attribution IN ('cdn', 'company_only', 'shared', 'unknown')", name=op.f('ck_indexed_host_lookups_attribution')),
    sa.CheckConstraint("host_role IN ('website', 'mail')", name=op.f('ck_indexed_host_lookups_host_role')),
    sa.CheckConstraint("outcome IN ('found', 'not_indexed', 'lookup_failed', 'dns_failed', 'no_address')", name=op.f('ck_indexed_host_lookups_outcome')),
    sa.ForeignKeyConstraint(['company_id'], ['companies.id'], name=op.f('fk_indexed_host_lookups_company_id_companies'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['domain_id'], ['domains.id'], name=op.f('fk_indexed_host_lookups_domain_id_domains'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['evidence_version_id'], ['evidence_versions.id'], name=op.f('fk_indexed_host_lookups_evidence_version_id_evidence_versions'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['ingestion_run_id'], ['ingestion_runs.id'], name=op.f('fk_indexed_host_lookups_ingestion_run_id_ingestion_runs'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_indexed_host_lookups'))
    )
    op.create_index(op.f('ix_indexed_host_lookups_company_id'), 'indexed_host_lookups', ['company_id'], unique=False)
    op.create_index(op.f('ix_indexed_host_lookups_domain_id'), 'indexed_host_lookups', ['domain_id'], unique=False)
    op.create_index(op.f('ix_indexed_host_lookups_evidence_version_id'), 'indexed_host_lookups', ['evidence_version_id'], unique=False)
    op.create_index(op.f('ix_indexed_host_lookups_ingestion_run_id'), 'indexed_host_lookups', ['ingestion_run_id'], unique=False)
    op.create_index(op.f('ix_indexed_host_lookups_ip'), 'indexed_host_lookups', ['ip'], unique=False)
    op.create_table('indexed_service_observations',
    sa.Column('lookup_id', sa.BigInteger(), nullable=False),
    sa.Column('company_id', sa.BigInteger(), nullable=True),
    sa.Column('domain_id', sa.BigInteger(), nullable=False),
    sa.Column('ip', postgresql.INET(), nullable=False),
    sa.Column('port', sa.Integer(), nullable=False),
    sa.Column('service_hint', sa.Text(), nullable=True),
    sa.Column('sensitive', sa.Boolean(), nullable=False),
    sa.Column('attribution', sa.Text(), nullable=False),
    sa.Column('source', sa.Text(), nullable=False),
    sa.Column('source_scan_date', sa.Date(), nullable=True),
    sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('evidence_version_id', sa.BigInteger(), nullable=False),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("attribution IN ('cdn', 'company_only', 'shared', 'unknown')", name=op.f('ck_indexed_service_observations_attribution')),
    sa.CheckConstraint('port BETWEEN 1 AND 65535', name=op.f('ck_indexed_service_observations_port_range')),
    sa.ForeignKeyConstraint(['company_id'], ['companies.id'], name=op.f('fk_indexed_service_observations_company_id_companies'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['domain_id'], ['domains.id'], name=op.f('fk_indexed_service_observations_domain_id_domains'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['evidence_version_id'], ['evidence_versions.id'], name=op.f('fk_indexed_service_observations_evidence_version_id_evidence_versions'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['lookup_id'], ['indexed_host_lookups.id'], name=op.f('fk_indexed_service_observations_lookup_id_indexed_host_lookups'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_indexed_service_observations'))
    )
    op.create_index(op.f('ix_indexed_service_observations_company_id'), 'indexed_service_observations', ['company_id'], unique=False)
    op.create_index(op.f('ix_indexed_service_observations_domain_id'), 'indexed_service_observations', ['domain_id'], unique=False)
    op.create_index(op.f('ix_indexed_service_observations_evidence_version_id'), 'indexed_service_observations', ['evidence_version_id'], unique=False)
    op.create_index(op.f('ix_indexed_service_observations_lookup_id'), 'indexed_service_observations', ['lookup_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_indexed_service_observations_lookup_id'), table_name='indexed_service_observations')
    op.drop_index(op.f('ix_indexed_service_observations_evidence_version_id'), table_name='indexed_service_observations')
    op.drop_index(op.f('ix_indexed_service_observations_domain_id'), table_name='indexed_service_observations')
    op.drop_index(op.f('ix_indexed_service_observations_company_id'), table_name='indexed_service_observations')
    op.drop_table('indexed_service_observations')
    op.drop_index(op.f('ix_indexed_host_lookups_ip'), table_name='indexed_host_lookups')
    op.drop_index(op.f('ix_indexed_host_lookups_ingestion_run_id'), table_name='indexed_host_lookups')
    op.drop_index(op.f('ix_indexed_host_lookups_evidence_version_id'), table_name='indexed_host_lookups')
    op.drop_index(op.f('ix_indexed_host_lookups_domain_id'), table_name='indexed_host_lookups')
    op.drop_index(op.f('ix_indexed_host_lookups_company_id'), table_name='indexed_host_lookups')
    op.drop_table('indexed_host_lookups')
