"""Certificates and hostnames from Certificate Transparency logs (issue 10.1).

Adds ``ct_lookups`` (each crt.sh search and how it ended), ``certificates`` (one
row per issuer + serial number), ``certificate_observations`` (every sighting of
a certificate in a search), ``certificate_hostnames`` (the names a certificate
covers, wildcards flagged), and the views ``latest_ct_lookups`` and
``company_certificate_hostnames``.

Revision ID: 0013
Revises: 0012
Create Date: 2026-11-20
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0013'
down_revision: str | None = '0012'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

LATEST_VIEW = """
CREATE VIEW latest_ct_lookups AS
SELECT DISTINCT ON (l.domain_id) l.*
FROM ct_lookups l
ORDER BY l.domain_id, l.queried_at DESC, l.id DESC
"""

# One row per company and certificate name under one of its current domains. A wildcard is a pattern
# in a certificate, not a host that exists; nothing here says a host is live.
HOSTNAMES_VIEW = """
CREATE VIEW company_certificate_hostnames AS
SELECT cd.company_id,
       h.domain_id,
       h.hostname,
       h.is_wildcard,
       count(DISTINCT c.id) AS certificates,
       string_agg(DISTINCT c.issuer_name, '; ' ORDER BY c.issuer_name) AS issuers,
       min(c.not_before) AS earliest_not_before,
       max(c.not_after) AS latest_not_after,
       bool_or(c.not_before <= now() AND c.not_after >= now()) AS has_current_certificate,
       min(c.first_observed_at) AS first_observed_at,
       max(c.last_observed_at) AS last_observed_at
FROM certificate_hostnames h
JOIN certificates c ON c.id = h.certificate_id
JOIN company_domains cd ON cd.domain_id = h.domain_id AND cd.valid_to IS NULL
GROUP BY cd.company_id, h.domain_id, h.hostname, h.is_wildcard
"""


def upgrade() -> None:
    op.create_table('certificates',
    sa.Column('issuer_name', sa.Text(), nullable=False),
    sa.Column('issuer_ca_id', sa.BigInteger(), nullable=True),
    sa.Column('serial_number', sa.Text(), nullable=False),
    sa.Column('common_name', sa.Text(), nullable=True),
    sa.Column('not_before', sa.DateTime(timezone=True), nullable=True),
    sa.Column('not_after', sa.DateTime(timezone=True), nullable=True),
    sa.Column('first_observed_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_observed_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("serial_number = lower(serial_number) AND serial_number ~ '^[0-9a-f]+$'", name=op.f('ck_certificates_serial_number_hex')),
    sa.CheckConstraint('last_observed_at >= first_observed_at', name=op.f('ck_certificates_observed_dates')),
    sa.CheckConstraint('not_after IS NULL OR not_before IS NULL OR not_after >= not_before', name=op.f('ck_certificates_validity')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_certificates')),
    sa.UniqueConstraint('issuer_name', 'serial_number', name='uq_certificates_issuer_serial')
    )
    op.create_table('certificate_hostnames',
    sa.Column('certificate_id', sa.BigInteger(), nullable=False),
    sa.Column('hostname', sa.Text(), nullable=False),
    sa.Column('is_wildcard', sa.Boolean(), nullable=False),
    sa.Column('base_name', sa.Text(), nullable=False),
    sa.Column('domain_id', sa.BigInteger(), nullable=True),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("hostname = lower(hostname) AND hostname !~ '[/:@ ]'", name=op.f('ck_certificate_hostnames_hostname_normalized')),
    sa.CheckConstraint("is_wildcard = (hostname LIKE '*.%%')", name=op.f('ck_certificate_hostnames_wildcard_flag')),
    sa.CheckConstraint('base_name = CASE WHEN is_wildcard THEN substr(hostname, 3) ELSE hostname END', name=op.f('ck_certificate_hostnames_base_name')),
    sa.ForeignKeyConstraint(['certificate_id'], ['certificates.id'], name=op.f('fk_certificate_hostnames_certificate_id_certificates'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['domain_id'], ['domains.id'], name=op.f('fk_certificate_hostnames_domain_id_domains'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_certificate_hostnames')),
    sa.UniqueConstraint('certificate_id', 'hostname', name='uq_certificate_hostnames_name')
    )
    op.create_index(op.f('ix_certificate_hostnames_certificate_id'), 'certificate_hostnames', ['certificate_id'], unique=False)
    op.create_index(op.f('ix_certificate_hostnames_domain_id'), 'certificate_hostnames', ['domain_id'], unique=False)
    op.create_index(op.f('ix_certificate_hostnames_hostname'), 'certificate_hostnames', ['hostname'], unique=False)
    op.create_table('ct_lookups',
    sa.Column('domain_id', sa.BigInteger(), nullable=False),
    sa.Column('query', sa.Text(), nullable=False),
    sa.Column('source', sa.Text(), nullable=False),
    sa.Column('request_url', sa.Text(), nullable=False),
    sa.Column('queried_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('outcome', sa.Text(), nullable=False),
    sa.Column('http_status', sa.Integer(), nullable=True),
    sa.Column('message', sa.Text(), nullable=True),
    sa.Column('entry_count', sa.Integer(), nullable=True),
    sa.Column('certificate_count', sa.Integer(), nullable=True),
    sa.Column('evidence_version_id', sa.BigInteger(), nullable=True),
    sa.Column('ingestion_run_id', sa.BigInteger(), nullable=True),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("(outcome = 'lookup_failed') = (entry_count IS NULL)", name=op.f('ck_ct_lookups_count_unless_failed')),
    sa.CheckConstraint("(outcome = 'lookup_failed') = (evidence_version_id IS NULL)", name=op.f('ck_ct_lookups_evidence_unless_failed')),
    sa.CheckConstraint("(outcome = 'no_results') = (entry_count = 0)", name=op.f('ck_ct_lookups_no_results_means_zero')),
    sa.CheckConstraint("outcome IN ('answered', 'no_results', 'lookup_failed')", name=op.f('ck_ct_lookups_outcome')),
    sa.CheckConstraint("source IN ('crt.sh')", name=op.f('ck_ct_lookups_source')),
    sa.CheckConstraint('entry_count IS NULL OR entry_count >= 0', name=op.f('ck_ct_lookups_entry_count')),
    sa.ForeignKeyConstraint(['domain_id'], ['domains.id'], name=op.f('fk_ct_lookups_domain_id_domains'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['evidence_version_id'], ['evidence_versions.id'], name=op.f('fk_ct_lookups_evidence_version_id_evidence_versions'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['ingestion_run_id'], ['ingestion_runs.id'], name=op.f('fk_ct_lookups_ingestion_run_id_ingestion_runs'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_ct_lookups'))
    )
    op.create_index(op.f('ix_ct_lookups_domain_id'), 'ct_lookups', ['domain_id'], unique=False)
    op.create_index(op.f('ix_ct_lookups_evidence_version_id'), 'ct_lookups', ['evidence_version_id'], unique=False)
    op.create_index(op.f('ix_ct_lookups_ingestion_run_id'), 'ct_lookups', ['ingestion_run_id'], unique=False)
    op.create_table('certificate_observations',
    sa.Column('certificate_id', sa.BigInteger(), nullable=False),
    sa.Column('ct_lookup_id', sa.BigInteger(), nullable=False),
    sa.Column('log_entry_id', sa.BigInteger(), nullable=False),
    sa.Column('evidence_version_id', sa.BigInteger(), nullable=False),
    sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('source_ref', sa.Text(), nullable=False),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['certificate_id'], ['certificates.id'], name=op.f('fk_certificate_observations_certificate_id_certificates'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['ct_lookup_id'], ['ct_lookups.id'], name=op.f('fk_certificate_observations_ct_lookup_id_ct_lookups'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['evidence_version_id'], ['evidence_versions.id'], name=op.f('fk_certificate_observations_evidence_version_id_evidence_versions'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_certificate_observations')),
    sa.UniqueConstraint('ct_lookup_id', 'log_entry_id', name='uq_certificate_observations_lookup_entry')
    )
    op.create_index(op.f('ix_certificate_observations_certificate_id'), 'certificate_observations', ['certificate_id'], unique=False)
    op.create_index(op.f('ix_certificate_observations_ct_lookup_id'), 'certificate_observations', ['ct_lookup_id'], unique=False)
    op.create_index(op.f('ix_certificate_observations_evidence_version_id'), 'certificate_observations', ['evidence_version_id'], unique=False)
    op.execute(LATEST_VIEW)
    op.execute(HOSTNAMES_VIEW)


def downgrade() -> None:
    op.execute("DROP VIEW IF EXISTS company_certificate_hostnames")
    op.execute("DROP VIEW IF EXISTS latest_ct_lookups")
    op.drop_index(op.f('ix_certificate_observations_evidence_version_id'), table_name='certificate_observations')
    op.drop_index(op.f('ix_certificate_observations_ct_lookup_id'), table_name='certificate_observations')
    op.drop_index(op.f('ix_certificate_observations_certificate_id'), table_name='certificate_observations')
    op.drop_table('certificate_observations')
    op.drop_index(op.f('ix_ct_lookups_ingestion_run_id'), table_name='ct_lookups')
    op.drop_index(op.f('ix_ct_lookups_evidence_version_id'), table_name='ct_lookups')
    op.drop_index(op.f('ix_ct_lookups_domain_id'), table_name='ct_lookups')
    op.drop_table('ct_lookups')
    op.drop_index(op.f('ix_certificate_hostnames_hostname'), table_name='certificate_hostnames')
    op.drop_index(op.f('ix_certificate_hostnames_domain_id'), table_name='certificate_hostnames')
    op.drop_index(op.f('ix_certificate_hostnames_certificate_id'), table_name='certificate_hostnames')
    op.drop_table('certificate_hostnames')
    op.drop_table('certificates')
