"""The certificate each company website presents (issue 10.1 follow-up).

``website_certificate_checks`` keeps one row per TLS handshake with a company's known domain or its
``www.`` host: whether a browser would trust the certificate, why not, and the certificate's issuer,
names and dates. ``latest_website_certificates`` is the newest check of each host.

Revision ID: 0015
Revises: 0014
Create Date: 2026-11-20 03:25:47.797090
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

LATEST_VIEW = """
CREATE VIEW latest_website_certificates AS
SELECT DISTINCT ON (w.host) w.*
FROM website_certificate_checks w
ORDER BY w.host, w.checked_at DESC, w.id DESC
"""

revision: str = '0015'
down_revision: str | None = '0014'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('website_certificate_checks',
    sa.Column('domain_id', sa.BigInteger(), nullable=False),
    sa.Column('host', sa.Text(), nullable=False),
    sa.Column('port', sa.Integer(), server_default='443', nullable=False),
    sa.Column('checked_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('outcome', sa.Text(), nullable=False),
    sa.Column('message', sa.Text(), nullable=True),
    sa.Column('tls_version', sa.Text(), nullable=True),
    sa.Column('cert_sha256', sa.Text(), nullable=True),
    sa.Column('serial_number', sa.Text(), nullable=True),
    sa.Column('issuer_name', sa.Text(), nullable=True),
    sa.Column('subject_name', sa.Text(), nullable=True),
    sa.Column('common_name', sa.Text(), nullable=True),
    sa.Column('names', postgresql.JSONB(none_as_null=True, astext_type=sa.Text()), nullable=True),
    sa.Column('not_before', sa.DateTime(timezone=True), nullable=True),
    sa.Column('not_after', sa.DateTime(timezone=True), nullable=True),
    sa.Column('evidence_version_id', sa.BigInteger(), nullable=True),
    sa.Column('ingestion_run_id', sa.BigInteger(), nullable=True),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("(outcome = 'unreachable') = (cert_sha256 IS NULL)", name=op.f('ck_website_certificate_checks_certificate_unless_unreachable')),
    sa.CheckConstraint("(outcome = 'unreachable') = (evidence_version_id IS NULL)", name=op.f('ck_website_certificate_checks_evidence_unless_unreachable')),
    sa.CheckConstraint("cert_sha256 IS NULL OR cert_sha256 ~ '^[0-9a-f]{64}$'", name=op.f('ck_website_certificate_checks_cert_sha256_hex')),
    sa.CheckConstraint("outcome IN ('trusted', 'not_trusted', 'unreachable')", name=op.f('ck_website_certificate_checks_outcome')),
    sa.CheckConstraint("serial_number IS NULL OR serial_number ~ '^[0-9a-f]+$'", name=op.f('ck_website_certificate_checks_serial_number_hex')),
    sa.CheckConstraint('port BETWEEN 1 AND 65535', name=op.f('ck_website_certificate_checks_port')),
    sa.ForeignKeyConstraint(['domain_id'], ['domains.id'], name=op.f('fk_website_certificate_checks_domain_id_domains'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['evidence_version_id'], ['evidence_versions.id'], name=op.f('fk_website_certificate_checks_evidence_version_id_evidence_versions'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['ingestion_run_id'], ['ingestion_runs.id'], name=op.f('fk_website_certificate_checks_ingestion_run_id_ingestion_runs'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_website_certificate_checks'))
    )
    op.create_index(op.f('ix_website_certificate_checks_cert_sha256'), 'website_certificate_checks', ['cert_sha256'], unique=False)
    op.create_index(op.f('ix_website_certificate_checks_domain_id'), 'website_certificate_checks', ['domain_id'], unique=False)
    op.create_index(op.f('ix_website_certificate_checks_evidence_version_id'), 'website_certificate_checks', ['evidence_version_id'], unique=False)
    op.create_index(op.f('ix_website_certificate_checks_host'), 'website_certificate_checks', ['host'], unique=False)
    op.create_index(op.f('ix_website_certificate_checks_ingestion_run_id'), 'website_certificate_checks', ['ingestion_run_id'], unique=False)
    op.execute(LATEST_VIEW)


def downgrade() -> None:
    op.execute("DROP VIEW latest_website_certificates")
    op.drop_index(op.f('ix_website_certificate_checks_ingestion_run_id'), table_name='website_certificate_checks')
    op.drop_index(op.f('ix_website_certificate_checks_host'), table_name='website_certificate_checks')
    op.drop_index(op.f('ix_website_certificate_checks_evidence_version_id'), table_name='website_certificate_checks')
    op.drop_index(op.f('ix_website_certificate_checks_domain_id'), table_name='website_certificate_checks')
    op.drop_index(op.f('ix_website_certificate_checks_cert_sha256'), table_name='website_certificate_checks')
    op.drop_table('website_certificate_checks')
