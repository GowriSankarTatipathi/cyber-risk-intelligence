"""Website security headers (issue 1.2).

``http_security_checks`` keeps one row per request to a company website's home page (outcome,
redirects, whether plain HTTP goes on to HTTPS, assessment version); ``http_security_observations``
keeps each graded header of an answered check. ``latest_http_security_checks`` is the newest check
of each host.

Revision ID: 0016
Revises: 0015
Create Date: 2026-11-20 04:14:11.790475
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

LATEST_VIEW = """
CREATE VIEW latest_http_security_checks AS
SELECT DISTINCT ON (k.host) k.*
FROM http_security_checks k
ORDER BY k.host, k.checked_at DESC, k.id DESC
"""

revision: str = '0016'
down_revision: str | None = '0015'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('http_security_checks',
    sa.Column('domain_id', sa.BigInteger(), nullable=False),
    sa.Column('host', sa.Text(), nullable=False),
    sa.Column('requested_url', sa.Text(), nullable=False),
    sa.Column('checked_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('outcome', sa.Text(), nullable=False),
    sa.Column('message', sa.Text(), nullable=True),
    sa.Column('final_url', sa.Text(), nullable=True),
    sa.Column('http_status', sa.Integer(), nullable=True),
    sa.Column('redirects', postgresql.JSONB(none_as_null=True, astext_type=sa.Text()), nullable=True),
    sa.Column('http_redirect', sa.Text(), nullable=False),
    sa.Column('http_redirect_location', sa.Text(), nullable=True),
    sa.Column('assessment_version', sa.Text(), nullable=False),
    sa.Column('evidence_version_id', sa.BigInteger(), nullable=True),
    sa.Column('ingestion_run_id', sa.BigInteger(), nullable=True),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("(outcome = 'answered') = (evidence_version_id IS NOT NULL)", name=op.f('ck_http_security_checks_evidence_when_answered')),
    sa.CheckConstraint("(outcome = 'answered') = (http_status IS NOT NULL)", name=op.f('ck_http_security_checks_status_when_answered')),
    sa.CheckConstraint("http_redirect IN ('redirects_to_https', 'no_redirect', 'redirects_elsewhere', 'request_failed')", name=op.f('ck_http_security_checks_http_redirect')),
    sa.CheckConstraint("outcome IN ('answered', 'request_failed')", name=op.f('ck_http_security_checks_outcome')),
    sa.ForeignKeyConstraint(['domain_id'], ['domains.id'], name=op.f('fk_http_security_checks_domain_id_domains'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['evidence_version_id'], ['evidence_versions.id'], name=op.f('fk_http_security_checks_evidence_version_id_evidence_versions'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['ingestion_run_id'], ['ingestion_runs.id'], name=op.f('fk_http_security_checks_ingestion_run_id_ingestion_runs'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_http_security_checks'))
    )
    op.create_index(op.f('ix_http_security_checks_domain_id'), 'http_security_checks', ['domain_id'], unique=False)
    op.create_index(op.f('ix_http_security_checks_evidence_version_id'), 'http_security_checks', ['evidence_version_id'], unique=False)
    op.create_index(op.f('ix_http_security_checks_host'), 'http_security_checks', ['host'], unique=False)
    op.create_index(op.f('ix_http_security_checks_ingestion_run_id'), 'http_security_checks', ['ingestion_run_id'], unique=False)
    op.create_table('http_security_observations',
    sa.Column('check_id', sa.BigInteger(), nullable=False),
    sa.Column('domain_id', sa.BigInteger(), nullable=False),
    sa.Column('header', sa.Text(), nullable=False),
    sa.Column('observed_value', sa.Text(), nullable=True),
    sa.Column('value_count', sa.Integer(), nullable=False),
    sa.Column('result', sa.Text(), nullable=False),
    sa.Column('note', sa.Text(), nullable=True),
    sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('evidence_version_id', sa.BigInteger(), nullable=False),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("result <> 'missing' OR value_count = 0", name=op.f('ck_http_security_observations_missing_means_not_sent')),
    sa.CheckConstraint("result IN ('pass', 'weak', 'missing', 'invalid', 'info')", name=op.f('ck_http_security_observations_result')),
    sa.CheckConstraint('(value_count = 0) = (observed_value IS NULL)', name=op.f('ck_http_security_observations_value_when_sent')),
    sa.CheckConstraint('header = lower(header)', name=op.f('ck_http_security_observations_header_lower')),
    sa.ForeignKeyConstraint(['check_id'], ['http_security_checks.id'], name=op.f('fk_http_security_observations_check_id_http_security_checks'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['domain_id'], ['domains.id'], name=op.f('fk_http_security_observations_domain_id_domains'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['evidence_version_id'], ['evidence_versions.id'], name=op.f('fk_http_security_observations_evidence_version_id_evidence_versions'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_http_security_observations')),
    sa.UniqueConstraint('check_id', 'header', name='uq_http_security_observations_check_header')
    )
    op.create_index(op.f('ix_http_security_observations_check_id'), 'http_security_observations', ['check_id'], unique=False)
    op.create_index(op.f('ix_http_security_observations_domain_id'), 'http_security_observations', ['domain_id'], unique=False)
    op.create_index(op.f('ix_http_security_observations_evidence_version_id'), 'http_security_observations', ['evidence_version_id'], unique=False)
    op.execute(LATEST_VIEW)


def downgrade() -> None:
    op.execute("DROP VIEW latest_http_security_checks")
    op.drop_index(op.f('ix_http_security_observations_evidence_version_id'), table_name='http_security_observations')
    op.drop_index(op.f('ix_http_security_observations_domain_id'), table_name='http_security_observations')
    op.drop_index(op.f('ix_http_security_observations_check_id'), table_name='http_security_observations')
    op.drop_table('http_security_observations')
    op.drop_index(op.f('ix_http_security_checks_ingestion_run_id'), table_name='http_security_checks')
    op.drop_index(op.f('ix_http_security_checks_host'), table_name='http_security_checks')
    op.drop_index(op.f('ix_http_security_checks_evidence_version_id'), table_name='http_security_checks')
    op.drop_index(op.f('ix_http_security_checks_domain_id'), table_name='http_security_checks')
    op.drop_table('http_security_checks')
