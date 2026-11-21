"""NVD records: CVSS severity, CWE weaknesses and affected products (issue 5.3).

``vulnerabilities`` keeps one row per CVE looked up in NVD (outcome, NVD status, description, dates,
affected vendor:product pairs, references, the stored record). ``cvss_scores`` keeps every CVSS
assessment with its version, vector and source; ``vulnerability_weaknesses`` the CWE ids. The view
``vulnerability_severity`` picks one labelled score per CVE for ranking (v3.1, then v3.0, v4.0, v2.0;
NVD's Primary first) and lists its CWEs.

Revision ID: 0024
Revises: 0023
Create Date: 2026-11-21 01:56:53.071122
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0024'
down_revision: str | None = '0023'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


SEVERITY_VIEW = """
CREATE VIEW vulnerability_severity AS
SELECT v.id AS vulnerability_id, v.cve_id, v.vuln_status, p.cvss_version, p.base_score, p.base_severity,
       p.vector_string, p.source AS score_source, p.score_type,
       (SELECT array_agg(DISTINCT w.cwe_id ORDER BY w.cwe_id) FROM vulnerability_weaknesses w
         WHERE w.vulnerability_id = v.id AND w.cwe_id LIKE 'CWE-%') AS cwes
FROM vulnerabilities v
LEFT JOIN LATERAL (
    SELECT * FROM cvss_scores x WHERE x.vulnerability_id = v.id
    ORDER BY array_position(ARRAY['3.1', '3.0', '4.0', '2.0'], x.cvss_version),
             (x.score_type = 'Primary') DESC, (x.source = 'nvd@nist.gov') DESC, x.base_score DESC, x.id
    LIMIT 1
) p ON true
WHERE v.outcome = 'found'
"""


def upgrade() -> None:
    op.create_table('vulnerabilities',
    sa.Column('cve_id', sa.Text(), nullable=False),
    sa.Column('outcome', sa.Text(), nullable=False),
    sa.Column('vuln_status', sa.Text(), nullable=True),
    sa.Column('source_identifier', sa.Text(), nullable=True),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('published_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_modified_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('affected_products', postgresql.JSONB(none_as_null=True, astext_type=sa.Text()), nullable=True),
    sa.Column('affected_cpe_count', sa.Integer(), nullable=True),
    sa.Column('references', postgresql.JSONB(none_as_null=True, astext_type=sa.Text()), nullable=True),
    sa.Column('message', sa.Text(), nullable=True),
    sa.Column('retrieved_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('evidence_version_id', sa.BigInteger(), nullable=True),
    sa.Column('ingestion_run_id', sa.BigInteger(), nullable=True),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'", name=op.f('ck_vulnerabilities_cve_id_format')),
    sa.CheckConstraint("outcome <> 'found' OR evidence_version_id IS NOT NULL", name=op.f('ck_vulnerabilities_evidence_when_found')),
    sa.CheckConstraint("outcome IN ('found', 'not_found', 'lookup_failed')", name=op.f('ck_vulnerabilities_outcome')),
    sa.ForeignKeyConstraint(['evidence_version_id'], ['evidence_versions.id'], name=op.f('fk_vulnerabilities_evidence_version_id_evidence_versions'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['ingestion_run_id'], ['ingestion_runs.id'], name=op.f('fk_vulnerabilities_ingestion_run_id_ingestion_runs'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_vulnerabilities')),
    sa.UniqueConstraint('cve_id', name=op.f('uq_vulnerabilities_cve_id'))
    )
    op.create_index(op.f('ix_vulnerabilities_evidence_version_id'), 'vulnerabilities', ['evidence_version_id'], unique=False)
    op.create_index(op.f('ix_vulnerabilities_ingestion_run_id'), 'vulnerabilities', ['ingestion_run_id'], unique=False)
    op.create_table('cvss_scores',
    sa.Column('vulnerability_id', sa.BigInteger(), nullable=False),
    sa.Column('cvss_version', sa.Text(), nullable=False),
    sa.Column('source', sa.Text(), nullable=False),
    sa.Column('score_type', sa.Text(), nullable=True),
    sa.Column('vector_string', sa.Text(), nullable=False),
    sa.Column('base_score', sa.Numeric(precision=3, scale=1), nullable=False),
    sa.Column('base_severity', sa.Text(), nullable=True),
    sa.Column('attack_vector', sa.Text(), nullable=True),
    sa.Column('user_interaction', sa.Text(), nullable=True),
    sa.Column('privileges_required', sa.Text(), nullable=True),
    sa.Column('exploitability_score', sa.Numeric(precision=3, scale=1), nullable=True),
    sa.Column('impact_score', sa.Numeric(precision=3, scale=1), nullable=True),
    sa.Column('evidence_version_id', sa.BigInteger(), nullable=False),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("cvss_version IN ('2.0', '3.0', '3.1', '4.0')", name=op.f('ck_cvss_scores_cvss_version')),
    sa.CheckConstraint('base_score >= 0 AND base_score <= 10', name=op.f('ck_cvss_scores_base_score_range')),
    sa.ForeignKeyConstraint(['evidence_version_id'], ['evidence_versions.id'], name=op.f('fk_cvss_scores_evidence_version_id_evidence_versions'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerabilities.id'], name=op.f('fk_cvss_scores_vulnerability_id_vulnerabilities'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_cvss_scores'))
    )
    op.create_index(op.f('ix_cvss_scores_evidence_version_id'), 'cvss_scores', ['evidence_version_id'], unique=False)
    op.create_index(op.f('ix_cvss_scores_vulnerability_id'), 'cvss_scores', ['vulnerability_id'], unique=False)
    op.create_table('vulnerability_weaknesses',
    sa.Column('vulnerability_id', sa.BigInteger(), nullable=False),
    sa.Column('cwe_id', sa.Text(), nullable=False),
    sa.Column('source', sa.Text(), nullable=False),
    sa.Column('weakness_type', sa.Text(), nullable=True),
    sa.Column('evidence_version_id', sa.BigInteger(), nullable=False),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['evidence_version_id'], ['evidence_versions.id'], name=op.f('fk_vulnerability_weaknesses_evidence_version_id_evidence_versions'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerabilities.id'], name=op.f('fk_vulnerability_weaknesses_vulnerability_id_vulnerabilities'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_vulnerability_weaknesses')),
    sa.UniqueConstraint('vulnerability_id', 'cwe_id', 'source', name='uq_vulnerability_weaknesses_cwe')
    )
    op.create_index(op.f('ix_vulnerability_weaknesses_evidence_version_id'), 'vulnerability_weaknesses', ['evidence_version_id'], unique=False)
    op.create_index(op.f('ix_vulnerability_weaknesses_vulnerability_id'), 'vulnerability_weaknesses', ['vulnerability_id'], unique=False)
    op.execute(SEVERITY_VIEW)


def downgrade() -> None:
    op.execute("DROP VIEW IF EXISTS vulnerability_severity")
    op.drop_index(op.f('ix_vulnerability_weaknesses_vulnerability_id'), table_name='vulnerability_weaknesses')
    op.drop_index(op.f('ix_vulnerability_weaknesses_evidence_version_id'), table_name='vulnerability_weaknesses')
    op.drop_table('vulnerability_weaknesses')
    op.drop_index(op.f('ix_cvss_scores_vulnerability_id'), table_name='cvss_scores')
    op.drop_index(op.f('ix_cvss_scores_evidence_version_id'), table_name='cvss_scores')
    op.drop_table('cvss_scores')
    op.drop_index(op.f('ix_vulnerabilities_ingestion_run_id'), table_name='vulnerabilities')
    op.drop_index(op.f('ix_vulnerabilities_evidence_version_id'), table_name='vulnerabilities')
    op.drop_table('vulnerabilities')
