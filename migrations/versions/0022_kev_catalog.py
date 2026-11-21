"""CISA Known Exploited Vulnerabilities catalog (issue 5.1).

``kev_catalog_releases`` records each catalog release imported (version, release time, CISA's count,
the stored snapshot). ``kev_entries`` keeps one row per CVE with CISA's values and the first and last
release it was seen in. The view ``indexed_exposure_kev_matches`` lists, for the latest exposure run of
each domain, the CVEs Shodan inferred on an IP that are in KEV (Shodan's CVEs are unverified leads).

Revision ID: 0022
Revises: 0021
Create Date: 2026-11-21 01:26:42.398681
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0022'
down_revision: str | None = '0021'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# The latest exposure run per domain (as the exposure summary reads it), one row per inferred CVE
# that is in KEV. in_latest_catalog is false for an entry CISA has since removed.
MATCH_VIEW = """
CREATE VIEW indexed_exposure_kev_matches AS
WITH l AS (
    SELECT x.*, max(x.ingestion_run_id) OVER (PARTITION BY x.domain_id) AS last_run
    FROM indexed_host_lookups x
), latest_release AS (
    SELECT id FROM kev_catalog_releases ORDER BY date_released DESC, id DESC LIMIT 1
)
SELECT l.id AS lookup_id, l.company_id, l.domain_id, l.host, l.host_role, l.name_hint, l.ip, l.attribution,
       l.retrieved_at, l.evidence_version_id AS exposure_evidence_version_id,
       k.id AS kev_entry_id, k.cve_id, k.vendor_project, k.product, k.vulnerability_name, k.date_added,
       k.known_ransomware_use, k.evidence_version_id AS kev_evidence_version_id,
       (k.last_seen_release_id = (SELECT id FROM latest_release)) AS in_latest_catalog
FROM l
CROSS JOIN LATERAL jsonb_array_elements_text(l.potential_vulns) AS v(cve)
JOIN kev_entries k ON k.cve_id = upper(v.cve)
WHERE l.outcome = 'found' AND l.ingestion_run_id IS NOT DISTINCT FROM l.last_run
"""


def upgrade() -> None:
    op.create_table('kev_catalog_releases',
    sa.Column('catalog_version', sa.Text(), nullable=False),
    sa.Column('date_released', sa.DateTime(timezone=True), nullable=False),
    sa.Column('entry_count', sa.Integer(), nullable=True),
    sa.Column('evidence_version_id', sa.BigInteger(), nullable=False),
    sa.Column('ingestion_run_id', sa.BigInteger(), nullable=True),
    sa.Column('retrieved_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['evidence_version_id'], ['evidence_versions.id'], name=op.f('fk_kev_catalog_releases_evidence_version_id_evidence_versions'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['ingestion_run_id'], ['ingestion_runs.id'], name=op.f('fk_kev_catalog_releases_ingestion_run_id_ingestion_runs'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_kev_catalog_releases')),
    sa.UniqueConstraint('catalog_version', 'date_released', name='uq_kev_catalog_releases_version')
    )
    op.create_index(op.f('ix_kev_catalog_releases_evidence_version_id'), 'kev_catalog_releases', ['evidence_version_id'], unique=False)
    op.create_index(op.f('ix_kev_catalog_releases_ingestion_run_id'), 'kev_catalog_releases', ['ingestion_run_id'], unique=False)
    op.create_table('kev_entries',
    sa.Column('cve_id', sa.Text(), nullable=False),
    sa.Column('vendor_project', sa.Text(), nullable=False),
    sa.Column('product', sa.Text(), nullable=False),
    sa.Column('vulnerability_name', sa.Text(), nullable=True),
    sa.Column('short_description', sa.Text(), nullable=True),
    sa.Column('date_added', sa.Date(), nullable=False),
    sa.Column('required_action', sa.Text(), nullable=False),
    sa.Column('due_date', sa.Date(), nullable=True),
    sa.Column('known_ransomware_use', sa.Text(), nullable=True),
    sa.Column('forensic_triage', sa.Text(), nullable=True),
    sa.Column('notes', sa.Text(), nullable=True),
    sa.Column('cwes', postgresql.JSONB(none_as_null=True, astext_type=sa.Text()), nullable=True),
    sa.Column('first_seen_release_id', sa.BigInteger(), nullable=False),
    sa.Column('last_seen_release_id', sa.BigInteger(), nullable=False),
    sa.Column('evidence_version_id', sa.BigInteger(), nullable=False),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'", name=op.f('ck_kev_entries_cve_id_format')),
    sa.CheckConstraint("known_ransomware_use IS NULL OR known_ransomware_use IN ('Known', 'Unknown')", name=op.f('ck_kev_entries_known_ransomware_use')),
    sa.ForeignKeyConstraint(['evidence_version_id'], ['evidence_versions.id'], name=op.f('fk_kev_entries_evidence_version_id_evidence_versions'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['first_seen_release_id'], ['kev_catalog_releases.id'], name=op.f('fk_kev_entries_first_seen_release_id_kev_catalog_releases'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['last_seen_release_id'], ['kev_catalog_releases.id'], name=op.f('fk_kev_entries_last_seen_release_id_kev_catalog_releases'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_kev_entries')),
    sa.UniqueConstraint('cve_id', name=op.f('uq_kev_entries_cve_id'))
    )
    op.create_index(op.f('ix_kev_entries_evidence_version_id'), 'kev_entries', ['evidence_version_id'], unique=False)
    op.create_index(op.f('ix_kev_entries_first_seen_release_id'), 'kev_entries', ['first_seen_release_id'], unique=False)
    op.create_index(op.f('ix_kev_entries_last_seen_release_id'), 'kev_entries', ['last_seen_release_id'], unique=False)
    op.execute(MATCH_VIEW)


def downgrade() -> None:
    op.execute("DROP VIEW IF EXISTS indexed_exposure_kev_matches")
    op.drop_index(op.f('ix_kev_entries_last_seen_release_id'), table_name='kev_entries')
    op.drop_index(op.f('ix_kev_entries_first_seen_release_id'), table_name='kev_entries')
    op.drop_index(op.f('ix_kev_entries_evidence_version_id'), table_name='kev_entries')
    op.drop_table('kev_entries')
    op.drop_index(op.f('ix_kev_catalog_releases_ingestion_run_id'), table_name='kev_catalog_releases')
    op.drop_index(op.f('ix_kev_catalog_releases_evidence_version_id'), table_name='kev_catalog_releases')
    op.drop_table('kev_catalog_releases')
