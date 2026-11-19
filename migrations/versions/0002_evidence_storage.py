"""Evidence and historical storage (Issue 17.7).

Adds sources, evidence_objects (checksummed originals in object storage),
evidence_versions (dated captures of a URL) and evidence_links.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-19 06:37:01.416061
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = '0002'
down_revision: str | None = '0001'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('evidence_objects',
    sa.Column('sha256', sa.Text(), nullable=False),
    sa.Column('size_bytes', sa.BigInteger(), nullable=False),
    sa.Column('media_type', sa.Text(), nullable=False),
    sa.Column('storage_backend', sa.Text(), nullable=False),
    sa.Column('bucket', sa.Text(), nullable=False),
    sa.Column('object_key', sa.Text(), nullable=False),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name=op.f('ck_evidence_objects_sha256_format')),
    sa.CheckConstraint("storage_backend IN ('minio', 'local')", name=op.f('ck_evidence_objects_storage_backend')),
    sa.CheckConstraint('size_bytes >= 0', name=op.f('ck_evidence_objects_size_bytes')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_evidence_objects')),
    sa.UniqueConstraint('sha256', name=op.f('uq_evidence_objects_sha256')),
    sa.UniqueConstraint('storage_backend', 'bucket', 'object_key', name='uq_evidence_objects_location')
    )
    op.create_table('sources',
    sa.Column('source_key', sa.Text(), nullable=False),
    sa.Column('name', sa.Text(), nullable=False),
    sa.Column('source_type', sa.Text(), nullable=False),
    sa.Column('access_method', sa.Text(), nullable=False),
    sa.Column('base_url', sa.Text(), nullable=True),
    sa.Column('terms_url', sa.Text(), nullable=True),
    sa.Column('license', sa.Text(), nullable=True),
    sa.Column('rate_limit_note', sa.Text(), nullable=True),
    sa.Column('is_permitted', sa.Boolean(), server_default=sa.text('true'), nullable=False),
    sa.Column('notes', sa.Text(), nullable=True),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("access_method IN ('api', 'bulk_download', 'web_page', 'archive', 'manual', 'other')", name=op.f('ck_sources_access_method')),
    sa.CheckConstraint("source_key ~ '^[a-z0-9][a-z0-9_-]*$'", name=op.f('ck_sources_source_key_format')),
    sa.CheckConstraint("source_type IN ('regulator', 'registry', 'exchange', 'company_website', 'news', 'archive', 'dataset', 'vulnerability_db', 'breach_disclosure', 'other')", name=op.f('ck_sources_source_type')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_sources')),
    sa.UniqueConstraint('source_key', name=op.f('uq_sources_source_key'))
    )
    op.create_table('evidence_versions',
    sa.Column('source_id', sa.BigInteger(), nullable=False),
    sa.Column('evidence_object_id', sa.BigInteger(), nullable=False),
    sa.Column('source_url', sa.Text(), nullable=False),
    sa.Column('title', sa.Text(), nullable=True),
    sa.Column('http_status', sa.Integer(), nullable=True),
    sa.Column('published_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('observed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('archive_url', sa.Text(), nullable=True),
    sa.Column('archive_captured_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('collected_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('notes', sa.Text(), nullable=True),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('archive_captured_at IS NULL OR archive_url IS NOT NULL', name=op.f('ck_evidence_versions_archive_capture_has_url')),
    sa.CheckConstraint('http_status IS NULL OR http_status BETWEEN 100 AND 599', name=op.f('ck_evidence_versions_http_status')),
    sa.CheckConstraint('last_seen_at >= collected_at', name=op.f('ck_evidence_versions_seen_after_collected')),
    sa.ForeignKeyConstraint(['evidence_object_id'], ['evidence_objects.id'], name=op.f('fk_evidence_versions_evidence_object_id_evidence_objects'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['source_id'], ['sources.id'], name=op.f('fk_evidence_versions_source_id_sources'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_evidence_versions')),
    sa.UniqueConstraint('source_id', 'source_url', 'evidence_object_id', name='uq_evidence_versions_capture')
    )
    op.create_index(op.f('ix_evidence_versions_evidence_object_id'), 'evidence_versions', ['evidence_object_id'], unique=False)
    op.create_index(op.f('ix_evidence_versions_source_id'), 'evidence_versions', ['source_id'], unique=False)
    op.create_index('ix_evidence_versions_url_collected', 'evidence_versions', ['source_url', 'collected_at'], unique=False)
    op.create_table('evidence_links',
    sa.Column('evidence_version_id', sa.BigInteger(), nullable=False),
    sa.Column('relation', sa.Text(), server_default='supports', nullable=False),
    sa.Column('locator', sa.Text(), nullable=True),
    sa.Column('note', sa.Text(), nullable=True),
    sa.Column('company_id', sa.BigInteger(), nullable=True),
    sa.Column('legal_entity_id', sa.BigInteger(), nullable=True),
    sa.Column('entity_identifier_id', sa.BigInteger(), nullable=True),
    sa.Column('entity_relationship_id', sa.BigInteger(), nullable=True),
    sa.Column('company_alias_id', sa.BigInteger(), nullable=True),
    sa.Column('company_domain_id', sa.BigInteger(), nullable=True),
    sa.Column('industry_classification_id', sa.BigInteger(), nullable=True),
    sa.Column('index_membership_id', sa.BigInteger(), nullable=True),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("relation IN ('supports', 'contradicts', 'mentions')", name=op.f('ck_evidence_links_relation')),
    sa.CheckConstraint('num_nonnulls(company_id, legal_entity_id, entity_identifier_id, entity_relationship_id, company_alias_id, company_domain_id, industry_classification_id, index_membership_id) = 1', name=op.f('ck_evidence_links_exactly_one_target')),
    sa.ForeignKeyConstraint(['company_alias_id'], ['company_aliases.id'], name=op.f('fk_evidence_links_company_alias_id_company_aliases'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['company_domain_id'], ['company_domains.id'], name=op.f('fk_evidence_links_company_domain_id_company_domains'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['company_id'], ['companies.id'], name=op.f('fk_evidence_links_company_id_companies'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['entity_identifier_id'], ['entity_identifiers.id'], name=op.f('fk_evidence_links_entity_identifier_id_entity_identifiers'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['entity_relationship_id'], ['entity_relationships.id'], name=op.f('fk_evidence_links_entity_relationship_id_entity_relationships'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['evidence_version_id'], ['evidence_versions.id'], name=op.f('fk_evidence_links_evidence_version_id_evidence_versions'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['index_membership_id'], ['index_memberships.id'], name=op.f('fk_evidence_links_index_membership_id_index_memberships'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['industry_classification_id'], ['industry_classifications.id'], name=op.f('fk_evidence_links_industry_classification_id_industry_classifications'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['legal_entity_id'], ['legal_entities.id'], name=op.f('fk_evidence_links_legal_entity_id_legal_entities'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_evidence_links')),
    sa.UniqueConstraint('evidence_version_id', 'relation', 'locator', 'company_id', 'legal_entity_id', 'entity_identifier_id', 'entity_relationship_id', 'company_alias_id', 'company_domain_id', 'industry_classification_id', 'index_membership_id', name='uq_evidence_links_link', postgresql_nulls_not_distinct=True)
    )
    op.create_index(op.f('ix_evidence_links_company_alias_id'), 'evidence_links', ['company_alias_id'], unique=False)
    op.create_index(op.f('ix_evidence_links_company_domain_id'), 'evidence_links', ['company_domain_id'], unique=False)
    op.create_index(op.f('ix_evidence_links_company_id'), 'evidence_links', ['company_id'], unique=False)
    op.create_index(op.f('ix_evidence_links_entity_identifier_id'), 'evidence_links', ['entity_identifier_id'], unique=False)
    op.create_index(op.f('ix_evidence_links_entity_relationship_id'), 'evidence_links', ['entity_relationship_id'], unique=False)
    op.create_index(op.f('ix_evidence_links_evidence_version_id'), 'evidence_links', ['evidence_version_id'], unique=False)
    op.create_index(op.f('ix_evidence_links_index_membership_id'), 'evidence_links', ['index_membership_id'], unique=False)
    op.create_index(op.f('ix_evidence_links_industry_classification_id'), 'evidence_links', ['industry_classification_id'], unique=False)
    op.create_index(op.f('ix_evidence_links_legal_entity_id'), 'evidence_links', ['legal_entity_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_evidence_links_legal_entity_id'), table_name='evidence_links')
    op.drop_index(op.f('ix_evidence_links_industry_classification_id'), table_name='evidence_links')
    op.drop_index(op.f('ix_evidence_links_index_membership_id'), table_name='evidence_links')
    op.drop_index(op.f('ix_evidence_links_evidence_version_id'), table_name='evidence_links')
    op.drop_index(op.f('ix_evidence_links_entity_relationship_id'), table_name='evidence_links')
    op.drop_index(op.f('ix_evidence_links_entity_identifier_id'), table_name='evidence_links')
    op.drop_index(op.f('ix_evidence_links_company_id'), table_name='evidence_links')
    op.drop_index(op.f('ix_evidence_links_company_domain_id'), table_name='evidence_links')
    op.drop_index(op.f('ix_evidence_links_company_alias_id'), table_name='evidence_links')
    op.drop_table('evidence_links')
    op.drop_index('ix_evidence_versions_url_collected', table_name='evidence_versions')
    op.drop_index(op.f('ix_evidence_versions_source_id'), table_name='evidence_versions')
    op.drop_index(op.f('ix_evidence_versions_evidence_object_id'), table_name='evidence_versions')
    op.drop_table('evidence_versions')
    op.drop_table('sources')
    op.drop_table('evidence_objects')
