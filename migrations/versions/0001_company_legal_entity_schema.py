"""Company and legal entity schema (Issue 17.1).

Creates companies, legal_entities, entity_identifiers, entity_relationships,
company_aliases, domains, company_domains, industry_classifications and
index_memberships. btree_gist is needed for the exclusion constraints that
stop the same identifier or relationship from overlapping in time.

Revision ID: 0001
Revises: 
Create Date: 2026-11-19
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0001'
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # btree_gist is a trusted extension, so the database owner (cyber_app) can create it.
    op.execute("CREATE EXTENSION IF NOT EXISTS btree_gist")
    op.create_table('companies',
    sa.Column('company_key', sa.Text(), nullable=False),
    sa.Column('display_name', sa.Text(), nullable=False),
    sa.Column('normalized_name', sa.Text(), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("company_key ~ '^[a-z0-9][a-z0-9-]*$'", name=op.f('ck_companies_company_key_format')),
    sa.CheckConstraint('length(trim(display_name)) > 0', name=op.f('ck_companies_display_name_not_blank')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_companies')),
    sa.UniqueConstraint('company_key', name=op.f('uq_companies_company_key'))
    )
    op.create_index(op.f('ix_companies_normalized_name'), 'companies', ['normalized_name'], unique=False)
    op.create_table('domains',
    sa.Column('name', sa.Text(), nullable=False),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("name = lower(name) AND name !~ '[/:@ ]' AND position('.' in name) > 1", name=op.f('ck_domains_name_normalized')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_domains')),
    sa.UniqueConstraint('name', name=op.f('uq_domains_name'))
    )
    op.create_table('index_memberships',
    sa.Column('company_id', sa.BigInteger(), nullable=False),
    sa.Column('index_name', sa.Text(), nullable=False),
    sa.Column('ticker', sa.Text(), nullable=True),
    sa.Column('observed_on', sa.Date(), nullable=False),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('source_ref', sa.Text(), nullable=True),
    sa.Column('verification_status', sa.Text(), server_default='unknown', nullable=False),
    sa.Column('observed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('collected_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("verification_status IN ('verified', 'observed', 'claimed', 'unverified', 'unknown')", name=op.f('ck_index_memberships_verification_status')),
    sa.ForeignKeyConstraint(['company_id'], ['companies.id'], name=op.f('fk_index_memberships_company_id_companies'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_index_memberships')),
    sa.UniqueConstraint('company_id', 'index_name', 'observed_on', name='uq_index_memberships_observation')
    )
    op.create_index(op.f('ix_index_memberships_company_id'), 'index_memberships', ['company_id'], unique=False)
    op.create_table('industry_classifications',
    sa.Column('company_id', sa.BigInteger(), nullable=False),
    sa.Column('system', sa.Text(), nullable=False),
    sa.Column('code', sa.Text(), nullable=True),
    sa.Column('label', sa.Text(), nullable=False),
    sa.Column('level', sa.Text(), nullable=True),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('source_ref', sa.Text(), nullable=True),
    sa.Column('verification_status', sa.Text(), server_default='unknown', nullable=False),
    sa.Column('observed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('collected_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('valid_from', sa.Date(), nullable=True),
    sa.Column('valid_to', sa.Date(), nullable=True),
    sa.CheckConstraint("system IN ('GICS', 'ICB', 'NAICS', 'SIC', 'project_group')", name=op.f('ck_industry_classifications_system')),
    sa.CheckConstraint("verification_status IN ('verified', 'observed', 'claimed', 'unverified', 'unknown')", name=op.f('ck_industry_classifications_verification_status')),
    sa.CheckConstraint('valid_from IS NULL OR valid_to IS NULL OR valid_to > valid_from', name=op.f('ck_industry_classifications_valid_period')),
    sa.ForeignKeyConstraint(['company_id'], ['companies.id'], name=op.f('fk_industry_classifications_company_id_companies'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_industry_classifications')),
    sa.UniqueConstraint('company_id', 'system', 'level', 'label', 'valid_from', name='uq_industry_classifications_entry', postgresql_nulls_not_distinct=True)
    )
    op.create_index(op.f('ix_industry_classifications_company_id'), 'industry_classifications', ['company_id'], unique=False)
    op.create_table('legal_entities',
    sa.Column('company_id', sa.BigInteger(), nullable=True),
    sa.Column('legal_name', sa.Text(), nullable=False),
    sa.Column('normalized_name', sa.Text(), nullable=False),
    sa.Column('jurisdiction_country', sa.Text(), nullable=True),
    sa.Column('jurisdiction_subdivision', sa.Text(), nullable=True),
    sa.Column('entity_status', sa.Text(), server_default='unknown', nullable=False),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('source_ref', sa.Text(), nullable=True),
    sa.Column('verification_status', sa.Text(), server_default='unknown', nullable=False),
    sa.Column('observed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('collected_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("entity_status IN ('active', 'inactive', 'merged', 'dissolved', 'unknown')", name=op.f('ck_legal_entities_entity_status')),
    sa.CheckConstraint("jurisdiction_country ~ '^[A-Z]{2}$'", name=op.f('ck_legal_entities_jurisdiction_country_iso')),
    sa.CheckConstraint("verification_status IN ('verified', 'observed', 'claimed', 'unverified', 'unknown')", name=op.f('ck_legal_entities_verification_status')),
    sa.CheckConstraint('length(trim(legal_name)) > 0', name=op.f('ck_legal_entities_legal_name_not_blank')),
    sa.ForeignKeyConstraint(['company_id'], ['companies.id'], name=op.f('fk_legal_entities_company_id_companies'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_legal_entities'))
    )
    op.create_index(op.f('ix_legal_entities_company_id'), 'legal_entities', ['company_id'], unique=False)
    op.create_index(op.f('ix_legal_entities_normalized_name'), 'legal_entities', ['normalized_name'], unique=False)
    op.create_table('company_aliases',
    sa.Column('company_id', sa.BigInteger(), nullable=False),
    sa.Column('legal_entity_id', sa.BigInteger(), nullable=True),
    sa.Column('alias', sa.Text(), nullable=False),
    sa.Column('normalized_alias', sa.Text(), nullable=False),
    sa.Column('alias_type', sa.Text(), nullable=False),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('source_ref', sa.Text(), nullable=True),
    sa.Column('verification_status', sa.Text(), server_default='unknown', nullable=False),
    sa.Column('observed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('collected_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('valid_from', sa.Date(), nullable=True),
    sa.Column('valid_to', sa.Date(), nullable=True),
    sa.CheckConstraint("alias_type IN ('legal_name', 'former_name', 'trade_name', 'brand', 'abbreviation', 'other')", name=op.f('ck_company_aliases_alias_type')),
    sa.CheckConstraint("verification_status IN ('verified', 'observed', 'claimed', 'unverified', 'unknown')", name=op.f('ck_company_aliases_verification_status')),
    sa.CheckConstraint('length(trim(alias)) > 0', name=op.f('ck_company_aliases_alias_not_blank')),
    sa.CheckConstraint('valid_from IS NULL OR valid_to IS NULL OR valid_to > valid_from', name=op.f('ck_company_aliases_valid_period')),
    sa.ForeignKeyConstraint(['company_id'], ['companies.id'], name=op.f('fk_company_aliases_company_id_companies'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['legal_entity_id'], ['legal_entities.id'], name=op.f('fk_company_aliases_legal_entity_id_legal_entities'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_company_aliases')),
    sa.UniqueConstraint('company_id', 'normalized_alias', 'alias_type', name='uq_company_aliases_alias')
    )
    op.create_index(op.f('ix_company_aliases_company_id'), 'company_aliases', ['company_id'], unique=False)
    op.create_index(op.f('ix_company_aliases_legal_entity_id'), 'company_aliases', ['legal_entity_id'], unique=False)
    op.create_index(op.f('ix_company_aliases_normalized_alias'), 'company_aliases', ['normalized_alias'], unique=False)
    op.create_table('company_domains',
    sa.Column('company_id', sa.BigInteger(), nullable=False),
    sa.Column('legal_entity_id', sa.BigInteger(), nullable=True),
    sa.Column('domain_id', sa.BigInteger(), nullable=False),
    sa.Column('role', sa.Text(), server_default='other', nullable=False),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('source_ref', sa.Text(), nullable=True),
    sa.Column('verification_status', sa.Text(), server_default='unknown', nullable=False),
    sa.Column('observed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('collected_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('valid_from', sa.Date(), nullable=True),
    sa.Column('valid_to', sa.Date(), nullable=True),
    postgresql.ExcludeConstraint((sa.column('company_id'), '='), (sa.column('domain_id'), '='), (sa.column('role'), '='), (sa.text("daterange(valid_from, valid_to, '[)')"), '&&'), using='gist', name='no_overlapping_company_domain'),
    sa.CheckConstraint("role IN ('primary_website', 'corporate', 'product', 'investor_relations', 'trust_center', 'email', 'other')", name=op.f('ck_company_domains_role')),
    sa.CheckConstraint("verification_status IN ('verified', 'observed', 'claimed', 'unverified', 'unknown')", name=op.f('ck_company_domains_verification_status')),
    sa.CheckConstraint('valid_from IS NULL OR valid_to IS NULL OR valid_to > valid_from', name=op.f('ck_company_domains_valid_period')),
    sa.ForeignKeyConstraint(['company_id'], ['companies.id'], name=op.f('fk_company_domains_company_id_companies'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['domain_id'], ['domains.id'], name=op.f('fk_company_domains_domain_id_domains'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['legal_entity_id'], ['legal_entities.id'], name=op.f('fk_company_domains_legal_entity_id_legal_entities'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_company_domains'))
    )
    op.create_index(op.f('ix_company_domains_company_id'), 'company_domains', ['company_id'], unique=False)
    op.create_index(op.f('ix_company_domains_domain_id'), 'company_domains', ['domain_id'], unique=False)
    op.create_index(op.f('ix_company_domains_legal_entity_id'), 'company_domains', ['legal_entity_id'], unique=False)
    op.create_table('entity_identifiers',
    sa.Column('legal_entity_id', sa.BigInteger(), nullable=False),
    sa.Column('scheme', sa.Text(), nullable=False),
    sa.Column('issuer_scope', sa.Text(), server_default='', nullable=False),
    sa.Column('value', sa.Text(), nullable=False),
    sa.Column('normalized_value', sa.Text(), nullable=False),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('source_ref', sa.Text(), nullable=True),
    sa.Column('verification_status', sa.Text(), server_default='unknown', nullable=False),
    sa.Column('observed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('collected_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('valid_from', sa.Date(), nullable=True),
    sa.Column('valid_to', sa.Date(), nullable=True),
    postgresql.ExcludeConstraint((sa.column('scheme'), '='), (sa.column('issuer_scope'), '='), (sa.column('normalized_value'), '='), (sa.text("daterange(valid_from, valid_to, '[)')"), '&&'), using='gist', name='no_overlapping_identifier'),
    sa.CheckConstraint("scheme <> 'lei' OR normalized_value ~ '^[A-Z0-9]{18}[0-9]{2}$'", name=op.f('ck_entity_identifiers_lei_format')),
    sa.CheckConstraint("scheme <> 'sec_cik' OR normalized_value ~ '^[0-9]{10}$'", name=op.f('ck_entity_identifiers_cik_format')),
    sa.CheckConstraint("scheme IN ('sec_cik', 'lei', 'ticker', 'opencorporates', 'ein', 'duns', 'other')", name=op.f('ck_entity_identifiers_scheme')),
    sa.CheckConstraint("verification_status IN ('verified', 'observed', 'claimed', 'unverified', 'unknown')", name=op.f('ck_entity_identifiers_verification_status')),
    sa.CheckConstraint('valid_from IS NULL OR valid_to IS NULL OR valid_to > valid_from', name=op.f('ck_entity_identifiers_valid_period')),
    sa.ForeignKeyConstraint(['legal_entity_id'], ['legal_entities.id'], name=op.f('fk_entity_identifiers_legal_entity_id_legal_entities'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_entity_identifiers'))
    )
    op.create_index(op.f('ix_entity_identifiers_legal_entity_id'), 'entity_identifiers', ['legal_entity_id'], unique=False)
    op.create_index('ix_entity_identifiers_lookup', 'entity_identifiers', ['scheme', 'normalized_value'], unique=False)
    op.create_table('entity_relationships',
    sa.Column('child_entity_id', sa.BigInteger(), nullable=False),
    sa.Column('parent_entity_id', sa.BigInteger(), nullable=False),
    sa.Column('relationship_type', sa.Text(), nullable=False),
    sa.Column('ownership_pct', sa.Numeric(precision=7, scale=4), nullable=True),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('source_ref', sa.Text(), nullable=True),
    sa.Column('verification_status', sa.Text(), server_default='unknown', nullable=False),
    sa.Column('observed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('collected_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('valid_from', sa.Date(), nullable=True),
    sa.Column('valid_to', sa.Date(), nullable=True),
    postgresql.ExcludeConstraint((sa.column('child_entity_id'), '='), (sa.column('parent_entity_id'), '='), (sa.column('relationship_type'), '='), (sa.text("daterange(valid_from, valid_to, '[)')"), '&&'), using='gist', name='no_overlapping_relationship'),
    sa.CheckConstraint("relationship_type IN ('subsidiary_of', 'acquired_by', 'merged_into', 'successor_of', 'affiliate_of')", name=op.f('ck_entity_relationships_relationship_type')),
    sa.CheckConstraint("verification_status IN ('verified', 'observed', 'claimed', 'unverified', 'unknown')", name=op.f('ck_entity_relationships_verification_status')),
    sa.CheckConstraint('child_entity_id <> parent_entity_id', name=op.f('ck_entity_relationships_not_self')),
    sa.CheckConstraint('ownership_pct IS NULL OR (ownership_pct > 0 AND ownership_pct <= 100)', name=op.f('ck_entity_relationships_ownership_pct')),
    sa.CheckConstraint('valid_from IS NULL OR valid_to IS NULL OR valid_to > valid_from', name=op.f('ck_entity_relationships_valid_period')),
    sa.ForeignKeyConstraint(['child_entity_id'], ['legal_entities.id'], name=op.f('fk_entity_relationships_child_entity_id_legal_entities'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['parent_entity_id'], ['legal_entities.id'], name=op.f('fk_entity_relationships_parent_entity_id_legal_entities'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_entity_relationships'))
    )
    op.create_index(op.f('ix_entity_relationships_child_entity_id'), 'entity_relationships', ['child_entity_id'], unique=False)
    op.create_index(op.f('ix_entity_relationships_parent_entity_id'), 'entity_relationships', ['parent_entity_id'], unique=False)


def downgrade() -> None:
    # btree_gist is left installed; other objects may depend on it.
    op.drop_index(op.f('ix_entity_relationships_parent_entity_id'), table_name='entity_relationships')
    op.drop_index(op.f('ix_entity_relationships_child_entity_id'), table_name='entity_relationships')
    op.drop_table('entity_relationships')
    op.drop_index('ix_entity_identifiers_lookup', table_name='entity_identifiers')
    op.drop_index(op.f('ix_entity_identifiers_legal_entity_id'), table_name='entity_identifiers')
    op.drop_table('entity_identifiers')
    op.drop_index(op.f('ix_company_domains_legal_entity_id'), table_name='company_domains')
    op.drop_index(op.f('ix_company_domains_domain_id'), table_name='company_domains')
    op.drop_index(op.f('ix_company_domains_company_id'), table_name='company_domains')
    op.drop_table('company_domains')
    op.drop_index(op.f('ix_company_aliases_normalized_alias'), table_name='company_aliases')
    op.drop_index(op.f('ix_company_aliases_legal_entity_id'), table_name='company_aliases')
    op.drop_index(op.f('ix_company_aliases_company_id'), table_name='company_aliases')
    op.drop_table('company_aliases')
    op.drop_index(op.f('ix_legal_entities_normalized_name'), table_name='legal_entities')
    op.drop_index(op.f('ix_legal_entities_company_id'), table_name='legal_entities')
    op.drop_table('legal_entities')
    op.drop_index(op.f('ix_industry_classifications_company_id'), table_name='industry_classifications')
    op.drop_table('industry_classifications')
    op.drop_index(op.f('ix_index_memberships_company_id'), table_name='index_memberships')
    op.drop_table('index_memberships')
    op.drop_table('domains')
    op.drop_index(op.f('ix_companies_normalized_name'), table_name='companies')
    op.drop_table('companies')
