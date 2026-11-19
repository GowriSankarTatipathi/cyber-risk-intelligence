"""Trust-center collection and security-control claims (Issue 1.1).

Adds collection_targets, page_fetches and security_control_claims.

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-19 07:33:28.613252
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = '0005'
down_revision: str | None = '0004'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('collection_targets',
    sa.Column('company_id', sa.BigInteger(), nullable=False),
    sa.Column('url', sa.Text(), nullable=False),
    sa.Column('page_type', sa.Text(), nullable=False),
    sa.Column('active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
    sa.Column('notes', sa.Text(), nullable=True),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("page_type IN ('trust_center', 'security', 'compliance', 'privacy', 'status', 'other')", name=op.f('ck_collection_targets_page_type')),
    sa.CheckConstraint("url ~ '^https?://'", name=op.f('ck_collection_targets_url_http')),
    sa.ForeignKeyConstraint(['company_id'], ['companies.id'], name=op.f('fk_collection_targets_company_id_companies'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_collection_targets')),
    sa.UniqueConstraint('company_id', 'url', name='uq_collection_targets_url')
    )
    op.create_index(op.f('ix_collection_targets_company_id'), 'collection_targets', ['company_id'], unique=False)
    op.create_table('security_control_claims',
    sa.Column('verification_status', sa.Text(), server_default='claimed', nullable=False),
    sa.Column('company_id', sa.BigInteger(), nullable=False),
    sa.Column('legal_entity_id', sa.BigInteger(), nullable=True),
    sa.Column('evidence_version_id', sa.BigInteger(), nullable=False),
    sa.Column('control_category', sa.Text(), nullable=False),
    sa.Column('assertion', sa.Text(), server_default='affirmed', nullable=False),
    sa.Column('qualifier', sa.Text(), nullable=True),
    sa.Column('claim_text', sa.Text(), nullable=False),
    sa.Column('context_text', sa.Text(), nullable=True),
    sa.Column('section_heading', sa.Text(), nullable=True),
    sa.Column('claim_hash', sa.Text(), nullable=False),
    sa.Column('page_updated_on', sa.Date(), nullable=True),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('source_ref', sa.Text(), nullable=True),
    sa.Column('observed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('collected_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("assertion IN ('affirmed', 'negated')", name=op.f('ck_security_control_claims_assertion')),
    sa.CheckConstraint("control_category IN ('encryption_at_rest', 'encryption_in_transit', 'key_management', 'mfa', 'sso', 'access_control', 'security_policy', 'compliance_certification', 'vulnerability_management', 'penetration_testing', 'bug_bounty', 'incident_response', 'backup_and_recovery', 'logging_and_monitoring', 'security_training', 'vendor_risk', 'data_residency')", name=op.f('ck_security_control_claims_control_category')),
    sa.CheckConstraint("verification_status = 'claimed'", name=op.f('ck_security_control_claims_always_claimed')),
    sa.CheckConstraint('length(trim(claim_text)) > 0', name=op.f('ck_security_control_claims_claim_text_not_blank')),
    sa.ForeignKeyConstraint(['company_id'], ['companies.id'], name=op.f('fk_security_control_claims_company_id_companies'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['evidence_version_id'], ['evidence_versions.id'], name=op.f('fk_security_control_claims_evidence_version_id_evidence_versions'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['legal_entity_id'], ['legal_entities.id'], name=op.f('fk_security_control_claims_legal_entity_id_legal_entities'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_security_control_claims')),
    sa.UniqueConstraint('evidence_version_id', 'control_category', 'qualifier', 'claim_hash', name='uq_security_control_claims_claim', postgresql_nulls_not_distinct=True)
    )
    op.create_index(op.f('ix_security_control_claims_company_id'), 'security_control_claims', ['company_id'], unique=False)
    op.create_index(op.f('ix_security_control_claims_control_category'), 'security_control_claims', ['control_category'], unique=False)
    op.create_index(op.f('ix_security_control_claims_evidence_version_id'), 'security_control_claims', ['evidence_version_id'], unique=False)
    op.create_index(op.f('ix_security_control_claims_legal_entity_id'), 'security_control_claims', ['legal_entity_id'], unique=False)
    op.create_table('page_fetches',
    sa.Column('target_id', sa.BigInteger(), nullable=False),
    sa.Column('ingestion_run_id', sa.BigInteger(), nullable=True),
    sa.Column('attempted_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('outcome', sa.Text(), nullable=False),
    sa.Column('http_status', sa.Integer(), nullable=True),
    sa.Column('final_url', sa.Text(), nullable=True),
    sa.Column('evidence_version_id', sa.BigInteger(), nullable=True),
    sa.Column('claims_found', sa.Integer(), nullable=True),
    sa.Column('message', sa.Text(), nullable=True),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("CASE WHEN outcome IN ('captured', 'not_modified') THEN evidence_version_id IS NOT NULL WHEN outcome = 'not_html' THEN true ELSE evidence_version_id IS NULL END", name=op.f('ck_page_fetches_evidence_matches_outcome')),
    sa.CheckConstraint("outcome IN ('captured', 'not_modified', 'unavailable', 'login_required', 'blocked_by_robots', 'rate_limited', 'not_html', 'withheld')", name=op.f('ck_page_fetches_outcome')),
    sa.CheckConstraint('http_status IS NULL OR http_status BETWEEN 100 AND 599', name=op.f('ck_page_fetches_http_status')),
    sa.ForeignKeyConstraint(['evidence_version_id'], ['evidence_versions.id'], name=op.f('fk_page_fetches_evidence_version_id_evidence_versions'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['ingestion_run_id'], ['ingestion_runs.id'], name=op.f('fk_page_fetches_ingestion_run_id_ingestion_runs'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['target_id'], ['collection_targets.id'], name=op.f('fk_page_fetches_target_id_collection_targets'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_page_fetches'))
    )
    op.create_index(op.f('ix_page_fetches_evidence_version_id'), 'page_fetches', ['evidence_version_id'], unique=False)
    op.create_index(op.f('ix_page_fetches_ingestion_run_id'), 'page_fetches', ['ingestion_run_id'], unique=False)
    op.create_index(op.f('ix_page_fetches_target_id'), 'page_fetches', ['target_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_page_fetches_target_id'), table_name='page_fetches')
    op.drop_index(op.f('ix_page_fetches_ingestion_run_id'), table_name='page_fetches')
    op.drop_index(op.f('ix_page_fetches_evidence_version_id'), table_name='page_fetches')
    op.drop_table('page_fetches')
    op.drop_index(op.f('ix_security_control_claims_legal_entity_id'), table_name='security_control_claims')
    op.drop_index(op.f('ix_security_control_claims_evidence_version_id'), table_name='security_control_claims')
    op.drop_index(op.f('ix_security_control_claims_control_category'), table_name='security_control_claims')
    op.drop_index(op.f('ix_security_control_claims_company_id'), table_name='security_control_claims')
    op.drop_table('security_control_claims')
    op.drop_index(op.f('ix_collection_targets_company_id'), table_name='collection_targets')
    op.drop_table('collection_targets')
