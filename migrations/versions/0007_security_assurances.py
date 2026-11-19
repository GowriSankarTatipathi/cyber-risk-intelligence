"""Security certifications, attestations and authorizations (issue 1.3).

Adds ``security_assurances`` (one row per statement from one source: company
claim, company-published document, or independent register) and the
``company_assurance_summary`` view (one row per company and framework, saying
whether anything independent backs it and whether it is current).

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-19
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0007'
down_revision: str | None = '0006'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# One row per company + framework (+ SOC report type). "verified" needs a current, active register entry;
# a register entry that lapsed or was withdrawn is "verified_lapsed"; everything else is "claimed".
SUMMARY_VIEW = """
CREATE VIEW company_assurance_summary AS
SELECT a.company_id,
       a.kind,
       a.framework,
       a.report_type,
       CASE
         WHEN bool_or(a.verification_status = 'verified' AND a.directory_status = 'active'
                      AND (a.valid_until IS NULL OR a.valid_until >= current_date)) THEN 'verified'
         WHEN bool_or(a.verification_status = 'verified') THEN 'verified_lapsed'
         ELSE 'claimed'
       END AS status,
       CASE
         WHEN max(a.valid_until) IS NULL THEN 'unknown'
         WHEN max(a.valid_until) >= current_date THEN 'current'
         ELSE 'expired'
       END AS validity,
       max(a.valid_until) AS latest_valid_until,
       max(a.period_end) AS latest_period_end,
       bool_or(a.report_availability = 'public') AS public_report,
       bool_or(a.report_availability = 'gated') AS gated_report,
       count(*) FILTER (WHERE a.basis = 'company_claim') AS company_claims,
       count(*) FILTER (WHERE a.basis = 'company_document') AS company_documents,
       count(*) FILTER (WHERE a.basis = 'issuer_directory') AS register_entries,
       max(a.observed_at) AS last_observed_at
FROM security_assurances a
GROUP BY a.company_id, a.kind, a.framework, a.report_type
"""


def upgrade() -> None:
    op.create_table('security_assurances',
    sa.Column('company_id', sa.BigInteger(), nullable=False),
    sa.Column('legal_entity_id', sa.BigInteger(), nullable=True),
    sa.Column('kind', sa.Text(), nullable=False),
    sa.Column('framework', sa.Text(), nullable=False),
    sa.Column('report_type', sa.Text(), nullable=True),
    sa.Column('level', sa.Text(), nullable=True),
    sa.Column('basis', sa.Text(), nullable=False),
    sa.Column('verification_status', sa.Text(), nullable=False),
    sa.Column('report_availability', sa.Text(), server_default='unknown', nullable=False),
    sa.Column('issuer', sa.Text(), nullable=True),
    sa.Column('accreditation_body', sa.Text(), nullable=True),
    sa.Column('certificate_number', sa.Text(), nullable=True),
    sa.Column('scope_text', sa.Text(), nullable=True),
    sa.Column('issued_on', sa.Date(), nullable=True),
    sa.Column('valid_from', sa.Date(), nullable=True),
    sa.Column('valid_until', sa.Date(), nullable=True),
    sa.Column('period_start', sa.Date(), nullable=True),
    sa.Column('period_end', sa.Date(), nullable=True),
    sa.Column('directory_status', sa.Text(), nullable=True),
    sa.Column('evidence_version_id', sa.BigInteger(), nullable=False),
    sa.Column('claim_id', sa.BigInteger(), nullable=True),
    sa.Column('source_ref', sa.Text(), nullable=True),
    sa.Column('quote', sa.Text(), nullable=True),
    sa.Column('observed_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("(directory_status IS NULL OR basis = 'issuer_directory') AND (directory_status IS NULL OR directory_status IN ('active', 'expired', 'suspended', 'withdrawn', 'unknown'))", name=op.f('ck_security_assurances_directory_status')),
    sa.CheckConstraint("(verification_status = 'verified') = (basis = 'issuer_directory')", name=op.f('ck_security_assurances_verified_only_from_directory')),
    sa.CheckConstraint("basis IN ('company_claim', 'company_document', 'issuer_directory')", name=op.f('ck_security_assurances_basis')),
    sa.CheckConstraint("framework IN ('ISO/IEC 27001', 'ISO/IEC 27017', 'ISO/IEC 27018', 'ISO/IEC 27701', 'ISO 22301', 'ISO 9001', 'HITRUST', 'CSA STAR', 'TISAX', 'Cyber Essentials', 'Cyber Essentials Plus', 'CMMC', 'SOC 1', 'SOC 2', 'SOC 3', 'PCI DSS', 'C5', 'FedRAMP', 'StateRAMP', 'IRAP')", name=op.f('ck_security_assurances_framework')),
    sa.CheckConstraint("kind = CASE framework WHEN 'ISO/IEC 27001' THEN 'certification' WHEN 'ISO/IEC 27017' THEN 'certification' WHEN 'ISO/IEC 27018' THEN 'certification' WHEN 'ISO/IEC 27701' THEN 'certification' WHEN 'ISO 22301' THEN 'certification' WHEN 'ISO 9001' THEN 'certification' WHEN 'HITRUST' THEN 'certification' WHEN 'CSA STAR' THEN 'certification' WHEN 'TISAX' THEN 'certification' WHEN 'Cyber Essentials' THEN 'certification' WHEN 'Cyber Essentials Plus' THEN 'certification' WHEN 'CMMC' THEN 'certification' WHEN 'SOC 1' THEN 'attestation' WHEN 'SOC 2' THEN 'attestation' WHEN 'SOC 3' THEN 'attestation' WHEN 'PCI DSS' THEN 'attestation' WHEN 'C5' THEN 'attestation' WHEN 'FedRAMP' THEN 'authorization' WHEN 'StateRAMP' THEN 'authorization' WHEN 'IRAP' THEN 'authorization' END", name=op.f('ck_security_assurances_kind_matches_framework')),
    sa.CheckConstraint("report_availability IN ('public', 'gated', 'unknown')", name=op.f('ck_security_assurances_report_availability')),
    sa.CheckConstraint("report_type IS NULL OR (framework IN ('SOC 1', 'SOC 2') AND report_type IN ('Type I', 'Type II'))", name=op.f('ck_security_assurances_report_type')),
    sa.CheckConstraint("verification_status IN ('claimed', 'verified')", name=op.f('ck_security_assurances_verification_status')),
    sa.CheckConstraint('period_end IS NULL OR period_start IS NULL OR period_end >= period_start', name=op.f('ck_security_assurances_period_dates')),
    sa.CheckConstraint('valid_until IS NULL OR valid_from IS NULL OR valid_until >= valid_from', name=op.f('ck_security_assurances_valid_dates')),
    sa.ForeignKeyConstraint(['claim_id'], ['security_control_claims.id'], name=op.f('fk_security_assurances_claim_id_security_control_claims'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['company_id'], ['companies.id'], name=op.f('fk_security_assurances_company_id_companies'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['evidence_version_id'], ['evidence_versions.id'], name=op.f('fk_security_assurances_evidence_version_id_evidence_versions'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['legal_entity_id'], ['legal_entities.id'], name=op.f('fk_security_assurances_legal_entity_id_legal_entities'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_security_assurances')),
    sa.UniqueConstraint('company_id', 'framework', 'report_type', 'level', 'basis', 'evidence_version_id', 'certificate_number', name='uq_security_assurances_statement', postgresql_nulls_not_distinct=True)
    )
    op.create_index(op.f('ix_security_assurances_claim_id'), 'security_assurances', ['claim_id'], unique=False)
    op.create_index(op.f('ix_security_assurances_company_id'), 'security_assurances', ['company_id'], unique=False)
    op.create_index(op.f('ix_security_assurances_evidence_version_id'), 'security_assurances', ['evidence_version_id'], unique=False)
    op.create_index(op.f('ix_security_assurances_framework'), 'security_assurances', ['framework'], unique=False)
    op.create_index(op.f('ix_security_assurances_legal_entity_id'), 'security_assurances', ['legal_entity_id'], unique=False)
    op.execute(SUMMARY_VIEW)


def downgrade() -> None:
    op.execute("DROP VIEW IF EXISTS company_assurance_summary")
    op.drop_index(op.f('ix_security_assurances_legal_entity_id'), table_name='security_assurances')
    op.drop_index(op.f('ix_security_assurances_framework'), table_name='security_assurances')
    op.drop_index(op.f('ix_security_assurances_evidence_version_id'), table_name='security_assurances')
    op.drop_index(op.f('ix_security_assurances_company_id'), table_name='security_assurances')
    op.drop_index(op.f('ix_security_assurances_claim_id'), table_name='security_assurances')
    op.drop_table('security_assurances')
