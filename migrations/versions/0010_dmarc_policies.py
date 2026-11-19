"""DMARC policy collection (issue 23.2).

Adds DMARC columns to ``email_security_observations`` (policy, subdomain policy,
pct, DKIM/SPF alignment, reporting destinations, the published tags, which
values were defaulted, and whether the record was inherited from the
organizational domain), allows ``control = 'dmarc'``, and adds the
``latest_dmarc_observations`` view.

Revision ID: 0010
Revises: 0009
Create Date: 2026-11-19
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0010'
down_revision: str | None = '0009'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE = 'email_security_observations'
LATEST_DMARC_VIEW = """
CREATE VIEW latest_dmarc_observations AS
SELECT DISTINCT ON (o.company_id, o.domain_id) o.*
FROM email_security_observations o
WHERE o.control = 'dmarc'
ORDER BY o.company_id, o.domain_id, o.observed_at DESC, o.id DESC
"""
CHECKS = {
    'dmarc_policy': "dmarc_policy IS NULL OR dmarc_policy IN ('none', 'quarantine', 'reject')",
    'dmarc_subdomain_policy': "dmarc_subdomain_policy IS NULL OR dmarc_subdomain_policy IN ('none', 'quarantine', 'reject')",
    'dmarc_pct': 'dmarc_pct IS NULL OR dmarc_pct BETWEEN 0 AND 100',
    'dkim_alignment': "dkim_alignment IS NULL OR dkim_alignment IN ('relaxed', 'strict')",
    'spf_alignment': "spf_alignment IS NULL OR spf_alignment IN ('relaxed', 'strict')",
    'policy_source': "policy_source IS NULL OR policy_source IN ('domain', 'organizational_domain')",
    'dmarc_fields_only_for_dmarc': "control = 'dmarc' OR (dmarc_policy IS NULL AND tags IS NULL AND policy_source IS NULL)",
    'spf_fields_only_for_spf': "control = 'spf' OR (all_qualifier IS NULL AND mechanisms IS NULL)",
}


def upgrade() -> None:
    op.add_column('email_security_observations', sa.Column('dmarc_policy', sa.Text(), nullable=True))
    op.add_column('email_security_observations', sa.Column('dmarc_subdomain_policy', sa.Text(), nullable=True))
    op.add_column('email_security_observations', sa.Column('dmarc_pct', sa.Integer(), nullable=True))
    op.add_column('email_security_observations', sa.Column('dkim_alignment', sa.Text(), nullable=True))
    op.add_column('email_security_observations', sa.Column('spf_alignment', sa.Text(), nullable=True))
    op.add_column('email_security_observations', sa.Column('aggregate_report_uris', postgresql.JSONB(none_as_null=True, astext_type=sa.Text()), nullable=True))
    op.add_column('email_security_observations', sa.Column('failure_report_uris', postgresql.JSONB(none_as_null=True, astext_type=sa.Text()), nullable=True))
    op.add_column('email_security_observations', sa.Column('tags', postgresql.JSONB(none_as_null=True, astext_type=sa.Text()), nullable=True))
    op.add_column('email_security_observations', sa.Column('defaults_used', postgresql.JSONB(none_as_null=True, astext_type=sa.Text()), nullable=True))
    op.add_column('email_security_observations', sa.Column('policy_source', sa.Text(), nullable=True))
    op.add_column('email_security_observations', sa.Column('policy_dns_record_id', sa.BigInteger(), nullable=True))
    op.create_index(op.f('ix_email_security_observations_policy_dns_record_id'), 'email_security_observations', ['policy_dns_record_id'], unique=False)
    op.create_foreign_key(op.f('fk_email_security_observations_policy_dns_record_id_dns_security_records'), 'email_security_observations', 'dns_security_records', ['policy_dns_record_id'], ['id'], ondelete='CASCADE')
    op.drop_constraint(op.f('ck_email_security_observations_control'), TABLE, type_='check')
    op.create_check_constraint(op.f('ck_email_security_observations_control'), TABLE, "control IN ('spf', 'dmarc')")
    for name, sql in CHECKS.items():
        op.create_check_constraint(op.f(f'ck_email_security_observations_{name}'), TABLE, sql)
    op.execute(LATEST_DMARC_VIEW)


def downgrade() -> None:
    op.execute("DROP VIEW IF EXISTS latest_dmarc_observations")
    op.execute(f"DELETE FROM {TABLE} WHERE control = 'dmarc'")
    for name in CHECKS:
        op.drop_constraint(op.f(f'ck_email_security_observations_{name}'), TABLE, type_='check')
    op.drop_constraint(op.f('ck_email_security_observations_control'), TABLE, type_='check')
    op.create_check_constraint(op.f('ck_email_security_observations_control'), TABLE, "control IN ('spf')")
    op.drop_constraint(op.f('fk_email_security_observations_policy_dns_record_id_dns_security_records'), 'email_security_observations', type_='foreignkey')
    op.drop_index(op.f('ix_email_security_observations_policy_dns_record_id'), table_name='email_security_observations')
    op.drop_column('email_security_observations', 'policy_dns_record_id')
    op.drop_column('email_security_observations', 'policy_source')
    op.drop_column('email_security_observations', 'defaults_used')
    op.drop_column('email_security_observations', 'tags')
    op.drop_column('email_security_observations', 'failure_report_uris')
    op.drop_column('email_security_observations', 'aggregate_report_uris')
    op.drop_column('email_security_observations', 'spf_alignment')
    op.drop_column('email_security_observations', 'dkim_alignment')
    op.drop_column('email_security_observations', 'dmarc_pct')
    op.drop_column('email_security_observations', 'dmarc_subdomain_policy')
    op.drop_column('email_security_observations', 'dmarc_policy')
