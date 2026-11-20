"""Certificate Transparency from Cert Spotter as well as crt.sh (issue 10.1 follow-up).

Cert Spotter pages through very large domains quickly, so it becomes the first source with crt.sh
as the fallback. Its certificates are identified by the SHA-256 of their to-be-signed part rather
than a serial number, so ``certificates`` gains ``tbs_sha256`` (unique), ``cert_sha256`` and
``revoked``, and ``serial_number`` becomes optional (one of the two is required).
``certificate_observations.log_entry_id`` becomes the text ``source_entry_id``. ``ct_lookups``
gains ``pages`` and ``complete`` (false when a search stopped early and kept what it had read),
and ``source`` may be ``certspotter``.

Revision ID: 0014
Revises: 0013
Create Date: 2026-11-20
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0014'
down_revision: str | None = '0013'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

LATEST_VIEW = """
CREATE VIEW latest_ct_lookups AS
SELECT DISTINCT ON (l.domain_id) l.*
FROM ct_lookups l
ORDER BY l.domain_id, l.queried_at DESC, l.id DESC
"""


def upgrade() -> None:
    op.execute("DROP VIEW latest_ct_lookups")
    op.alter_column('certificate_observations', 'log_entry_id', new_column_name='source_entry_id',
                    type_=sa.Text(), postgresql_using='log_entry_id::text')
    op.add_column('certificates', sa.Column('tbs_sha256', sa.Text(), nullable=True))
    op.add_column('certificates', sa.Column('cert_sha256', sa.Text(), nullable=True))
    op.add_column('certificates', sa.Column('revoked', sa.Boolean(), nullable=True))
    op.alter_column('certificates', 'serial_number', existing_type=sa.Text(), nullable=True)
    op.create_unique_constraint(op.f('uq_certificates_tbs_sha256'), 'certificates', ['tbs_sha256'])
    op.drop_constraint(op.f('ck_certificates_serial_number_hex'), 'certificates', type_='check')
    op.create_check_constraint(op.f('ck_certificates_serial_number_hex'), 'certificates',
                               "serial_number IS NULL OR (serial_number = lower(serial_number) "
                               "AND serial_number ~ '^[0-9a-f]+$')")
    op.create_check_constraint(op.f('ck_certificates_tbs_sha256_hex'), 'certificates',
                               "tbs_sha256 IS NULL OR tbs_sha256 ~ '^[0-9a-f]{64}$'")
    op.create_check_constraint(op.f('ck_certificates_has_identity'), 'certificates',
                               'serial_number IS NOT NULL OR tbs_sha256 IS NOT NULL')
    op.add_column('ct_lookups', sa.Column('pages', sa.Integer(), nullable=True))
    op.add_column('ct_lookups', sa.Column('complete', sa.Boolean(), server_default='true', nullable=False))
    op.drop_constraint(op.f('ck_ct_lookups_source'), 'ct_lookups', type_='check')
    op.create_check_constraint(op.f('ck_ct_lookups_source'), 'ct_lookups', "source IN ('certspotter', 'crt.sh')")
    op.create_check_constraint(op.f('ck_ct_lookups_incomplete_only_when_answered'), 'ct_lookups',
                               "complete OR outcome = 'answered'")
    op.execute(LATEST_VIEW)


def downgrade() -> None:
    # Cert Spotter rows have no serial number or numeric entry id, so they cannot be kept in the old shape.
    op.execute("DROP VIEW latest_ct_lookups")
    op.execute("DELETE FROM certificates WHERE serial_number IS NULL")
    op.execute("DELETE FROM ct_lookups WHERE source = 'certspotter'")
    op.drop_constraint(op.f('ck_ct_lookups_incomplete_only_when_answered'), 'ct_lookups', type_='check')
    op.drop_constraint(op.f('ck_ct_lookups_source'), 'ct_lookups', type_='check')
    op.create_check_constraint(op.f('ck_ct_lookups_source'), 'ct_lookups', "source IN ('crt.sh')")
    op.drop_column('ct_lookups', 'complete')
    op.drop_column('ct_lookups', 'pages')
    op.drop_constraint(op.f('ck_certificates_has_identity'), 'certificates', type_='check')
    op.drop_constraint(op.f('ck_certificates_tbs_sha256_hex'), 'certificates', type_='check')
    op.drop_constraint(op.f('ck_certificates_serial_number_hex'), 'certificates', type_='check')
    op.create_check_constraint(op.f('ck_certificates_serial_number_hex'), 'certificates',
                               "serial_number = lower(serial_number) AND serial_number ~ '^[0-9a-f]+$'")
    op.drop_constraint(op.f('uq_certificates_tbs_sha256'), 'certificates', type_='unique')
    op.alter_column('certificates', 'serial_number', existing_type=sa.Text(), nullable=False)
    op.drop_column('certificates', 'revoked')
    op.drop_column('certificates', 'cert_sha256')
    op.drop_column('certificates', 'tbs_sha256')
    op.alter_column('certificate_observations', 'source_entry_id', new_column_name='log_entry_id',
                    type_=sa.BigInteger(), postgresql_using='source_entry_id::bigint')
    op.execute(LATEST_VIEW)
