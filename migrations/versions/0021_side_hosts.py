"""Side hosts from CT certificates in the exposure lookups (issue 10.3 follow-up).

``indexed_host_lookups.host_role`` may now be ``certificate_name``: a host named in one of the
company's Certificate Transparency certificates (``vpn.``, ``remote.``, ``owa.`` ...), and
``name_hint`` records the kind of service its name suggests.

Revision ID: 0021
Revises: 0020
Create Date: 2026-11-20 06:20:00
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0021'
down_revision: str | None = '0020'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ROLE = op.f("ck_indexed_host_lookups_host_role")
HINT = op.f("ck_indexed_host_lookups_name_hint")


def upgrade() -> None:
    op.add_column('indexed_host_lookups', sa.Column('name_hint', sa.Text(), nullable=True))
    op.drop_constraint(ROLE, "indexed_host_lookups", type_="check")
    op.create_check_constraint(ROLE, "indexed_host_lookups", "host_role IN ('website', 'mail', 'certificate_name')")
    op.create_check_constraint(
        HINT, "indexed_host_lookups",
        "name_hint IS NULL OR name_hint IN ('remote_access', 'file_transfer', 'admin', 'mail', 'identity', "
        "'development')")


def downgrade() -> None:
    op.execute("DELETE FROM indexed_host_lookups WHERE host_role = 'certificate_name'")
    op.drop_constraint(HINT, "indexed_host_lookups", type_="check")
    op.drop_constraint(ROLE, "indexed_host_lookups", type_="check")
    op.create_check_constraint(ROLE, "indexed_host_lookups", "host_role IN ('website', 'mail')")
    op.drop_column('indexed_host_lookups', 'name_hint')
