"""Fingerprint of a fetched page's readable text (issue 1.1 follow-up).

Lets the collector tell "the page says something new" from "only hidden bytes
changed" (timestamps, tracking codes), so unchanged pages don't create new
evidence versions and duplicate claims on every run.

Revision ID: 0006
Revises: 0005
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0006'
down_revision: str | None = '0005'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('page_fetches', sa.Column('text_sha256', sa.Text(), nullable=True,
                                            comment="sha256 of the page's readable text; NULL if not read"))
    op.create_check_constraint(op.f('ck_page_fetches_text_sha256_hex'), 'page_fetches',
                               "text_sha256 IS NULL OR text_sha256 ~ '^[0-9a-f]{64}$'")


def downgrade() -> None:
    op.drop_constraint(op.f('ck_page_fetches_text_sha256_hex'), 'page_fetches', type_='check')
    op.drop_column('page_fetches', 'text_sha256')
