"""DKIM selectors from a domain's MX or provider verification record (issue 23.3).

``dkim_evidence.selector_source`` may now be ``mail_provider``: the selector is one its provider
documents, and the provider was shown by the domain's MX hosts or its domain verification TXT
record (Microsoft 365 ``MS=``), not only by SPF.

Revision ID: 0019
Revises: 0018
Create Date: 2026-11-20 05:20:21.733411
"""
from collections.abc import Sequence

from alembic import op

revision: str = '0019'
down_revision: str | None = '0018'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NAME = op.f("ck_dkim_evidence_selector_source")  # already in the naming convention's form


def upgrade() -> None:
    op.drop_constraint(NAME, "dkim_evidence", type_="check")
    op.create_check_constraint(
        NAME, "dkim_evidence",
        "selector_source IS NULL OR selector_source IN ('spf_provider', 'mail_provider', 'published')")


def downgrade() -> None:
    op.execute("DELETE FROM dkim_evidence WHERE selector_source = 'mail_provider'")
    op.drop_constraint(NAME, "dkim_evidence", type_="check")
    op.create_check_constraint(
        NAME, "dkim_evidence", "selector_source IS NULL OR selector_source IN ('spf_provider', 'published')")
