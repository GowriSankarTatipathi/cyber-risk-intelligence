"""Issue 2.1: backup schedules a company publishes about itself.

``backup_policy_claims`` holds what one sentence on a company's own page says
about its backups: how often (``frequency_class`` and ``interval_minutes``),
of what (``covered_system``), how (``methods``), kept how long
(``retention_days``) and the recovery objectives (``rpo_minutes``,
``rto_minutes``). Rows come from 1.1 ``backup_and_recovery`` claims.

* A sentence about backups that gives no schedule is kept with
  ``frequency_class`` NULL: the frequency is unknown, not "none".
* ``continuous`` has no interval; ``daily`` is 1440 minutes. They are never merged.
* ``scope`` keeps the company's own practice apart from a product feature
  ("you can schedule backups hourly") and from what customers must do
  themselves, so a vendor's generic product text is not read as every
  customer's (or the vendor's own) backup policy.
* Everything here is what the company says: ``verification_status`` is always ``claimed``.
"""

import json
from datetime import date, datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from ..backup.parse import FREQUENCY_CLASSES, METHODS, SCOPES
from .base import Base, IdMixin, in_list

ASSERTIONS = ("affirmed", "negated")


class BackupPolicyClaim(IdMixin, Base):
    __tablename__ = "backup_policy_claims"

    company_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    legal_entity_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("legal_entities.id", ondelete="SET NULL"), index=True
    )
    claim_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("security_control_claims.id", ondelete="SET NULL"), index=True
    )
    evidence_version_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("evidence_versions.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    source_ref: Mapped[str | None] = mapped_column(Text)
    quote: Mapped[str] = mapped_column(Text, nullable=False)  # the published sentence
    claim_hash: Mapped[str] = mapped_column(Text, nullable=False)
    section_heading: Mapped[str | None] = mapped_column(Text)
    assertion: Mapped[str] = mapped_column(Text, nullable=False, server_default="affirmed")

    scope: Mapped[str] = mapped_column(Text, nullable=False)
    covered_system: Mapped[str | None] = mapped_column(Text)
    frequency_class: Mapped[str | None] = mapped_column(Text, index=True)  # NULL: not stated
    interval_minutes: Mapped[int | None] = mapped_column(Integer)
    frequency_phrase: Mapped[str | None] = mapped_column(Text)
    methods: Mapped[list | None] = mapped_column(JSONB(none_as_null=True))
    retention_days: Mapped[int | None] = mapped_column(Integer)
    retention_phrase: Mapped[str | None] = mapped_column(Text)
    rpo_minutes: Mapped[int | None] = mapped_column(Integer)
    rto_minutes: Mapped[int | None] = mapped_column(Integer)
    objective_phrase: Mapped[str | None] = mapped_column(Text)

    page_updated_on: Mapped[date | None] = mapped_column(Date)  # as the page states it
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)  # when we captured it
    verification_status: Mapped[str] = mapped_column(Text, nullable=False, server_default="claimed")

    __table_args__ = (
        UniqueConstraint("evidence_version_id", "claim_hash", "frequency_phrase",
                         name="uq_backup_policy_claims_statement", postgresql_nulls_not_distinct=True),
        CheckConstraint(in_list("scope", SCOPES), name="scope"),
        CheckConstraint(in_list("assertion", ASSERTIONS), name="assertion"),
        CheckConstraint(f"frequency_class IS NULL OR {in_list('frequency_class', FREQUENCY_CLASSES)}",
                        name="frequency_class"),
        CheckConstraint("(frequency_class IS NULL) = (frequency_phrase IS NULL)", name="frequency_phrase"),
        CheckConstraint("frequency_class IS DISTINCT FROM 'continuous' OR interval_minutes IS NULL",
                        name="continuous_has_no_interval"),
        CheckConstraint("frequency_class IS NOT NULL OR interval_minutes IS NULL", name="interval_needs_frequency"),
        CheckConstraint("interval_minutes IS NULL OR interval_minutes > 0", name="interval_minutes"),
        CheckConstraint("retention_days IS NULL OR retention_days > 0", name="retention_days"),
        CheckConstraint("rpo_minutes IS NULL OR rpo_minutes >= 0", name="rpo_minutes"),
        CheckConstraint("rto_minutes IS NULL OR rto_minutes >= 0", name="rto_minutes"),
        CheckConstraint(f"methods IS NULL OR methods <@ '{json.dumps(list(METHODS))}'::jsonb", name="methods"),
        CheckConstraint("verification_status = 'claimed'", name="always_claimed"),
        CheckConstraint("length(trim(quote)) > 0", name="quote_not_blank"),
    )
