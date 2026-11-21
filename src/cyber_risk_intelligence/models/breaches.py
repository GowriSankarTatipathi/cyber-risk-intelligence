"""Issue 11.1: public breach metadata (Have I Been Pwned) and what each breach source lets us see.

* ``public_breach_metadata``: one row per breach in HIBP's public breach catalogue, keyed by HIBP's
  stable ``Name``: title, the breached site's domain, breach date, when HIBP added and last changed it,
  number of accounts, description, data classes (what kinds of data leaked) and HIBP's flags (verified,
  fabricated, sensitive, spam list, malware, stealer log, retired). This is metadata about the breach.
  No email address, account or credential is ever collected. ``first_seen_run_id`` /
  ``last_seen_run_id`` say in which imports of the catalogue we saw it; one missing from the newest
  import has left the catalogue. ``evidence_version_id`` is the stored catalogue its current values
  came from, and earlier values stay in earlier stored catalogues.
* ``breach_source_access_notes``: for each capability a breach source offers (the public catalogue,
  domain search, account search, stealer logs ...), whether it is public, needs a paid key or needs
  proof that we control the domain, whether we use it, and what that means for missing data.

A breach is linked to a company only through the view ``company_public_breaches``, when the breached
site's domain is one of the company's known domains (or a subdomain of one). A company with no row
there may still have been breached: missing is not absent.
"""

from datetime import date, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, IdMixin, in_list

BREACH_ACCESS = ("public", "api_key", "verified_domain")


class PublicBreachMetadata(IdMixin, Base):
    __tablename__ = "public_breach_metadata"

    name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)  # HIBP's stable key
    title: Mapped[str | None] = mapped_column(Text)
    domain: Mapped[str | None] = mapped_column(Text, index=True)  # the breached site; NULL = HIBP gives none
    breach_date: Mapped[date | None] = mapped_column(Date)  # HIBP's estimate of when it happened
    added_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    pwn_count: Mapped[int | None] = mapped_column(BigInteger)
    description: Mapped[str | None] = mapped_column(Text)  # HIBP's text (HTML), as published
    data_classes: Mapped[list | None] = mapped_column(JSONB(none_as_null=True))
    is_verified: Mapped[bool | None] = mapped_column(Boolean)
    is_fabricated: Mapped[bool | None] = mapped_column(Boolean)
    is_sensitive: Mapped[bool | None] = mapped_column(Boolean)
    is_retired: Mapped[bool | None] = mapped_column(Boolean)
    is_spam_list: Mapped[bool | None] = mapped_column(Boolean)
    is_malware: Mapped[bool | None] = mapped_column(Boolean)
    is_stealer_log: Mapped[bool | None] = mapped_column(Boolean)
    is_subscription_free: Mapped[bool | None] = mapped_column(Boolean)
    disclosure_url: Mapped[str | None] = mapped_column(Text)
    attribution: Mapped[str | None] = mapped_column(Text)
    first_seen_run_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("ingestion_runs.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    last_seen_run_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("ingestion_runs.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    evidence_version_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("evidence_versions.id", ondelete="RESTRICT"), nullable=False, index=True
    )

    __table_args__ = (
        CheckConstraint("domain IS NULL OR (domain = lower(domain) AND domain !~ '[/:@ ]')", name="domain_normalized"),
        CheckConstraint("pwn_count IS NULL OR pwn_count >= 0", name="pwn_count_non_negative"),
    )


class BreachSourceAccessNote(IdMixin, Base):
    __tablename__ = "breach_source_access_notes"

    source_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("sources.id", ondelete="CASCADE"), nullable=False, index=True
    )
    capability: Mapped[str] = mapped_column(Text, nullable=False)  # e.g. breach_catalogue, domain_search
    endpoint: Mapped[str | None] = mapped_column(Text)
    access: Mapped[str] = mapped_column(Text, nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, nullable=False)
    returns: Mapped[str] = mapped_column(Text, nullable=False)  # what the capability gives
    limitation: Mapped[str] = mapped_column(Text, nullable=False)  # what it means for our data
    documentation_url: Mapped[str | None] = mapped_column(Text)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("source_id", "capability", name="uq_breach_source_access_notes_capability"),
        CheckConstraint(in_list("access", BREACH_ACCESS), name="access"),
        CheckConstraint("NOT used OR access = 'public'", name="only_public_capabilities_used"),
    )
