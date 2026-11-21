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

* ``aggregate_exposure_observations`` (issue 11.2): aggregate infostealer counts per company domain.

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


EXPOSURE_OUTCOMES = ("found", "none_reported", "lookup_failed")


class AggregateExposureObservation(IdMixin, Base):
    """Issue 11.2: one aggregate infostealer-exposure answer for one company domain, from one source run.

    Counts only, as the publisher (Hudson Rock's free domain search) reports them: how many infected
    computers had saved logins for the domain, split into the company's ``employees`` (corporate login
    pages), ``users`` (customer login pages) and ``third_parties``, the dates of the latest infections,
    infostealer families and a password-strength breakdown (quantities, never passwords). The hosts of
    employee login pages (e.g. ``vpn.acme.com``) are kept by host name only. No email address, username,
    password, cookie or URL query is stored.

    ``none_reported`` means the source has no infection for the domain (counts 0): not proof that none
    happened. ``lookup_failed`` (rate limit, error) has no counts at all, never zero. Each run adds rows,
    so history is kept.
    """

    __tablename__ = "aggregate_exposure_observations"

    company_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    domain_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("domains.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(Text, nullable=False)  # e.g. hudson_rock
    outcome: Mapped[str] = mapped_column(Text, nullable=False)
    message: Mapped[str | None] = mapped_column(Text)
    total_infections: Mapped[int | None] = mapped_column(BigInteger)  # publisher's "total" for the domain
    employees: Mapped[int | None] = mapped_column(BigInteger)
    users: Mapped[int | None] = mapped_column(BigInteger)
    third_parties: Mapped[int | None] = mapped_column(BigInteger)
    last_employee_infection_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_user_infection_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stealer_families: Mapped[dict | None] = mapped_column(JSONB(none_as_null=True))
    employee_password_strength: Mapped[dict | None] = mapped_column(JSONB(none_as_null=True))
    user_password_strength: Mapped[dict | None] = mapped_column(JSONB(none_as_null=True))
    employee_login_hosts: Mapped[list | None] = mapped_column(JSONB(none_as_null=True))
    third_party_domains: Mapped[list | None] = mapped_column(JSONB(none_as_null=True))
    source_dataset_size: Mapped[int | None] = mapped_column(BigInteger)  # infected computers in the whole source
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    evidence_version_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("evidence_versions.id", ondelete="RESTRICT"), index=True
    )
    ingestion_run_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("ingestion_runs.id", ondelete="SET NULL"), index=True
    )

    __table_args__ = (
        CheckConstraint(in_list("outcome", EXPOSURE_OUTCOMES), name="outcome"),
        CheckConstraint("outcome = 'lookup_failed' OR evidence_version_id IS NOT NULL", name="answer_has_evidence"),
        CheckConstraint("outcome <> 'lookup_failed' OR (total_infections IS NULL AND employees IS NULL "
                        "AND users IS NULL AND third_parties IS NULL)", name="failed_lookup_has_no_counts"),
        CheckConstraint("coalesce(employees, 0) >= 0 AND coalesce(users, 0) >= 0 AND coalesce(third_parties, 0) >= 0 "
                        "AND coalesce(total_infections, 0) >= 0", name="counts_non_negative"),
    )
