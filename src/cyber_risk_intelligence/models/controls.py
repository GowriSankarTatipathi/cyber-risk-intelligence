"""Issue 1.1: trust-center collection and company security-control claims.

* ``collection_targets``: public pages we are allowed to collect for a company
  (trust center, security page, compliance page ...).
* ``page_fetches``: every attempt to fetch a target and its outcome. A page we
  could not read is recorded as ``unavailable`` / ``login_required`` / ...,
  which says nothing about whether the company has the controls.
* ``security_control_claims``: statements a company makes about its own
  controls, with the exact published sentence, its context, and the stored
  page it came from. These are claims: ``verification_status`` is always
  ``claimed``.
"""

from datetime import date, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, IdMixin, ProvenanceMixin, in_list

PAGE_TYPES = ("trust_center", "security", "compliance", "privacy", "status", "other")
FETCH_OUTCOMES = (
    "captured",           # page stored as evidence
    "not_modified",       # same content as last time (stored version reused)
    "unavailable",        # 404/410/5xx or network error: we don't know
    "login_required",     # behind sign-in or NDA: not public
    "blocked_by_robots",  # robots.txt disallows us: not collected
    "rate_limited",       # 429: try again later
    "not_html",           # a file type this collector doesn't parse (stored if fetched); PDFs are captured
    "withheld",           # content looked like it contained a credential, so it was not stored
)
CONTROL_CATEGORIES = (
    "encryption_at_rest", "encryption_in_transit", "key_management", "mfa", "sso", "access_control",
    "security_policy", "compliance_certification", "vulnerability_management", "penetration_testing",
    "bug_bounty", "incident_response", "backup_and_recovery", "logging_and_monitoring",
    "security_training", "vendor_risk", "data_residency",
)
ASSERTIONS = ("affirmed", "negated")


class CollectionTarget(IdMixin, Base):
    __tablename__ = "collection_targets"

    company_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    url: Mapped[str] = mapped_column(Text, nullable=False)
    page_type: Mapped[str] = mapped_column(Text, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    notes: Mapped[str | None] = mapped_column(Text)

    fetches: Mapped[list["PageFetch"]] = relationship(back_populates="target", order_by="PageFetch.id")

    __table_args__ = (
        UniqueConstraint("company_id", "url", name="uq_collection_targets_url"),
        CheckConstraint(in_list("page_type", PAGE_TYPES), name="page_type"),
        CheckConstraint("url ~ '^https?://'", name="url_http"),
    )


class PageFetch(IdMixin, Base):
    __tablename__ = "page_fetches"

    target_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("collection_targets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ingestion_run_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("ingestion_runs.id", ondelete="SET NULL"), index=True
    )
    attempted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    outcome: Mapped[str] = mapped_column(Text, nullable=False)
    http_status: Mapped[int | None] = mapped_column(Integer)
    final_url: Mapped[str | None] = mapped_column(Text)
    evidence_version_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("evidence_versions.id", ondelete="RESTRICT"), index=True
    )
    claims_found: Mapped[int | None] = mapped_column(Integer)
    message: Mapped[str | None] = mapped_column(Text)
    # sha256 of the readable text; a capture with the same text as the last one is "not_modified".
    text_sha256: Mapped[str | None] = mapped_column(Text, comment="sha256 of the page's readable text; NULL if not read")

    target: Mapped[CollectionTarget] = relationship(back_populates="fetches")

    __table_args__ = (
        CheckConstraint(in_list("outcome", FETCH_OUTCOMES), name="outcome"),
        CheckConstraint(
            "CASE WHEN outcome IN ('captured', 'not_modified') THEN evidence_version_id IS NOT NULL "
            "WHEN outcome = 'not_html' THEN true ELSE evidence_version_id IS NULL END",
            name="evidence_matches_outcome",
        ),
        CheckConstraint("text_sha256 IS NULL OR text_sha256 ~ '^[0-9a-f]{64}$'", name="text_sha256_hex"),
        CheckConstraint("http_status IS NULL OR http_status BETWEEN 100 AND 599", name="http_status"),
    )


class SecurityControlClaim(IdMixin, ProvenanceMixin, Base):
    __tablename__ = "security_control_claims"

    verification_status: Mapped[str] = mapped_column(Text, nullable=False, server_default="claimed")

    company_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    legal_entity_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("legal_entities.id", ondelete="SET NULL"), index=True
    )
    evidence_version_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("evidence_versions.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    control_category: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    assertion: Mapped[str] = mapped_column(Text, nullable=False, server_default="affirmed")
    # Framework or detail named in the claim, e.g. "SOC 2 Type II", "AES-256", "TLS 1.2".
    qualifier: Mapped[str | None] = mapped_column(Text)
    claim_text: Mapped[str] = mapped_column(Text, nullable=False)  # exact published sentence
    context_text: Mapped[str | None] = mapped_column(Text)  # surrounding paragraph
    section_heading: Mapped[str | None] = mapped_column(Text)
    claim_hash: Mapped[str] = mapped_column(Text, nullable=False)
    # Date the page says it was last updated, if it says so. Publication date lives on the evidence version.
    page_updated_on: Mapped[date | None] = mapped_column(Date)

    __table_args__ = (
        UniqueConstraint("evidence_version_id", "control_category", "qualifier", "claim_hash",
                         name="uq_security_control_claims_claim", postgresql_nulls_not_distinct=True),
        CheckConstraint(in_list("control_category", CONTROL_CATEGORIES), name="control_category"),
        CheckConstraint(in_list("assertion", ASSERTIONS), name="assertion"),
        # A company describing itself is never independent verification.
        CheckConstraint("verification_status = 'claimed'", name="always_claimed"),
        CheckConstraint("length(trim(claim_text)) > 0", name="claim_text_not_blank"),
    )
