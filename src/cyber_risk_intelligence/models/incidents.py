"""Issue 3.3: healthcare breaches reported to HHS (OCR breach portal).

* ``healthcare_breach_records``: one row per breach report on the HHS OCR portal ("wall of shame":
  breaches of protected health information affecting 500 or more people). HHS publishes no record id, so
  a report is identified by the covered entity's normalized name, state, submission date and, for the rare
  reports that share all three, their order in the list (``same_day_seq``; ``ambiguous_identity`` marks
  them). A later download with a different count, type, location, description or list (under
  investigation -> archive) updates the row and appends the earlier values to ``revisions``: a new
  version, never a second incident.
* ``healthcare_breach_company_candidates``: possible links from a report to one of our companies, found by
  name only. They stay ``unverified`` until someone records a source that confirms (or rejects) the
  identity: a name match alone is never treated as the company.
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
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, IdMixin, in_list

HHS_LISTS = ("under_investigation", "archived")
CANDIDATE_STATUSES = ("unverified", "confirmed", "rejected")


class HealthcareBreachRecord(IdMixin, Base):
    __tablename__ = "healthcare_breach_records"

    incident_key: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    entity_name: Mapped[str] = mapped_column(Text, nullable=False)  # as HHS publishes it
    normalized_name: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    state: Mapped[str | None] = mapped_column(Text)
    entity_type: Mapped[str | None] = mapped_column(Text)  # Healthcare Provider, Health Plan, Business Associate ...
    individuals_affected: Mapped[int | None] = mapped_column(BigInteger)
    submitted_on: Mapped[date] = mapped_column(Date, nullable=False, index=True)  # reported to HHS, not the breach date
    breach_types: Mapped[list | None] = mapped_column(JSONB(none_as_null=True))
    locations: Mapped[list | None] = mapped_column(JSONB(none_as_null=True))
    business_associate_present: Mapped[bool | None] = mapped_column(Boolean)
    web_description: Mapped[str | None] = mapped_column(Text)
    list_status: Mapped[str] = mapped_column(Text, nullable=False)
    same_day_seq: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    ambiguous_identity: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    revisions: Mapped[list | None] = mapped_column(JSONB(none_as_null=True))
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
        CheckConstraint(in_list("list_status", HHS_LISTS), name="list_status"),
        CheckConstraint("individuals_affected IS NULL OR individuals_affected >= 0", name="individuals_non_negative"),
        CheckConstraint("same_day_seq >= 1", name="same_day_seq_positive"),
    )


class HealthcareBreachCompanyCandidate(IdMixin, Base):
    __tablename__ = "healthcare_breach_company_candidates"

    breach_record_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("healthcare_breach_records.id", ondelete="CASCADE"), nullable=False, index=True
    )
    company_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    match_basis: Mapped[str] = mapped_column(Text, nullable=False)  # exact_name / exact_alias / name_prefix
    matched_name: Mapped[str] = mapped_column(Text, nullable=False)  # our name or alias that matched
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="unverified")
    review_source_url: Mapped[str | None] = mapped_column(Text)  # the source that confirmed or rejected it
    review_note: Mapped[str | None] = mapped_column(Text)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    found_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("breach_record_id", "company_id", name="uq_healthcare_breach_candidates_pair"),
        CheckConstraint(in_list("status", CANDIDATE_STATUSES), name="status"),
        CheckConstraint("status = 'unverified' OR review_source_url IS NOT NULL", name="review_needs_source"),
    )
