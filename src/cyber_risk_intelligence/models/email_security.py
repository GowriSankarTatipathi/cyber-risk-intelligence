"""Issues 23.1 and 23.2: DNS lookups and the email-security records read from them (SPF, DMARC).

* ``dns_security_records``: one row per public DNS query we made: the name and
  type asked, the resolver, when, what came back (the raw TXT strings, exactly
  as split on the wire) and how it ended. A failed lookup is recorded as
  ``lookup_failed``; it says nothing about what the domain publishes.
* ``email_security_observations``: what one lookup shows for one control
  (``spf`` now). ``status`` keeps "the domain publishes no SPF record"
  (``missing``) apart from "we could not tell" (``lookup_failed``) and from
  a published but broken record (``invalid``, ``multiple``).
"""

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, IdMixin, in_list

RECORD_TYPES = ("TXT",)
LOOKUP_OUTCOMES = (
    "answered",       # NOERROR with records
    "no_records",     # NOERROR, the name exists but has no records of this type
    "nxdomain",       # the name does not exist
    "lookup_failed",  # timeout, SERVFAIL, REFUSED, network error: unknown
)
CONTROLS = ("spf", "dmarc")
DMARC_POLICIES = ("none", "quarantine", "reject")
ALIGNMENTS = ("relaxed", "strict")
POLICY_SOURCES = ("domain", "organizational_domain")
OBSERVATION_STATUSES = (
    "present",        # exactly one SPF record that parses (it may still have problems listed)
    "missing",        # the domain answered and publishes no SPF record
    "multiple",       # more than one SPF record (an SPF permerror)
    "invalid",        # one SPF record that does not parse
    "no_domain",      # SPF: the domain does not exist (for DMARC a missing _dmarc name is just "missing")
    "lookup_failed",  # we could not find out
)
ALL_QUALIFIERS = ("pass", "fail", "softfail", "neutral")


class DnsSecurityRecord(IdMixin, Base):
    __tablename__ = "dns_security_records"

    domain_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("domains.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    query_name: Mapped[str] = mapped_column(Text, nullable=False)
    record_type: Mapped[str] = mapped_column(Text, nullable=False)
    resolver: Mapped[str] = mapped_column(Text, nullable=False)
    queried_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    outcome: Mapped[str] = mapped_column(Text, nullable=False)
    rcode: Mapped[str | None] = mapped_column(Text)
    message: Mapped[str | None] = mapped_column(Text)
    # Each record is the list of its character-strings, as published (TXT records are split in 255-byte pieces).
    answers: Mapped[list | None] = mapped_column(JSONB(none_as_null=True))
    ttl: Mapped[int | None] = mapped_column(Integer)
    evidence_version_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("evidence_versions.id", ondelete="RESTRICT"), index=True
    )
    ingestion_run_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("ingestion_runs.id", ondelete="SET NULL"), index=True
    )

    __table_args__ = (
        CheckConstraint(in_list("record_type", RECORD_TYPES), name="record_type"),
        CheckConstraint(in_list("outcome", LOOKUP_OUTCOMES), name="outcome"),
        CheckConstraint("(outcome = 'answered') = (answers IS NOT NULL)", name="answers_only_when_answered"),
        CheckConstraint("(outcome = 'lookup_failed') = (evidence_version_id IS NULL)",
                        name="evidence_unless_failed"),
        CheckConstraint("ttl IS NULL OR ttl >= 0", name="ttl"),
    )


class EmailSecurityObservation(IdMixin, Base):
    __tablename__ = "email_security_observations"

    company_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("companies.id", ondelete="CASCADE"), index=True
    )
    domain_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("domains.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    dns_record_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("dns_security_records.id", ondelete="CASCADE"), nullable=False, index=True
    )
    control: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    record_text: Mapped[str | None] = mapped_column(Text)  # the record; several are joined by newlines
    record_count: Mapped[int | None] = mapped_column(Integer)
    all_qualifier: Mapped[str | None] = mapped_column(Text)
    redirect: Mapped[str | None] = mapped_column(Text)
    mechanisms: Mapped[list | None] = mapped_column(JSONB(none_as_null=True))
    modifiers: Mapped[list | None] = mapped_column(JSONB(none_as_null=True))
    dns_lookup_terms: Mapped[int | None] = mapped_column(Integer)
    problems: Mapped[list | None] = mapped_column(JSONB(none_as_null=True))
    # DMARC (23.2). Effective values; ``tags`` keeps the record's tags exactly as published, so a
    # value that was defaulted (left out of the record) can be told from one that was published.
    dmarc_policy: Mapped[str | None] = mapped_column(Text)
    dmarc_subdomain_policy: Mapped[str | None] = mapped_column(Text)
    dmarc_pct: Mapped[int | None] = mapped_column(Integer)
    dkim_alignment: Mapped[str | None] = mapped_column(Text)
    spf_alignment: Mapped[str | None] = mapped_column(Text)
    aggregate_report_uris: Mapped[list | None] = mapped_column(JSONB(none_as_null=True))
    failure_report_uris: Mapped[list | None] = mapped_column(JSONB(none_as_null=True))
    tags: Mapped[dict | None] = mapped_column(JSONB(none_as_null=True))
    defaults_used: Mapped[list | None] = mapped_column(JSONB(none_as_null=True))
    # Where the record was found: at _dmarc.<domain>, or inherited from the organizational domain.
    policy_source: Mapped[str | None] = mapped_column(Text)
    policy_dns_record_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("dns_security_records.id", ondelete="CASCADE"), index=True
    )
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    evidence_version_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("evidence_versions.id", ondelete="RESTRICT"), index=True
    )
    source_ref: Mapped[str | None] = mapped_column(Text)
    verification_status: Mapped[str] = mapped_column(Text, nullable=False, server_default="observed")

    __table_args__ = (
        UniqueConstraint("dns_record_id", "control", name="uq_email_security_observations_lookup_control"),
        CheckConstraint(in_list("control", CONTROLS), name="control"),
        CheckConstraint(in_list("status", OBSERVATION_STATUSES), name="status"),
        CheckConstraint(f"all_qualifier IS NULL OR {in_list('all_qualifier', ALL_QUALIFIERS)}", name="all_qualifier"),
        CheckConstraint("(status IN ('present', 'invalid', 'multiple')) = (record_text IS NOT NULL)",
                        name="record_text_matches_status"),
        CheckConstraint("(status = 'lookup_failed') = (evidence_version_id IS NULL)", name="evidence_unless_failed"),
        CheckConstraint("verification_status = 'observed'", name="verification_status"),
        CheckConstraint("dns_lookup_terms IS NULL OR dns_lookup_terms >= 0", name="dns_lookup_terms"),
        CheckConstraint(f"dmarc_policy IS NULL OR {in_list('dmarc_policy', DMARC_POLICIES)}", name="dmarc_policy"),
        CheckConstraint(f"dmarc_subdomain_policy IS NULL OR {in_list('dmarc_subdomain_policy', DMARC_POLICIES)}",
                        name="dmarc_subdomain_policy"),
        CheckConstraint("dmarc_pct IS NULL OR dmarc_pct BETWEEN 0 AND 100", name="dmarc_pct"),
        CheckConstraint(f"dkim_alignment IS NULL OR {in_list('dkim_alignment', ALIGNMENTS)}", name="dkim_alignment"),
        CheckConstraint(f"spf_alignment IS NULL OR {in_list('spf_alignment', ALIGNMENTS)}", name="spf_alignment"),
        CheckConstraint(f"policy_source IS NULL OR {in_list('policy_source', POLICY_SOURCES)}", name="policy_source"),
        CheckConstraint("control = 'dmarc' OR (dmarc_policy IS NULL AND tags IS NULL AND policy_source IS NULL)",
                        name="dmarc_fields_only_for_dmarc"),
        CheckConstraint("control = 'spf' OR (all_qualifier IS NULL AND mechanisms IS NULL)",
                        name="spf_fields_only_for_spf"),
    )
