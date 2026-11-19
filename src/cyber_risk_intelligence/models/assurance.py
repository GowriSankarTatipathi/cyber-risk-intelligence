"""Issue 1.3: security certifications, attestations and authorizations.

``security_assurances`` holds one row per statement that a company holds an
independent security assessment, from one source:

* ``basis = 'company_claim'``: the company says so on its own site (from a 1.1
  claim, e.g. "we are ISO 27001 certified"). Status ``claimed``.
* ``basis = 'company_document'``: the company publishes the certificate or
  report itself (an ISO certificate PDF, a SOC 3 report). Better evidence, with
  issuer, dates and scope, but still the company's own publication: ``claimed``.
* ``basis = 'issuer_directory'``: the record appears in an independent
  register run by the issuer or accreditation system (IAF CertSearch, UKAS
  CertCheck, FedRAMP Marketplace, CSA STAR Registry ...). Only these rows are
  ``verified``; the database refuses a verified row with any other basis.

Certifications (ISO/IEC 27001 ...) are kept apart from attestations (SOC 1/2/3
reports, PCI DSS) and government authorizations (FedRAMP ...) by ``kind``.
Unknown dates stay NULL; a report the company only shares under NDA is recorded
with ``report_availability = 'gated'``, not left out.
"""

from datetime import date, datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, IdMixin, in_list

# framework -> kind. Only independent assessments; self-declared alignment (GDPR, HIPAA, NIST CSF) is not here.
FRAMEWORKS: dict[str, str] = {
    "ISO/IEC 27001": "certification",
    "ISO/IEC 27017": "certification",
    "ISO/IEC 27018": "certification",
    "ISO/IEC 27701": "certification",
    "ISO 22301": "certification",
    "ISO 9001": "certification",
    "HITRUST": "certification",
    "CSA STAR": "certification",
    "TISAX": "certification",
    "Cyber Essentials": "certification",
    "Cyber Essentials Plus": "certification",
    "CMMC": "certification",
    "SOC 1": "attestation",
    "SOC 2": "attestation",
    "SOC 3": "attestation",
    "PCI DSS": "attestation",
    "C5": "attestation",
    "FedRAMP": "authorization",
    "StateRAMP": "authorization",
    "IRAP": "authorization",
}
KINDS = ("certification", "attestation", "authorization")
REPORT_TYPES = ("Type I", "Type II")  # SOC 1 and SOC 2 only
BASES = ("company_claim", "company_document", "issuer_directory")
ASSURANCE_STATUSES = ("claimed", "verified")
REPORT_AVAILABILITY = ("public", "gated", "unknown")
DIRECTORY_STATUSES = ("active", "expired", "suspended", "withdrawn", "unknown")


def _kind_matches_framework() -> str:
    cases = " ".join(f"WHEN '{f}' THEN '{k}'" for f, k in FRAMEWORKS.items())
    return f"kind = CASE framework {cases} END"


class SecurityAssurance(IdMixin, Base):
    __tablename__ = "security_assurances"

    company_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    legal_entity_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("legal_entities.id", ondelete="SET NULL"), index=True
    )
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    framework: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    report_type: Mapped[str | None] = mapped_column(Text)  # SOC 1/2: Type I or Type II
    level: Mapped[str | None] = mapped_column(Text)  # e.g. FedRAMP "High", CSA STAR "Level 2"

    basis: Mapped[str] = mapped_column(Text, nullable=False)
    verification_status: Mapped[str] = mapped_column(Text, nullable=False)
    report_availability: Mapped[str] = mapped_column(Text, nullable=False, server_default="unknown")

    issuer: Mapped[str | None] = mapped_column(Text)  # certification body / audit firm / authorizing body
    accreditation_body: Mapped[str | None] = mapped_column(Text)  # e.g. UKAS, ANAB
    certificate_number: Mapped[str | None] = mapped_column(Text)
    scope_text: Mapped[str | None] = mapped_column(Text)
    issued_on: Mapped[date | None] = mapped_column(Date)
    valid_from: Mapped[date | None] = mapped_column(Date)
    valid_until: Mapped[date | None] = mapped_column(Date)  # expiry, where the scheme has one
    period_start: Mapped[date | None] = mapped_column(Date)  # SOC 2 Type II: period the auditor examined
    period_end: Mapped[date | None] = mapped_column(Date)
    directory_status: Mapped[str | None] = mapped_column(Text)  # issuer_directory rows: status in the register

    evidence_version_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("evidence_versions.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    claim_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("security_control_claims.id", ondelete="SET NULL"), index=True
    )
    source_ref: Mapped[str | None] = mapped_column(Text)  # URL of the page, document or register entry
    quote: Mapped[str | None] = mapped_column(Text)  # the sentence or certificate text this row is read from
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        UniqueConstraint("company_id", "framework", "report_type", "level", "basis", "evidence_version_id",
                         "certificate_number", name="uq_security_assurances_statement",
                         postgresql_nulls_not_distinct=True),
        CheckConstraint(in_list("framework", tuple(FRAMEWORKS)), name="framework"),
        CheckConstraint(_kind_matches_framework(), name="kind_matches_framework"),
        CheckConstraint(in_list("basis", BASES), name="basis"),
        CheckConstraint(in_list("verification_status", ASSURANCE_STATUSES), name="verification_status"),
        CheckConstraint(in_list("report_availability", REPORT_AVAILABILITY), name="report_availability"),
        CheckConstraint("report_type IS NULL OR (framework IN ('SOC 1', 'SOC 2') AND "
                        + in_list("report_type", REPORT_TYPES) + ")", name="report_type"),
        # Only an independent register verifies; what a company says or publishes about itself never does.
        CheckConstraint("(verification_status = 'verified') = (basis = 'issuer_directory')",
                        name="verified_only_from_directory"),
        CheckConstraint("(directory_status IS NULL OR basis = 'issuer_directory') AND "
                        f"(directory_status IS NULL OR {in_list('directory_status', DIRECTORY_STATUSES)})",
                        name="directory_status"),
        CheckConstraint("valid_until IS NULL OR valid_from IS NULL OR valid_until >= valid_from", name="valid_dates"),
        CheckConstraint("period_end IS NULL OR period_start IS NULL OR period_end >= period_start",
                        name="period_dates"),
    )
