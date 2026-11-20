"""Issue 10.1: certificates and hostnames from public Certificate Transparency logs.

* ``ct_lookups``: one row per search of a CT log index (crt.sh) for a company
  domain: what was asked, when, how it ended, and the stored response. A failed
  search (``lookup_failed``) says nothing about which certificates exist.
* ``certificates``: one row per certificate, identified by issuer and serial
  number, so the precertificate and the final certificate (two log entries)
  and repeat searches collapse to one stable record.
* ``certificate_observations``: each time a lookup saw a certificate, with the
  log index's own entry id. This keeps the source observations behind each
  certificate.
* ``certificate_hostnames``: the names a certificate covers. Wildcards
  (``*.example.com``) are kept, marked ``is_wildcard``, and never treated as a
  host that exists. A name is tied to a known domain (``domain_id``) only when
  it is that domain or under it; company links come from ``company_domains``.

Nothing here contacts the hosts. Names are read from public logs only; no host
is resolved, connected to or scanned.
"""

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, IdMixin, in_list

CT_SOURCES = ("crt.sh",)
CT_OUTCOMES = (
    "answered",       # the index answered with at least one certificate
    "no_results",     # the index answered: no current certificate names this domain
    "lookup_failed",  # timeout, 5xx, rate limit, unreadable answer: unknown
)


class CtLookup(IdMixin, Base):
    __tablename__ = "ct_lookups"

    domain_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("domains.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    query: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    request_url: Mapped[str] = mapped_column(Text, nullable=False)
    queried_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    outcome: Mapped[str] = mapped_column(Text, nullable=False)
    http_status: Mapped[int | None] = mapped_column(Integer)
    message: Mapped[str | None] = mapped_column(Text)
    entry_count: Mapped[int | None] = mapped_column(Integer)  # log entries returned
    certificate_count: Mapped[int | None] = mapped_column(Integer)  # distinct certificates among them
    evidence_version_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("evidence_versions.id", ondelete="RESTRICT"), index=True
    )
    ingestion_run_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("ingestion_runs.id", ondelete="SET NULL"), index=True
    )

    __table_args__ = (
        CheckConstraint(in_list("source", CT_SOURCES), name="source"),
        CheckConstraint(in_list("outcome", CT_OUTCOMES), name="outcome"),
        CheckConstraint("(outcome = 'lookup_failed') = (evidence_version_id IS NULL)", name="evidence_unless_failed"),
        CheckConstraint("(outcome = 'lookup_failed') = (entry_count IS NULL)", name="count_unless_failed"),
        CheckConstraint("(outcome = 'no_results') = (entry_count = 0)", name="no_results_means_zero"),
        CheckConstraint("entry_count IS NULL OR entry_count >= 0", name="entry_count"),
    )


class Certificate(IdMixin, Base):
    __tablename__ = "certificates"

    issuer_name: Mapped[str] = mapped_column(Text, nullable=False)
    issuer_ca_id: Mapped[int | None] = mapped_column(BigInteger)  # crt.sh CA id
    serial_number: Mapped[str] = mapped_column(Text, nullable=False)  # lower-case hex
    common_name: Mapped[str | None] = mapped_column(Text)
    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("issuer_name", "serial_number", name="uq_certificates_issuer_serial"),
        CheckConstraint("serial_number = lower(serial_number) AND serial_number ~ '^[0-9a-f]+$'",
                        name="serial_number_hex"),
        CheckConstraint("not_after IS NULL OR not_before IS NULL OR not_after >= not_before", name="validity"),
        CheckConstraint("last_observed_at >= first_observed_at", name="observed_dates"),
    )


class CertificateObservation(IdMixin, Base):
    __tablename__ = "certificate_observations"

    certificate_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("certificates.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ct_lookup_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("ct_lookups.id", ondelete="CASCADE"), nullable=False, index=True
    )
    log_entry_id: Mapped[int] = mapped_column(BigInteger, nullable=False)  # crt.sh certificate id
    evidence_version_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("evidence_versions.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_ref: Mapped[str] = mapped_column(Text, nullable=False)  # link to the log entry

    __table_args__ = (
        UniqueConstraint("ct_lookup_id", "log_entry_id", name="uq_certificate_observations_lookup_entry"),
    )


class CertificateHostname(IdMixin, Base):
    __tablename__ = "certificate_hostnames"

    certificate_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("certificates.id", ondelete="CASCADE"), nullable=False, index=True
    )
    hostname: Mapped[str] = mapped_column(Text, nullable=False, index=True)  # as in the certificate, lower-case
    is_wildcard: Mapped[bool] = mapped_column(Boolean, nullable=False)
    base_name: Mapped[str] = mapped_column(Text, nullable=False)  # the name without a leading "*."
    domain_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("domains.id", ondelete="SET NULL"), index=True
    )

    __table_args__ = (
        UniqueConstraint("certificate_id", "hostname", name="uq_certificate_hostnames_name"),
        CheckConstraint("hostname = lower(hostname) AND hostname !~ '[/:@ ]'", name="hostname_normalized"),
        CheckConstraint("is_wildcard = (hostname LIKE '*.%')", name="wildcard_flag"),
        CheckConstraint("base_name = CASE WHEN is_wildcard THEN substr(hostname, 3) ELSE hostname END",
                        name="base_name"),
    )
