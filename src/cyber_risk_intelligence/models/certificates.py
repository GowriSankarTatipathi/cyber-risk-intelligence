"""Issue 10.1: certificates and hostnames from public Certificate Transparency logs.

* ``ct_lookups``: one row per search of a CT log index (Cert Spotter, or crt.sh as a fallback) for a company
  domain: what was asked, when, how it ended, and the stored response. A failed
  search (``lookup_failed``) says nothing about which certificates exist.
* ``certificates``: one row per certificate, identified by the SHA-256 of its
  to-be-signed part (Cert Spotter) or by issuer and serial number (crt.sh), so
  the precertificate and the final certificate and repeat searches collapse to
  one stable record.
* ``certificate_observations``: each time a lookup saw a certificate, with the
  log index's own entry id. This keeps the source observations behind each
  certificate.
* ``certificate_hostnames``: the names a certificate covers. Wildcards
  (``*.example.com``) are kept, marked ``is_wildcard``, and never treated as a
  host that exists. A name is tied to a known domain (``domain_id``) only when
  it is that domain or under it; company links come from ``company_domains``.

* ``website_certificate_checks``: the certificate the company's own website presents (its known domain
  and ``www.`` host, one TLS handshake each), as a browser shows it under Inspect > Security.

The CT tables come from public logs only; no host named in a certificate is resolved, connected to or
scanned. The website check contacts only the company's known website, like visiting its home page.
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
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, IdMixin, in_list

CT_SOURCES = ("certspotter", "crt.sh")
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
    entry_count: Mapped[int | None] = mapped_column(Integer)  # entries returned
    pages: Mapped[int | None] = mapped_column(Integer)  # pages read (Cert Spotter returns 100 per page)
    # False when the search stopped early (page limit, or a page failed after retries): what was read is kept.
    complete: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
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
        CheckConstraint("complete OR outcome = 'answered'", name="incomplete_only_when_answered"),
    )


class Certificate(IdMixin, Base):
    __tablename__ = "certificates"

    issuer_name: Mapped[str] = mapped_column(Text, nullable=False)
    issuer_ca_id: Mapped[int | None] = mapped_column(BigInteger)  # crt.sh CA id
    serial_number: Mapped[str | None] = mapped_column(Text)  # lower-case hex (crt.sh)
    tbs_sha256: Mapped[str | None] = mapped_column(Text, unique=True)  # Cert Spotter certificate identity
    cert_sha256: Mapped[str | None] = mapped_column(Text)
    revoked: Mapped[bool | None] = mapped_column(Boolean)  # as the index reported it; NULL = not reported
    common_name: Mapped[str | None] = mapped_column(Text)
    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("issuer_name", "serial_number", name="uq_certificates_issuer_serial"),
        CheckConstraint("serial_number IS NULL OR (serial_number = lower(serial_number) "
                        "AND serial_number ~ '^[0-9a-f]+$')", name="serial_number_hex"),
        CheckConstraint("tbs_sha256 IS NULL OR tbs_sha256 ~ '^[0-9a-f]{64}$'", name="tbs_sha256_hex"),
        CheckConstraint("serial_number IS NOT NULL OR tbs_sha256 IS NOT NULL", name="has_identity"),
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
    source_entry_id: Mapped[str] = mapped_column(Text, nullable=False)  # the index's id for this entry
    evidence_version_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("evidence_versions.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_ref: Mapped[str] = mapped_column(Text, nullable=False)  # public link to the certificate

    __table_args__ = (
        UniqueConstraint("ct_lookup_id", "source_entry_id", name="uq_certificate_observations_lookup_entry"),
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


WEBSITE_TLS_OUTCOMES = (
    "trusted",      # the certificate verified against the system's trusted roots and matched the host name
    "not_trusted",  # a certificate was presented but did not verify (expired, wrong name, unknown issuer...)
    "unreachable",  # no TLS answer (no such host, refused, timeout): says nothing about the certificate
)


class WebsiteCertificateCheck(IdMixin, Base):
    """The certificate a company's own website presents, as a browser would see it (Inspect > Security).

    Only the company's known domain and its ``www`` host are asked, one TLS handshake each on port 443;
    no other host or port is contacted and none of the names inside the certificate is followed."""

    __tablename__ = "website_certificate_checks"

    domain_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("domains.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    host: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    port: Mapped[int] = mapped_column(Integer, nullable=False, server_default="443")
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    outcome: Mapped[str] = mapped_column(Text, nullable=False)
    message: Mapped[str | None] = mapped_column(Text)  # why it was not trusted / unreachable
    tls_version: Mapped[str | None] = mapped_column(Text)
    cert_sha256: Mapped[str | None] = mapped_column(Text, index=True)
    serial_number: Mapped[str | None] = mapped_column(Text)
    issuer_name: Mapped[str | None] = mapped_column(Text)
    subject_name: Mapped[str | None] = mapped_column(Text)
    common_name: Mapped[str | None] = mapped_column(Text)
    names: Mapped[list | None] = mapped_column(JSONB(none_as_null=True))  # subjectAltName DNS names
    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    evidence_version_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("evidence_versions.id", ondelete="RESTRICT"), index=True
    )
    ingestion_run_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("ingestion_runs.id", ondelete="SET NULL"), index=True
    )

    __table_args__ = (
        CheckConstraint(in_list("outcome", WEBSITE_TLS_OUTCOMES), name="outcome"),
        CheckConstraint("(outcome = 'unreachable') = (cert_sha256 IS NULL)", name="certificate_unless_unreachable"),
        CheckConstraint("(outcome = 'unreachable') = (evidence_version_id IS NULL)", name="evidence_unless_unreachable"),
        CheckConstraint("cert_sha256 IS NULL OR cert_sha256 ~ '^[0-9a-f]{64}$'", name="cert_sha256_hex"),
        CheckConstraint("serial_number IS NULL OR serial_number ~ '^[0-9a-f]+$'", name="serial_number_hex"),
        CheckConstraint("port BETWEEN 1 AND 65535", name="port"),
    )
