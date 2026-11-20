"""Issue 10.3: indexed exposure from Shodan InternetDB.

* ``indexed_host_lookups``: one row per (company host, IP) per run: which host and IP were looked up,
  how the lookup ended, Shodan's tags, host names, software (CPE) and inferred CVEs, and how far the
  IP can be tied to the company (``attribution``). A failed DNS or InternetDB lookup is kept as such,
  never read as "nothing exposed".
* ``indexed_service_observations``: one row per port Shodan indexed on a found IP, with a service hint
  from the port number and whether it is a sensitive service (remote admin, file sharing, database).

Shodan's data is indexed, not verified: the scan date is unknown (InternetDB gives none), a port may
be closed now, CVEs are inferred from version strings, and a CDN or shared IP is not the company's.
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
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, IdMixin, in_list

HOST_ROLES = ("website", "mail")
LOOKUP_OUTCOMES = ("found", "not_indexed", "lookup_failed", "dns_failed", "no_address")
ATTRIBUTIONS = ("cdn", "company_only", "shared", "unknown")


class IndexedHostLookup(IdMixin, Base):
    __tablename__ = "indexed_host_lookups"

    company_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("companies.id", ondelete="RESTRICT"), index=True
    )
    domain_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("domains.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    host: Mapped[str] = mapped_column(Text, nullable=False)
    host_role: Mapped[str] = mapped_column(Text, nullable=False)
    ip: Mapped[str | None] = mapped_column(INET, index=True)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    outcome: Mapped[str] = mapped_column(Text, nullable=False)
    attribution: Mapped[str | None] = mapped_column(Text)
    tags: Mapped[list | None] = mapped_column(JSONB(none_as_null=True))
    hostnames: Mapped[list | None] = mapped_column(JSONB(none_as_null=True))
    cpes: Mapped[list | None] = mapped_column(JSONB(none_as_null=True))
    potential_vulns: Mapped[list | None] = mapped_column(JSONB(none_as_null=True))
    source_scan_date: Mapped[date | None] = mapped_column(Date)
    message: Mapped[str | None] = mapped_column(Text)
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    evidence_version_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("evidence_versions.id", ondelete="RESTRICT"), index=True
    )
    ingestion_run_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("ingestion_runs.id", ondelete="SET NULL"), index=True
    )

    __table_args__ = (
        CheckConstraint(in_list("host_role", HOST_ROLES), name="host_role"),
        CheckConstraint(in_list("outcome", LOOKUP_OUTCOMES), name="outcome"),
        CheckConstraint("attribution IS NULL OR " + in_list("attribution", ATTRIBUTIONS), name="attribution"),
        CheckConstraint("(ip IS NULL) = (outcome IN ('dns_failed', 'no_address'))", name="ip_unless_unresolved"),
        CheckConstraint("(outcome = 'found') = (evidence_version_id IS NOT NULL)", name="evidence_when_found"),
        CheckConstraint("(outcome = 'found') = (attribution IS NOT NULL)", name="attribution_when_found"),
    )


class IndexedServiceObservation(IdMixin, Base):
    __tablename__ = "indexed_service_observations"

    lookup_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("indexed_host_lookups.id", ondelete="CASCADE"), nullable=False, index=True
    )
    company_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("companies.id", ondelete="RESTRICT"), index=True
    )
    domain_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("domains.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    ip: Mapped[str] = mapped_column(INET, nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    service_hint: Mapped[str | None] = mapped_column(Text)
    sensitive: Mapped[bool] = mapped_column(Boolean, nullable=False)
    attribution: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    source_scan_date: Mapped[date | None] = mapped_column(Date)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    evidence_version_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("evidence_versions.id", ondelete="RESTRICT"), nullable=False, index=True
    )

    __table_args__ = (
        CheckConstraint("port BETWEEN 1 AND 65535", name="port_range"),
        CheckConstraint(in_list("attribution", ATTRIBUTIONS), name="attribution"),
    )
