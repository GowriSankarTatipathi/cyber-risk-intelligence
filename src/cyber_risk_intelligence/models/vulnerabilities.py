"""Issue 5.1: CISA Known Exploited Vulnerabilities (KEV).

* ``kev_catalog_releases``: one row per catalog release CISA published that we imported: its version,
  release time, entry count and the stored snapshot (evidence) of the whole catalog.
* ``kev_entries``: one row per CVE in the catalog, with the values CISA gives (vendor, product, date
  added, required action, due date, known ransomware use ...). ``first_seen_release_id`` and
  ``last_seen_release_id`` say in which catalog versions we saw it; an entry whose last release is
  not the newest one has left the catalog. ``evidence_version_id`` is the snapshot its current values
  came from; older values stay in the older snapshots.

KEV is a reference catalog, not a company finding: it says a CVE was exploited somewhere, not that a
company is affected.
"""

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

from .base import Base, IdMixin, in_list

CVE_PATTERN = r"^CVE-[0-9]{4}-[0-9]{4,}$"
RANSOMWARE_USE = ("Known", "Unknown")


class KevCatalogRelease(IdMixin, Base):
    __tablename__ = "kev_catalog_releases"

    catalog_version: Mapped[str] = mapped_column(Text, nullable=False)
    date_released: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    entry_count: Mapped[int | None] = mapped_column(Integer)  # the count CISA states
    evidence_version_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("evidence_versions.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    ingestion_run_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("ingestion_runs.id", ondelete="SET NULL"), index=True
    )
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # CISA can publish more than one release with the same version label on one day.
    __table_args__ = (UniqueConstraint("catalog_version", "date_released", name="uq_kev_catalog_releases_version"),)


class KevEntry(IdMixin, Base):
    __tablename__ = "kev_entries"

    cve_id: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    vendor_project: Mapped[str] = mapped_column(Text, nullable=False)
    product: Mapped[str] = mapped_column(Text, nullable=False)
    vulnerability_name: Mapped[str | None] = mapped_column(Text)
    short_description: Mapped[str | None] = mapped_column(Text)
    date_added: Mapped[date] = mapped_column(Date, nullable=False)
    required_action: Mapped[str] = mapped_column(Text, nullable=False)
    due_date: Mapped[date | None] = mapped_column(Date)
    known_ransomware_use: Mapped[str | None] = mapped_column(Text)  # CISA's Known / Unknown; NULL = not given
    forensic_triage: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)
    cwes: Mapped[list | None] = mapped_column(JSONB(none_as_null=True))
    first_seen_release_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("kev_catalog_releases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    last_seen_release_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("kev_catalog_releases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    evidence_version_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("evidence_versions.id", ondelete="RESTRICT"), nullable=False, index=True
    )

    __table_args__ = (
        CheckConstraint(f"cve_id ~ '{CVE_PATTERN}'", name="cve_id_format"),
        CheckConstraint("known_ransomware_use IS NULL OR " + in_list("known_ransomware_use", RANSOMWARE_USE),
                        name="known_ransomware_use"),
    )
