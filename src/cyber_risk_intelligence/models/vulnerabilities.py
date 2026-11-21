"""Issue 5.1: CISA Known Exploited Vulnerabilities (KEV); 5.2: FIRST EPSS scores (``EpssScore``);
12.1: KEV change events (``KevChangeEvent``); 5.3: NVD records, CVSS scores and CWE weaknesses (``Vulnerability``, ``CvssScore``, ``VulnerabilityWeakness``).

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
from decimal import Decimal

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
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


KEV_CHANGE_TYPES = ("added", "updated", "removed")


class KevChangeEvent(IdMixin, Base):
    """Issue 12.1: one change to the KEV catalog, seen when a newer catalog release was imported.

    ``added``: the CVE is new in this release (``baseline`` is true for every entry of the very first
    catalog we imported, so alerts can skip them). ``updated``: CISA changed listed fields (``changed_fields``
    with ``previous_values`` and ``new_values``; the older values also stay in the older stored catalog).
    ``removed``: the CVE is no longer in the newest release. An unchanged catalog adds no event.
    """

    __tablename__ = "kev_change_events"

    cve_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    kev_entry_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("kev_entries.id", ondelete="CASCADE"), nullable=False, index=True
    )
    release_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("kev_catalog_releases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    change_type: Mapped[str] = mapped_column(Text, nullable=False)
    baseline: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    changed_fields: Mapped[list | None] = mapped_column(JSONB(none_as_null=True))
    previous_values: Mapped[dict | None] = mapped_column(JSONB(none_as_null=True))
    new_values: Mapped[dict | None] = mapped_column(JSONB(none_as_null=True))
    date_added: Mapped[date | None] = mapped_column(Date)  # CISA's dateAdded at the time of the event
    required_action: Mapped[str | None] = mapped_column(Text)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    evidence_version_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("evidence_versions.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    ingestion_run_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("ingestion_runs.id", ondelete="SET NULL"), index=True
    )

    __table_args__ = (
        UniqueConstraint("cve_id", "release_id", "change_type", name="uq_kev_change_events_cve_release_type"),
        CheckConstraint(in_list("change_type", KEV_CHANGE_TYPES), name="change_type"),
        CheckConstraint("change_type = 'updated' OR changed_fields IS NULL", name="fields_only_for_updates"),
    )


class EpssScore(IdMixin, Base):
    """Issue 5.2: one FIRST EPSS score for one CVE on one scoring date.

    ``epss`` is the estimated probability (0-1) of exploitation activity against the CVE anywhere in
    the next 30 days; ``percentile`` (0-1) ranks it among all scored CVEs that day. Both are about
    the CVE, not about any company: never a company's chance of a loss. A new date adds a row, so
    past scores are kept.
    """

    __tablename__ = "epss_scores"

    cve_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    score_date: Mapped[date] = mapped_column(Date, nullable=False)
    epss: Mapped[Decimal] = mapped_column(Numeric(12, 9), nullable=False)
    percentile: Mapped[Decimal] = mapped_column(Numeric(12, 9), nullable=False)
    model_version: Mapped[str | None] = mapped_column(Text)
    scored_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))  # the file's score_date stamp
    evidence_version_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("evidence_versions.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    ingestion_run_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("ingestion_runs.id", ondelete="SET NULL"), index=True
    )

    __table_args__ = (
        UniqueConstraint("cve_id", "score_date", name="uq_epss_scores_cve_date"),
        CheckConstraint(f"cve_id ~ '{CVE_PATTERN}'", name="cve_id_format"),
        CheckConstraint("epss >= 0 AND epss <= 1", name="epss_range"),
        CheckConstraint("percentile >= 0 AND percentile <= 1", name="percentile_range"),
    )


NVD_OUTCOMES = ("found", "not_found", "lookup_failed")
CVSS_VERSIONS = ("2.0", "3.0", "3.1", "4.0")


class Vulnerability(IdMixin, Base):
    """Issue 5.3: one CVE as the NVD describes it.

    ``outcome`` says how the last NVD lookup ended: ``found``, ``not_found`` (NVD has no record) or
    ``lookup_failed`` (no answer; unknown, retried next run). ``vuln_status`` is NVD's own status
    (Analyzed, Modified, Awaiting Analysis, Deferred, Rejected ...): a record NVD hasn't analysed may
    have no score, which stays missing rather than guessed. ``affected_products`` are the vendor:product
    pairs NVD lists as vulnerable; ``references`` are NVD's links. ``evidence_version_id`` is the stored
    NVD record these values came from; earlier versions stay in earlier evidence.
    """

    __tablename__ = "vulnerabilities"

    cve_id: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    outcome: Mapped[str] = mapped_column(Text, nullable=False)
    vuln_status: Mapped[str | None] = mapped_column(Text)
    source_identifier: Mapped[str | None] = mapped_column(Text)  # who assigned the CVE (the CNA)
    description: Mapped[str | None] = mapped_column(Text)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    affected_products: Mapped[list | None] = mapped_column(JSONB(none_as_null=True))
    affected_cpe_count: Mapped[int | None] = mapped_column(Integer)
    references: Mapped[list | None] = mapped_column(JSONB(none_as_null=True))
    message: Mapped[str | None] = mapped_column(Text)
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    evidence_version_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("evidence_versions.id", ondelete="RESTRICT"), index=True
    )
    ingestion_run_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("ingestion_runs.id", ondelete="SET NULL"), index=True
    )

    __table_args__ = (
        CheckConstraint(f"cve_id ~ '{CVE_PATTERN}'", name="cve_id_format"),
        CheckConstraint(in_list("outcome", NVD_OUTCOMES), name="outcome"),
        # A CVE NVD later drops keeps the last record we had as its evidence.
        CheckConstraint("outcome <> 'found' OR evidence_version_id IS NOT NULL", name="evidence_when_found"),
    )


class CvssScore(IdMixin, Base):
    """One CVSS assessment of a CVE, always labelled with its CVSS version, who scored it (``source``:
    NVD or the CNA/ADP) and whether NVD lists it as Primary or Secondary. Versions are never merged."""

    __tablename__ = "cvss_scores"

    vulnerability_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    cvss_version: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    score_type: Mapped[str | None] = mapped_column(Text)  # NVD's Primary / Secondary
    vector_string: Mapped[str] = mapped_column(Text, nullable=False)
    base_score: Mapped[Decimal] = mapped_column(Numeric(3, 1), nullable=False)
    base_severity: Mapped[str | None] = mapped_column(Text)
    attack_vector: Mapped[str | None] = mapped_column(Text)
    user_interaction: Mapped[str | None] = mapped_column(Text)
    privileges_required: Mapped[str | None] = mapped_column(Text)
    exploitability_score: Mapped[Decimal | None] = mapped_column(Numeric(3, 1))
    impact_score: Mapped[Decimal | None] = mapped_column(Numeric(3, 1))
    evidence_version_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("evidence_versions.id", ondelete="RESTRICT"), nullable=False, index=True
    )

    __table_args__ = (
        CheckConstraint(in_list("cvss_version", CVSS_VERSIONS), name="cvss_version"),
        CheckConstraint("base_score >= 0 AND base_score <= 10", name="base_score_range"),
    )


class VulnerabilityWeakness(IdMixin, Base):
    """A CWE weakness category NVD or the CNA assigned to a CVE (``NVD-CWE-noinfo`` / ``NVD-CWE-Other``
    kept as given: they mean "not enough information" / "no fitting CWE")."""

    __tablename__ = "vulnerability_weaknesses"

    vulnerability_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    cwe_id: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    weakness_type: Mapped[str | None] = mapped_column(Text)
    evidence_version_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("evidence_versions.id", ondelete="RESTRICT"), nullable=False, index=True
    )

    __table_args__ = (
        UniqueConstraint("vulnerability_id", "cwe_id", "source", name="uq_vulnerability_weaknesses_cwe"),
    )
