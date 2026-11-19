"""Issue 17.7: evidence and historical storage.

* ``sources``: registry of where we collect from (SEC EDGAR, GLEIF, a company
  website, an archive) and on what terms.
* ``evidence_objects``: the original bytes, stored once in object storage
  (MinIO) and addressed by their SHA-256 checksum.
* ``evidence_versions``: one capture of a URL. The same URL captured with new
  content becomes a new version, so history is kept. Publication, archive
  capture, observation and collection times are kept separately.
* ``evidence_links``: which records a capture supports. One capture can support
  many records, and a record can have many captures (including conflicting ones).
"""

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, IdMixin, in_list

SOURCE_TYPES = (
    "regulator", "registry", "exchange", "company_website", "news", "archive",
    "dataset", "vulnerability_db", "breach_disclosure", "other",
)
ACCESS_METHODS = ("api", "bulk_download", "web_page", "archive", "manual", "other")
STORAGE_BACKENDS = ("minio", "local")
LINK_RELATIONS = ("supports", "contradicts", "mentions")

# Records evidence can be attached to. Later issues add a nullable column here
# (and to LINK_TARGETS) for each new table that needs evidence.
LINK_TARGETS = (
    "company_id",
    "legal_entity_id",
    "entity_identifier_id",
    "entity_relationship_id",
    "company_alias_id",
    "company_domain_id",
    "industry_classification_id",
    "index_membership_id",
)


class Source(IdMixin, Base):
    __tablename__ = "sources"

    source_key: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    source_type: Mapped[str] = mapped_column(Text, nullable=False)
    access_method: Mapped[str] = mapped_column(Text, nullable=False)
    base_url: Mapped[str | None] = mapped_column(Text)
    terms_url: Mapped[str | None] = mapped_column(Text)
    license: Mapped[str | None] = mapped_column(Text)
    rate_limit_note: Mapped[str | None] = mapped_column(Text)
    # Collection must stop for a source that is no longer permitted.
    is_permitted: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    notes: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        CheckConstraint("source_key ~ '^[a-z0-9][a-z0-9_-]*$'", name="source_key_format"),
        CheckConstraint(in_list("source_type", SOURCE_TYPES), name="source_type"),
        CheckConstraint(in_list("access_method", ACCESS_METHODS), name="access_method"),
    )


class EvidenceObject(IdMixin, Base):
    """Original bytes, stored once per distinct content."""

    __tablename__ = "evidence_objects"

    sha256: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    media_type: Mapped[str] = mapped_column(Text, nullable=False)
    storage_backend: Mapped[str] = mapped_column(Text, nullable=False)
    bucket: Mapped[str] = mapped_column(Text, nullable=False)
    object_key: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name="sha256_format"),
        CheckConstraint("size_bytes >= 0", name="size_bytes"),
        CheckConstraint(in_list("storage_backend", STORAGE_BACKENDS), name="storage_backend"),
        UniqueConstraint("storage_backend", "bucket", "object_key", name="uq_evidence_objects_location"),
    )


class EvidenceVersion(IdMixin, Base):
    """One capture of ``source_url`` whose content is ``evidence_object``."""

    __tablename__ = "evidence_versions"

    source_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("sources.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    evidence_object_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("evidence_objects.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    source_url: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str | None] = mapped_column(Text)
    http_status: Mapped[int | None] = mapped_column(Integer)
    # NULL means "not known", never "not published".
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    archive_url: Mapped[str | None] = mapped_column(Text)
    archive_captured_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # First and latest time we downloaded exactly this content from this URL.
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    notes: Mapped[str | None] = mapped_column(Text)

    source: Mapped[Source] = relationship()
    evidence_object: Mapped[EvidenceObject] = relationship()
    links: Mapped[list["EvidenceLink"]] = relationship(back_populates="evidence_version")

    __table_args__ = (
        UniqueConstraint("source_id", "source_url", "evidence_object_id", name="uq_evidence_versions_capture"),
        CheckConstraint("last_seen_at >= collected_at", name="seen_after_collected"),
        CheckConstraint("http_status IS NULL OR http_status BETWEEN 100 AND 599", name="http_status"),
        CheckConstraint("archive_captured_at IS NULL OR archive_url IS NOT NULL", name="archive_capture_has_url"),
        Index("ix_evidence_versions_url_collected", "source_url", "collected_at"),
    )


def _fk(table: str) -> Mapped[int | None]:
    return mapped_column(BigInteger, ForeignKey(f"{table}.id", ondelete="CASCADE"), index=True)


class EvidenceLink(IdMixin, Base):
    """Evidence for exactly one record. Deleting the record removes its links."""

    __tablename__ = "evidence_links"

    evidence_version_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("evidence_versions.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    relation: Mapped[str] = mapped_column(Text, nullable=False, server_default="supports")
    # Optional pointer into the document: a field name, XBRL tag, page or CSS selector.
    locator: Mapped[str | None] = mapped_column(Text)
    note: Mapped[str | None] = mapped_column(Text)

    company_id: Mapped[int | None] = _fk("companies")
    legal_entity_id: Mapped[int | None] = _fk("legal_entities")
    entity_identifier_id: Mapped[int | None] = _fk("entity_identifiers")
    entity_relationship_id: Mapped[int | None] = _fk("entity_relationships")
    company_alias_id: Mapped[int | None] = _fk("company_aliases")
    company_domain_id: Mapped[int | None] = _fk("company_domains")
    industry_classification_id: Mapped[int | None] = _fk("industry_classifications")
    index_membership_id: Mapped[int | None] = _fk("index_memberships")

    evidence_version: Mapped[EvidenceVersion] = relationship(back_populates="links")

    __table_args__ = (
        CheckConstraint(f"num_nonnulls({', '.join(LINK_TARGETS)}) = 1", name="exactly_one_target"),
        CheckConstraint(in_list("relation", LINK_RELATIONS), name="relation"),
        UniqueConstraint(
            "evidence_version_id", "relation", "locator", *LINK_TARGETS,
            name="uq_evidence_links_link",
            postgresql_nulls_not_distinct=True,
        ),
    )
