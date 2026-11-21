"""Record, link and read evidence."""

from collections.abc import Collection
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Base, EvidenceLink, EvidenceObject, EvidenceVersion, Source
from ..models.evidence import LINK_TARGETS
from .secrets import SecretDetected, find_secrets
from .store import ObjectStore, sha256_hex


class ChecksumMismatch(RuntimeError):
    pass


def record_evidence(
    session: Session,
    store: ObjectStore,
    *,
    source: Source,
    source_url: str,
    content: bytes,
    media_type: str,
    title: str | None = None,
    http_status: int | None = None,
    published_at: datetime | None = None,
    observed_at: datetime | None = None,
    archive_url: str | None = None,
    archive_captured_at: datetime | None = None,
    notes: str | None = None,
    allow_secret_kinds: Collection[str] = (),
) -> EvidenceVersion:
    """Store ``content`` and record that it was captured from ``source_url``.

    Unknown dates stay NULL. Capturing the same bytes from the same URL again only
    moves ``last_seen_at``; different bytes create a new version, so history is kept.
    Raises ``SecretDetected`` (nothing stored) if the content looks like it holds credentials.
    ``allow_secret_kinds`` names patterns a source is known to trip on harmlessly (for example
    NVD descriptions quoting an exploit URL with ``password=...``); every other pattern still blocks.
    """
    if not source.is_permitted:
        raise PermissionError(f"Source {source.source_key!r} is not permitted for collection")
    kinds = [k for k in find_secrets(content) if k not in allow_secret_kinds]
    if kinds:
        raise SecretDetected(kinds)

    stored = store.put(content, media_type)
    obj = session.scalar(select(EvidenceObject).where(EvidenceObject.sha256 == stored.sha256))
    if obj is None:
        obj = EvidenceObject(
            sha256=stored.sha256,
            size_bytes=stored.size_bytes,
            media_type=media_type,
            storage_backend=stored.backend,
            bucket=stored.bucket,
            object_key=stored.key,
        )
        session.add(obj)
        session.flush()

    version = session.scalar(
        select(EvidenceVersion).where(
            EvidenceVersion.source_id == source.id,
            EvidenceVersion.source_url == source_url,
            EvidenceVersion.evidence_object_id == obj.id,
        )
    )
    if version is not None:
        version.last_seen_at = func.now()
        # Fill in dates we didn't know before, but never overwrite known ones.
        for name, value in (("published_at", published_at), ("archive_url", archive_url),
                            ("archive_captured_at", archive_captured_at), ("title", title)):
            if value is not None and getattr(version, name) is None:
                setattr(version, name, value)
        session.flush()
        session.refresh(version)
        return version

    version = EvidenceVersion(
        source_id=source.id,
        evidence_object=obj,
        source_url=source_url,
        title=title,
        http_status=http_status,
        published_at=published_at,
        observed_at=observed_at,
        archive_url=archive_url,
        archive_captured_at=archive_captured_at,
        notes=notes,
    )
    session.add(version)
    session.flush()
    return version


def link_evidence(
    session: Session,
    version: EvidenceVersion,
    record: Base,
    *,
    relation: str = "supports",
    locator: str | None = None,
    note: str | None = None,
) -> EvidenceLink:
    """Attach ``version`` as evidence for ``record`` (a company, entity, identifier, ...)."""
    column = f"{_singular(record.__tablename__)}_id"
    if column not in LINK_TARGETS:
        raise TypeError(f"Evidence cannot be linked to {type(record).__name__} yet")
    if record.id is None:
        session.flush()
    link = EvidenceLink(evidence_version_id=version.id, relation=relation, locator=locator, note=note, **{column: record.id})
    session.add(link)
    session.flush()
    return link


def read_evidence(session: Session, store: ObjectStore, version: EvidenceVersion) -> bytes:
    """Return the original bytes, after checking they still match the recorded checksum."""
    obj = version.evidence_object
    content = store.get(obj.object_key)
    if sha256_hex(content) != obj.sha256 or len(content) != obj.size_bytes:
        raise ChecksumMismatch(f"Evidence object {obj.id} does not match its checksum")
    return content


def _singular(table: str) -> str:
    if table.endswith("ies"):
        return table[:-3] + "y"
    if table.endswith("ses"):
        return table[:-2]
    return table[:-1]
