"""Declarative base and the provenance columns every collected record carries."""

from datetime import date, datetime

from sqlalchemy import BigInteger, CheckConstraint, Date, DateTime, MetaData, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

# How we know a value. A company's own claim is never "verified".
VERIFICATION_STATUSES = ("verified", "observed", "claimed", "unverified", "unknown")


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def in_list(column: str, values: tuple[str, ...]) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({quoted})"


class IdMixin:
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ProvenanceMixin:
    """Where a fact came from and when it was true.

    ``source_ref`` holds a source URL or citation for now. Issue 17.7 adds an
    ``evidence`` table; these tables will then gain an ``evidence_id`` foreign
    key and ``source_ref`` stays as the human-readable citation.

    NULL always means "not known", never "absent".
    """

    source_ref: Mapped[str | None] = mapped_column(Text)
    verification_status: Mapped[str] = mapped_column(
        Text, nullable=False, server_default="unknown"
    )
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ValidityMixin:
    """Time-bounded facts. ``valid_to`` is exclusive; NULL ends mean open or unknown."""

    valid_from: Mapped[date | None] = mapped_column(Date)
    valid_to: Mapped[date | None] = mapped_column(Date)


def provenance_checks() -> list[CheckConstraint]:
    return [CheckConstraint(in_list("verification_status", VERIFICATION_STATUSES), name="verification_status")]


def validity_checks() -> list[CheckConstraint]:
    return [
        CheckConstraint(
            "valid_from IS NULL OR valid_to IS NULL OR valid_to > valid_from",
            name="valid_period",
        )
    ]
