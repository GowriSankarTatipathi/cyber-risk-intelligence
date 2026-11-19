"""Issue 17.8: ingestion runs and data quality.

* ``ingestion_runs``: one execution of an import job, with its status, row
  counts, the stored raw input (17.7 evidence) and, for a retry, the run it retries.
* ``ingestion_errors``: every rejected row or failure, with the reason.
* ``validation_results``: per run, how many rows each rule checked and failed.
* ``data_versions``: each distinct content of a dataset gets a version number,
  so we know which version of the input a record came from.
* ``ingestion_cursors``: where a job should resume next time (a page token,
  a date, or the last processed data version).
"""

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, CheckConstraint, DateTime, ForeignKey, Integer, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, IdMixin, in_list

RUN_STATUSES = ("running", "succeeded", "partial", "failed")
ERROR_STAGES = ("parse", "validate", "write", "run")
SEVERITIES = ("error", "warning", "info")


class DataVersion(IdMixin, Base):
    __tablename__ = "data_versions"

    dataset_key: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_version_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("evidence_versions.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    row_count: Mapped[int | None] = mapped_column(Integer)

    __table_args__ = (
        UniqueConstraint("dataset_key", "version", name="uq_data_versions_version"),
        UniqueConstraint("dataset_key", "sha256", name="uq_data_versions_content"),
        CheckConstraint("version > 0", name="version_positive"),
        CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name="sha256_format"),
    )


class IngestionRun(IdMixin, Base):
    __tablename__ = "ingestion_runs"

    job_name: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    source_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("sources.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="running")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    input_evidence_version_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("evidence_versions.id", ondelete="RESTRICT"), index=True
    )
    data_version_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("data_versions.id", ondelete="RESTRICT"), index=True
    )
    retry_of_run_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("ingestion_runs.id", ondelete="SET NULL"), index=True
    )
    # Rows up to and including this number are committed; a retry resumes after it.
    last_committed_row: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    resumed_from_row: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    rows_seen: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    rows_inserted: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    rows_updated: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    rows_unchanged: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    rows_rejected: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    error_message: Mapped[str | None] = mapped_column(Text)
    parameters: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    errors: Mapped[list["IngestionError"]] = relationship(back_populates="run", order_by="IngestionError.id")
    validation_results: Mapped[list["ValidationResult"]] = relationship(back_populates="run")
    data_version: Mapped[DataVersion | None] = relationship()

    __table_args__ = (
        CheckConstraint(in_list("status", RUN_STATUSES), name="status"),
        CheckConstraint("(status = 'running') = (finished_at IS NULL)", name="finished_when_done"),
        CheckConstraint(
            "least(rows_seen, rows_inserted, rows_updated, rows_unchanged, rows_rejected, last_committed_row, resumed_from_row) >= 0",
            name="counts_non_negative",
        ),
    )


class IngestionError(IdMixin, Base):
    __tablename__ = "ingestion_errors"

    run_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("ingestion_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    stage: Mapped[str] = mapped_column(Text, nullable=False)
    code: Mapped[str] = mapped_column(Text, nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    row_number: Mapped[int | None] = mapped_column(Integer)
    row_key: Mapped[str | None] = mapped_column(Text)
    field: Mapped[str | None] = mapped_column(Text)
    # The offending input row, unless it looked like it held a secret.
    raw_row: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    run: Mapped[IngestionRun] = relationship(back_populates="errors")

    __table_args__ = (CheckConstraint(in_list("stage", ERROR_STAGES), name="stage"),)


class ValidationResult(IdMixin, Base):
    """Outcome of one rule, either for an import run (17.8) or a database-wide validation run (27.7)."""

    __tablename__ = "validation_results"

    run_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("ingestion_runs.id", ondelete="CASCADE"), index=True
    )
    validation_run_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("validation_runs.id", ondelete="CASCADE"), index=True
    )
    rule: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    rows_checked: Mapped[int] = mapped_column(Integer, nullable=False)
    rows_failed: Mapped[int] = mapped_column(Integer, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    run: Mapped[IngestionRun | None] = relationship(back_populates="validation_results")

    __table_args__ = (
        UniqueConstraint("run_id", "rule", name="uq_validation_results_rule"),
        UniqueConstraint("validation_run_id", "rule", name="uq_validation_results_validation_rule"),
        CheckConstraint("num_nonnulls(run_id, validation_run_id) = 1", name="exactly_one_run"),
        CheckConstraint(in_list("severity", SEVERITIES), name="severity"),
        CheckConstraint("rows_failed BETWEEN 0 AND rows_checked", name="failed_le_checked"),
    )


class IngestionCursor(IdMixin, Base):
    __tablename__ = "ingestion_cursors"

    job_name: Mapped[str] = mapped_column(Text, nullable=False)
    source_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("sources.id", ondelete="CASCADE"), nullable=False
    )
    cursor: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    last_run_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("ingestion_runs.id", ondelete="SET NULL")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    __table_args__ = (UniqueConstraint("job_name", "source_id", name="uq_ingestion_cursors_job"),)
