"""Issue 27.7: database-wide data-quality validation runs.

* ``validation_runs``: one execution of the check suite over the whole database.
* ``validation_results`` (shared with 17.8): per check, rows checked and failed.
* ``validation_findings``: each affected record (table + id) with the reason.
"""

from datetime import datetime

from sqlalchemy import BigInteger, CheckConstraint, DateTime, ForeignKey, Integer, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, IdMixin, in_list
from .ingestion import SEVERITIES, ValidationResult

VALIDATION_STATUSES = ("running", "passed", "warnings", "failed", "error")


class ValidationRun(IdMixin, Base):
    __tablename__ = "validation_runs"

    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="running")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    checks_run: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    errors: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    warnings: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    # What was checked (e.g. whether stored evidence bytes were re-hashed) and the code version.
    scope: Mapped[str | None] = mapped_column(Text)
    error_message: Mapped[str | None] = mapped_column(Text)

    results: Mapped[list[ValidationResult]] = relationship(
        primaryjoin="ValidationRun.id == foreign(ValidationResult.validation_run_id)",
        order_by="ValidationResult.id",
        viewonly=True,
    )
    findings: Mapped[list["ValidationFinding"]] = relationship(back_populates="run", order_by="ValidationFinding.id")

    __table_args__ = (
        CheckConstraint(in_list("status", VALIDATION_STATUSES), name="status"),
        CheckConstraint("(status = 'running') = (finished_at IS NULL)", name="finished_when_done"),
    )


class ValidationFinding(IdMixin, Base):
    __tablename__ = "validation_findings"

    validation_run_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("validation_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    check_name: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    # The affected record. No foreign key on purpose: findings must survive the record being fixed or deleted.
    table_name: Mapped[str] = mapped_column(Text, nullable=False)
    record_id: Mapped[int | None] = mapped_column(BigInteger)
    message: Mapped[str] = mapped_column(Text, nullable=False)

    run: Mapped[ValidationRun] = relationship(back_populates="findings")

    __table_args__ = (CheckConstraint(in_list("severity", SEVERITIES), name="severity"),)
