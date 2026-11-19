"""Repeatable, resumable import runs with recorded validation and errors.

A job describes *what* to import (parse rows, validation rules, how to write a
row). ``run_import`` handles the rest the same way for every job:

1. Opens an ``ingestion_runs`` row and commits it first, so even a crash leaves a record.
2. Stores the raw input as evidence (17.7) and assigns a data version.
3. Validates each row; rows failing an ``error`` rule are rejected with reasons,
   ``warning`` rules are recorded but the row is still written.
4. Rejects duplicate keys inside one input.
5. Writes rows in batches. Each row runs in a savepoint, so one bad row can't
   spoil the batch; each batch commits and moves ``last_committed_row``.
6. Ends as ``succeeded`` or ``partial`` (some rows rejected). A run-level
   problem (database gone, source rate limit) marks it ``failed``;
   ``retry_import`` then resumes after the last committed row.

Writes must be idempotent (look up, then insert or update), so repeating an
import never duplicates records.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Literal

from sqlalchemy import func, select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from ..evidence import find_secrets, link_evidence, read_evidence, record_evidence
from ..evidence.store import ObjectStore, sha256_hex
from ..models import (
    Base,
    DataVersion,
    EvidenceVersion,
    IngestionCursor,
    IngestionError,
    IngestionRun,
    Source,
    ValidationResult,
)

RowStatus = Literal["inserted", "updated", "unchanged"]


class RowRejected(Exception):
    """Raised by a job's ``write`` to reject one row with a reason."""

    def __init__(self, code: str, message: str, field: str | None = None):
        super().__init__(message)
        self.code, self.message, self.field = code, message, field


class TransientError(Exception):
    """A run-level problem worth retrying later, e.g. a 429 or 503 from the source."""


class IngestionFailed(RuntimeError):
    def __init__(self, run_id: int, cause: BaseException):
        super().__init__(f"Ingestion run {run_id} failed: {cause}")
        self.run_id = run_id


@dataclass(frozen=True)
class Rule:
    name: str
    check: Callable[[dict[str, Any]], str | None]  # returns a failure message, or None
    severity: Literal["error", "warning"] = "error"
    field: str | None = None


@dataclass(frozen=True)
class SourceSpec:
    source_key: str
    name: str
    source_type: str
    access_method: str
    base_url: str | None = None
    terms_url: str | None = None
    license: str | None = None
    notes: str | None = None


@dataclass(frozen=True)
class InputRow:
    number: int  # 1-based position in the input
    key: str  # stable identity used for de-duplication
    data: dict[str, Any]


@dataclass
class WriteContext:
    session: Session
    run: IngestionRun
    evidence: EvidenceVersion
    row: InputRow

    def cite(self, record: Base, locator: str | None = None) -> None:
        """Link the raw input to ``record`` once (repeat imports don't add duplicates)."""
        locator = locator or f"row {self.row.number}"
        from ..models.evidence import EvidenceLink  # local import to keep the public surface small
        from ..evidence.service import _singular

        column = f"{_singular(record.__tablename__)}_id"
        exists = self.session.scalar(
            select(EvidenceLink.id).where(
                EvidenceLink.evidence_version_id == self.evidence.id,
                getattr(EvidenceLink, column) == record.id,
                EvidenceLink.relation == "supports",
                EvidenceLink.locator == locator,
            )
        )
        if exists is None:
            link_evidence(self.session, self.evidence, record, locator=locator)


class Job:
    """Base class for import jobs. Subclasses set the attributes and implement ``parse`` and ``write``."""

    name: str
    dataset_key: str
    source: SourceSpec
    media_type: str = "text/csv"
    rules: tuple[Rule, ...] = ()

    def parse(self, content: bytes) -> Iterable[InputRow]:
        raise NotImplementedError

    def write(self, ctx: WriteContext) -> RowStatus:
        raise NotImplementedError


@dataclass
class _Tally:
    checked: dict[str, int] = field(default_factory=dict)
    failed: dict[str, int] = field(default_factory=dict)


def ensure_source(session: Session, spec: SourceSpec) -> Source:
    src = session.scalar(select(Source).where(Source.source_key == spec.source_key))
    if src is None:
        src = Source(**spec.__dict__)
        session.add(src)
        session.flush()
    return src


def _safe_raw(data: dict[str, Any]) -> dict[str, Any] | None:
    try:
        encoded = json.dumps(data, default=str).encode()
    except (TypeError, ValueError):
        return None
    return None if find_secrets(encoded) else json.loads(encoded)


def _error(session: Session, run_id: int, stage: str, code: str, message: str,
           row: InputRow | None = None, field: str | None = None) -> None:
    session.add(IngestionError(
        run_id=run_id, stage=stage, code=code, message=message[:2000], field=field,
        row_number=row.number if row else None, row_key=row.key if row else None,
        raw_row=_safe_raw(row.data) if row else None,
    ))


def run_import(
    session_factory: sessionmaker[Session],
    store: ObjectStore,
    job: Job,
    content: bytes,
    *,
    source_url: str,
    batch_size: int = 50,
    retry_of: int | None = None,
    parameters: dict[str, Any] | None = None,
) -> IngestionRun:
    """Run ``job`` over ``content``. Returns the finished run; raises ``IngestionFailed`` if it failed."""
    with session_factory() as s:
        src = ensure_source(s, job.source)
        resume_after = 0
        if retry_of is not None:
            prev = s.get(IngestionRun, retry_of)
            if prev is None or prev.job_name != job.name:
                raise ValueError(f"Run {retry_of} is not a run of {job.name}")
            resume_after = prev.last_committed_row if prev.status == "failed" else 0
        run = IngestionRun(job_name=job.name, source_id=src.id, retry_of_run_id=retry_of,
                           resumed_from_row=resume_after, last_committed_row=resume_after,
                           parameters=parameters)
        s.add(run)
        s.commit()
        run_id = run.id

    tally = _Tally()
    try:
        with session_factory() as s:
            src = s.get(Source, s.get(IngestionRun, run_id).source_id)
            ev = record_evidence(s, store, source=src, source_url=source_url, content=content,
                                 media_type=job.media_type)
            dv = _data_version(s, job.dataset_key, content, ev)
            run = s.get(IngestionRun, run_id)
            run.input_evidence_version_id, run.data_version_id = ev.id, dv.id
            s.commit()
            ev_id = ev.id

        rows = job.parse(content)
        seen: dict[str, int] = {}
        batch: list[InputRow] = []
        for row in rows:
            if row.key in seen:
                if row.number > resume_after:
                    batch.append(InputRow(row.number, row.key, {**row.data, "__duplicate_of__": seen[row.key]}))
            else:
                seen[row.key] = row.number
                if row.number > resume_after:
                    batch.append(row)
            if len(batch) >= batch_size:
                _process_batch(session_factory, run_id, ev_id, job, batch, tally)
                batch = []
        if batch:
            _process_batch(session_factory, run_id, ev_id, job, batch, tally)

        with session_factory() as s:
            run = s.get(IngestionRun, run_id)
            _save_tally(s, run_id, job, tally)
            dv = s.get(DataVersion, run.data_version_id)
            if dv.row_count is None:
                dv.row_count = len(seen)
            run.status = "partial" if run.rows_rejected else "succeeded"
            run.finished_at = func.now()
            _save_cursor(s, job, run, {"data_version": dv.version, "sha256": dv.sha256})
            s.commit()
            s.refresh(run)
            s.expunge(run)
            return run
    except BaseException as exc:  # noqa: BLE001 - record any failure, then re-raise
        with session_factory() as s:
            run = s.get(IngestionRun, run_id)
            _save_tally(s, run_id, job, tally)
            run.status = "failed"
            run.finished_at = func.now()
            run.error_message = f"{type(exc).__name__}: {exc}"[:2000]
            _error(s, run_id, "run", type(exc).__name__, str(exc) or type(exc).__name__)
            s.commit()
        if isinstance(exc, Exception):
            raise IngestionFailed(run_id, exc) from exc
        raise


def retry_import(session_factory: sessionmaker[Session], store: ObjectStore, job: Job, run_id: int,
                 *, batch_size: int = 50) -> IngestionRun:
    """Retry a run from its stored input. A failed run resumes after its last committed row."""
    with session_factory() as s:
        prev = s.get(IngestionRun, run_id)
        if prev is None or prev.input_evidence_version_id is None:
            raise ValueError(f"Run {run_id} has no stored input to retry")
        ev = s.get(EvidenceVersion, prev.input_evidence_version_id)
        content = read_evidence(s, store, ev)
        url = ev.source_url
    return run_import(session_factory, store, job, content, source_url=url,
                      batch_size=batch_size, retry_of=run_id)


def _data_version(s: Session, dataset_key: str, content: bytes, ev: EvidenceVersion) -> DataVersion:
    digest = sha256_hex(content)
    dv = s.scalar(select(DataVersion).where(DataVersion.dataset_key == dataset_key, DataVersion.sha256 == digest))
    if dv is None:
        latest = s.scalar(select(func.max(DataVersion.version)).where(DataVersion.dataset_key == dataset_key)) or 0
        dv = DataVersion(dataset_key=dataset_key, version=latest + 1, sha256=digest, evidence_version_id=ev.id)
        s.add(dv)
        s.flush()
    return dv


def _process_batch(session_factory: sessionmaker[Session], run_id: int, ev_id: int, job: Job,
                   batch: list[InputRow], tally: _Tally) -> None:
    with session_factory() as s:
        run = s.get(IngestionRun, run_id)
        ev = s.get(EvidenceVersion, ev_id)
        for row in batch:
            run.rows_seen += 1
            if "__parse_error__" in row.data:
                _error(s, run_id, "parse", "parse_error", str(row.data["__parse_error__"]), row)
                run.rows_rejected += 1
                continue
            if "__duplicate_of__" in row.data:
                _error(s, run_id, "validate", "duplicate_in_input",
                       f"Same key as row {row.data['__duplicate_of__']}", row)
                run.rows_rejected += 1
                continue
            if _validate(s, run_id, job, row, tally):
                run.rows_rejected += 1
                continue
            try:
                with s.begin_nested():
                    status = job.write(WriteContext(s, run, ev, row))
            except RowRejected as rej:
                _error(s, run_id, "write", rej.code, rej.message, row, rej.field)
                run.rows_rejected += 1
                continue
            except (TransientError, DBAPIError):
                raise
            except Exception as exc:  # a bug or bad data in one row: record it and carry on
                _error(s, run_id, "write", type(exc).__name__, str(exc), row)
                run.rows_rejected += 1
                continue
            setattr(run, f"rows_{status}", getattr(run, f"rows_{status}") + 1)
        run.last_committed_row = batch[-1].number
        s.commit()


def _validate(s: Session, run_id: int, job: Job, row: InputRow, tally: _Tally) -> bool:
    """Record rule failures; return True if the row must be rejected."""
    reject = False
    for rule in job.rules:
        tally.checked[rule.name] = tally.checked.get(rule.name, 0) + 1
        try:
            problem = rule.check(row.data)
        except Exception as exc:  # a rule that crashes counts as a failure
            problem = f"rule raised {type(exc).__name__}: {exc}"
        if problem:
            tally.failed[rule.name] = tally.failed.get(rule.name, 0) + 1
            if rule.severity == "error":
                reject = True
                _error(s, run_id, "validate", rule.name, problem, row, rule.field)
    return reject


def _save_tally(s: Session, run_id: int, job: Job, tally: _Tally) -> None:
    severities = {r.name: r.severity for r in job.rules}
    for rule, checked in tally.checked.items():
        vr = s.scalar(select(ValidationResult).where(ValidationResult.run_id == run_id, ValidationResult.rule == rule))
        if vr is None:
            vr = ValidationResult(run_id=run_id, rule=rule, severity=severities[rule], rows_checked=0, rows_failed=0)
            s.add(vr)
        vr.rows_checked, vr.rows_failed = checked, tally.failed.get(rule, 0)


def _save_cursor(s: Session, job: Job, run: IngestionRun, cursor: dict[str, Any]) -> None:
    cur = s.scalar(select(IngestionCursor).where(IngestionCursor.job_name == job.name,
                                                 IngestionCursor.source_id == run.source_id))
    if cur is None:
        cur = IngestionCursor(job_name=job.name, source_id=run.source_id, cursor=cursor)
        s.add(cur)
    cur.cursor, cur.last_run_id = cursor, run.id
