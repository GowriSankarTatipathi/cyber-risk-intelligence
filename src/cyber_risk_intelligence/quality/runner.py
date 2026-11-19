"""Run the data-quality checks and record the results."""

from __future__ import annotations

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, sessionmaker

from ..evidence.store import ObjectStore, sha256_hex
from ..models import EvidenceObject, ValidationFinding, ValidationResult, ValidationRun
from .checks import CHECKS, EVIDENCE_BYTES_CHECK, Check


def run_validation(
    session_factory: sessionmaker[Session],
    *,
    store: ObjectStore | None = None,
    checks: tuple[Check, ...] = CHECKS,
    max_findings_per_check: int = 1000,
) -> ValidationRun:
    """Run every check, store results and findings, and return the finished run.

    With ``store``, also re-reads every stored evidence object and verifies its checksum.
    The status is ``failed`` if any error-level check found something, ``warnings``
    if only warnings did, ``passed`` otherwise, and ``error`` if a check itself crashed.
    """
    with session_factory() as s:
        run = ValidationRun(scope="schema checks" + (" + evidence bytes" if store else ""))
        s.add(run)
        s.commit()
        run_id = run.id

    crashed = False
    totals = {"error": 0, "warning": 0, "info": 0}
    to_run = list(checks) + ([EVIDENCE_BYTES_CHECK] if store else [])
    for check in to_run:
        with session_factory() as s:
            try:
                with s.begin_nested():
                    checked = s.execute(text(check.checked_sql)).scalar_one()
                    if check is EVIDENCE_BYTES_CHECK:
                        failing = _evidence_bytes(s, store)
                    else:
                        failing = s.execute(text(check.failing_sql)).all()
            except Exception as exc:  # record the broken check and keep going
                crashed = True
                s.add(ValidationFinding(validation_run_id=run_id, check_name=check.name, severity="error",
                                        table_name="(check)", record_id=None,
                                        message=f"check could not run: {type(exc).__name__}: {exc}"[:2000]))
                s.commit()
                continue
            # A record can match a check more than once (e.g. overlapping two others); count it once.
            affected = {(t, rid) for t, rid, _ in failing} if failing else set()
            failed = len(affected) if any(rid is not None for _, rid in affected) else len(failing)
            s.add(ValidationResult(validation_run_id=run_id, rule=check.name, severity=check.severity,
                                   rows_checked=max(checked, failed), rows_failed=failed,
                                   description=check.description))
            for table_name, record_id, message in failing[:max_findings_per_check]:
                s.add(ValidationFinding(validation_run_id=run_id, check_name=check.name, severity=check.severity,
                                        table_name=table_name, record_id=record_id, message=message))
            if failed:
                totals[check.severity] += 1
            s.commit()

    with session_factory() as s:
        run = s.get(ValidationRun, run_id)
        run.checks_run = len(to_run)
        run.errors, run.warnings = totals["error"], totals["warning"]
        run.status = "error" if crashed else "failed" if totals["error"] else "warnings" if totals["warning"] else "passed"
        run.finished_at = func.now()
        s.commit()
        s.refresh(run)
        s.expunge(run)
        return run


def _evidence_bytes(s: Session, store: ObjectStore) -> list[tuple[str, int, str]]:
    bad = []
    for obj in s.scalars(select(EvidenceObject).order_by(EvidenceObject.id)):
        if obj.storage_backend != store.backend or obj.bucket != store.bucket:
            bad.append(("evidence_objects", obj.id, f"stored in {obj.storage_backend}/{obj.bucket}, not in the store checked"))
            continue
        try:
            content = store.get(obj.object_key)
        except Exception as exc:
            bad.append(("evidence_objects", obj.id, f"cannot be read: {type(exc).__name__}"))
            continue
        if len(content) != obj.size_bytes or sha256_hex(content) != obj.sha256:
            bad.append(("evidence_objects", obj.id, "bytes no longer match the recorded SHA-256"))
    return bad
