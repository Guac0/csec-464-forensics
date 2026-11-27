"""Deleting runs to free disk space, leaving a tombstone.

What is deleted: the run's result rows (and their search-index entries), its raw tool output
(stdout/stderr) and the files it dumped (``<data_dir>/runs/<id>/``).

What stays: the run record (plugin, args, exact argv, hashes of the raw output and of every
dumped file, findings, status), marked with ``deleted_at`` and the reason, plus its whole audit
history and a ``run.delete`` audit event. Reports and exports list the run as deleted; AI
citations to its rows show as citing a deleted run.

The database change (and its audit event) is committed before any file is removed: a crash in
between leaves orphaned files, never files deleted without a record.
"""

from __future__ import annotations

import logging
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import delete, func, select, text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import AIMessage, DerivedArtifact, Note, ResultRow, Run, RunStatus, utcnow
from app.services import audit
from app.services.resources import fmt_bytes
from app.services.results import FTS_TABLE

logger = logging.getLogger(__name__)

# Statuses offered by bulk clean-up ("delete all failed / interrupted / cancelled runs").
CLEANUP_STATUSES = (RunStatus.FAILED, RunStatus.INTERRUPTED, RunStatus.CANCELLED)
ACTIVE_STATUSES = (RunStatus.QUEUED, RunStatus.RUNNING)
MAX_REASON = 2000


@dataclass
class DeletePreview:
    run_id: int
    rows: int
    bytes_on_disk: int
    dumped_files: int
    ai_answers_citing: int
    notes_citing: int
    problem: str | None  # why it cannot be deleted, or None


@dataclass
class DeleteResult:
    run_id: int
    rows_deleted: int
    bytes_freed: int
    files_removed: bool


def run_dir(run_id: int) -> Path:
    return get_settings().runs_dir / str(run_id)


def dir_bytes(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            full = os.path.join(root, name)
            try:
                if not os.path.islink(full):
                    total += os.lstat(full).st_size
            except OSError:
                continue
    return total


def _problem(run: Run) -> str | None:
    if run.deleted_at is not None:
        return "already deleted"
    if run.status in ACTIVE_STATUSES:
        return f"run is {run.status.value}; cancel it first"
    return None


def _citing(session: Session, run: Run) -> tuple[int, int]:
    prefix = f"R{run.id}:"
    answers = 0
    for (citations,) in session.execute(
        select(AIMessage.citations).where(AIMessage.evidence_id == run.evidence_id)
    ):
        if any(str((c or {}).get("key", "")).startswith(prefix) for c in citations or []):
            answers += 1
    notes = session.scalar(select(func.count(Note.id)).where(Note.body.contains(f"[{prefix}"))) or 0
    return answers, notes


def preview(session: Session, run_id: int) -> DeletePreview:
    run = session.get(Run, run_id)
    if run is None:
        raise LookupError(f"run {run_id} not found")
    rows = session.scalar(select(func.count(ResultRow.id)).where(ResultRow.run_id == run_id)) or 0
    files = (
        session.scalar(
            select(func.count(DerivedArtifact.id)).where(DerivedArtifact.run_id == run_id)
        )
        or 0
    )
    answers, notes = _citing(session, run)
    return DeletePreview(
        run_id=run_id,
        rows=rows,
        bytes_on_disk=dir_bytes(run_dir(run_id)),
        dumped_files=files if run.deleted_at is None else 0,
        ai_answers_citing=answers,
        notes_citing=notes,
        problem=_problem(run),
    )


def _clean_reason(reason: str) -> str:
    reason = (reason or "").strip()
    if not reason:
        raise ValueError("a reason is required to delete a run")
    return reason[:MAX_REASON]


def _mark_deleted(
    session: Session, run: Run, reason: str, *, bulk: bool = False
) -> tuple[int, int]:
    """Delete rows and set the tombstone (no commit). Returns (rows deleted, bytes on disk)."""
    if run.search_indexed:
        fts_delete = (
            f"DELETE FROM {FTS_TABLE} WHERE rowid IN (SELECT id FROM result_rows WHERE run_id = :r)"  # noqa: E501, S608 - constant table name
        )
        session.execute(text(fts_delete), {"r": run.id})
    rows = session.scalar(select(func.count(ResultRow.id)).where(ResultRow.run_id == run.id)) or 0
    session.execute(delete(ResultRow).where(ResultRow.run_id == run.id))
    size = dir_bytes(run_dir(run.id))
    run.deleted_at = utcnow()
    run.delete_reason = reason
    run.search_indexed = False
    audit.record(
        session,
        "run.delete",
        object_type="run",
        object_id=run.id,
        evidence_id=run.evidence_id,
        summary=f"Deleted the data of run {run.id} ({run.plugin}): {rows} rows, {fmt_bytes(size)}",
        details={
            "reason": reason,
            "bulk": bulk,
            "status": run.status.value,
            "rows_deleted": rows,
            "bytes_on_disk": size,
            "stdout_sha256": run.stdout_sha256,
            "dumped_files": [
                {"filename": a.filename, "sha256": a.sha256}
                for a in session.scalars(
                    select(DerivedArtifact).where(DerivedArtifact.run_id == run.id)
                )
            ],
        },
    )
    return rows, size


def _remove_files(run_id: int) -> bool:
    path = run_dir(run_id)
    if not path.exists():
        return True
    try:
        shutil.rmtree(path)
    except OSError:
        logger.exception(
            "run %s: could not remove %s (record is already marked deleted)", run_id, path
        )
        return False
    return True


def delete_run(session: Session, run_id: int, reason: str) -> DeleteResult:
    """Delete a finished run's data, keeping a tombstone. Raises LookupError / ValueError."""
    reason = _clean_reason(reason)
    run = session.get(Run, run_id)
    if run is None:
        raise LookupError(f"run {run_id} not found")
    problem = _problem(run)
    if problem:
        raise ValueError(f"cannot delete run {run_id}: {problem}")
    rows, size = _mark_deleted(session, run, reason)
    session.commit()
    removed = _remove_files(run_id)
    from app.services import resources

    resources.data_dir_size(fresh=True)
    return DeleteResult(run_id, rows, size if removed else 0, removed)


def cleanup_candidates(
    session: Session, evidence_id: int, statuses: tuple[RunStatus, ...] = CLEANUP_STATUSES
) -> list[Run]:
    return list(
        session.scalars(
            select(Run)
            .where(
                Run.evidence_id == evidence_id,
                Run.status.in_(statuses),
                Run.deleted_at.is_(None),
            )
            .order_by(Run.id)
        )
    )


def delete_runs(
    session: Session,
    evidence_id: int,
    reason: str,
    statuses: tuple[RunStatus, ...] = CLEANUP_STATUSES,
) -> list[DeleteResult]:
    """Bulk clean-up: delete every not-yet-deleted run of ``evidence_id`` with one of
    ``statuses`` (only failed/interrupted/cancelled are allowed), one reason for all."""
    reason = _clean_reason(reason)
    if not statuses or any(s not in CLEANUP_STATUSES for s in statuses):
        raise ValueError("bulk clean-up only deletes failed, interrupted or cancelled runs")
    runs = cleanup_candidates(session, evidence_id, statuses)
    marked = [(run.id, *_mark_deleted(session, run, reason, bulk=True)) for run in runs]
    session.commit()
    results = []
    for run_id, rows, size in marked:
        removed = _remove_files(run_id)
        results.append(DeleteResult(run_id, rows, size if removed else 0, removed))
    from app.services import resources

    resources.data_dir_size(fresh=True)
    return results


def biggest_runs(session: Session, limit: int = 10) -> list[tuple[Run, int]]:
    """(run, bytes on disk) for the runs using the most space in runs_dir, biggest first.
    Includes leftovers of deleted runs whose files could not be removed."""
    runs_dir = get_settings().runs_dir
    sizes: list[tuple[int, int]] = []
    if runs_dir.is_dir():
        for entry in os.scandir(runs_dir):
            if entry.is_dir(follow_symlinks=False) and entry.name.isdigit():
                sizes.append((int(entry.name), dir_bytes(Path(entry.path))))
    sizes.sort(key=lambda t: t[1], reverse=True)
    out = []
    for run_id, size in sizes[:limit]:
        run = session.get(Run, run_id)
        if run is not None and size > 0:
            out.append((run, size))
    return out
