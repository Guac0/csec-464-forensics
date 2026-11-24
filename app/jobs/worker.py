"""In-process job worker: polls QUEUED runs from SQLite and executes them in a thread pool.

Design notes:
- A single daemon poll thread claims runs atomically (UPDATE ... WHERE status='queued') and only
  claims as many as there are free pool slots, so runs waiting their turn stay QUEUED (and are
  therefore cancellable without involving the worker).
- Each run gets its own DB session and a ``threading.Event`` used for cancellation. The event is
  registered *before* the claim commits, so a run that is RUNNING in the DB and owned by this
  worker is always cancellable.
- Exceptions never escape the poll loop or a run task; they are logged and recorded on the run.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from sqlalchemy import insert, select, update
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db import SessionLocal
from app.models import Evidence, ResultRow, Run, RunStatus, utcnow
from app.services import audit, integrity
from app.services import runs as runs_service
from app.services.evidence import resolve_evidence_path
from app.tools.base import ArgValidationError, ExecutionResult, ToolRequest, ToolRunner

logger = logging.getLogger(__name__)

ROW_BATCH_SIZE = 1000
STDERR_TAIL_CHARS = 2000


def execute(
    runner: ToolRunner,
    evidence_path: Path,
    request: ToolRequest,
    run_dir: Path,
    timeout: float,
    cancel_event: threading.Event,
    on_heartbeat: Callable[[], None] | None = None,
    max_output_bytes: int | None = None,
) -> ExecutionResult:
    """Indirection over app.tools.executor.execute (lazy import; monkeypatched in tests)."""
    from app.tools import executor

    return executor.execute(
        runner,
        evidence_path,
        request,
        run_dir,
        timeout,
        cancel_event,
        on_heartbeat=on_heartbeat,
        max_output_bytes=max_output_bytes,
    )


def run_post_hooks(session: Session, run_id: int) -> None:
    """Run post-run hooks for a succeeded run. Hook failures are recorded on the run by
    app.tools.hooks and never change its status; anything unexpected is only logged."""
    from app.tools import hooks

    try:
        hooks.run_hooks(session, run_id)
    except Exception:
        session.rollback()
        logger.exception("post-run hooks could not run for run %s", run_id)


def _rel_to_data_dir(path: Path, settings: Settings) -> str:
    """Path relative to data_dir (as stored on Run); falls back to the absolute path."""
    try:
        return path.resolve().relative_to(settings.data_dir.resolve()).as_posix()
    except ValueError:
        return str(path)


def _stderr_tail(path: Path, max_chars: int = STDERR_TAIL_CHARS) -> str:
    try:
        with path.open("rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - max_chars * 4))  # utf-8 is at most 4 bytes/char
            return f.read().decode("utf-8", errors="replace")[-max_chars:].strip()
    except OSError:
        return ""


def _with_tail(message: str, tail: str) -> str:
    return f"{message}\n--- stderr (tail) ---\n{tail}" if tail else message


def recover_stale_runs(session: Session) -> int:
    """Mark runs left RUNNING by a previous process as FAILED. Returns the number updated."""
    for run in session.scalars(select(Run).where(Run.status == RunStatus.RUNNING)):
        audit.record(
            session,
            "run.interrupted",
            object_type="run",
            object_id=run.id,
            evidence_id=run.evidence_id,
            summary=f"Run {run.id} was still running at restart; marked failed",
        )
    res = session.execute(
        update(Run)
        .where(Run.status == RunStatus.RUNNING)
        .values(status=RunStatus.FAILED, error="interrupted by restart", finished_at=utcnow())
    )
    session.commit()
    count = res.rowcount or 0  # type: ignore[attr-defined]
    if count:
        logger.warning("marked %d stale running run(s) as failed", count)
    return count


class Worker:
    def __init__(self, poll_interval: float = 1.0) -> None:
        self.poll_interval = poll_interval
        self._lock = threading.Lock()
        self._cancel_events: dict[int, threading.Event] = {}  # active run id -> cancel event
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._pool: ThreadPoolExecutor | None = None
        self._max_workers = 1

    # -- lifecycle ---------------------------------------------------------------------------

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        self._max_workers = max(1, get_settings().max_concurrent_runs)
        self._stop.clear()
        self._pool = ThreadPoolExecutor(max_workers=self._max_workers, thread_name_prefix="run")
        self._thread = threading.Thread(target=self._poll_loop, name="run-poller", daemon=True)
        self._thread.start()
        logger.info("worker started (max_concurrent_runs=%d)", self._max_workers)

    def stop(self, timeout: float = 30.0) -> None:
        """Stop polling, cancel active runs and wait for them to wind down."""
        self._stop.set()
        with self._lock:
            for ev in self._cancel_events.values():
                ev.set()
        if self._thread is not None:
            self._thread.join(timeout)
            self._thread = None
        if self._pool is not None:
            self._pool.shutdown(wait=True)
            self._pool = None
        logger.info("worker stopped")

    def cancel(self, run_id: int) -> bool:
        """Signal a running run to stop. Returns False if this worker does not own it."""
        with self._lock:
            ev = self._cancel_events.get(run_id)
        if ev is None:
            return False
        ev.set()
        return True

    def active_run_ids(self) -> list[int]:
        with self._lock:
            return list(self._cancel_events)

    # -- polling -----------------------------------------------------------------------------

    def _poll_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._claim_and_submit()
            except Exception:
                logger.exception("worker poll iteration failed")
            self._stop.wait(self.poll_interval)

    def _claim_and_submit(self) -> None:
        while not self._stop.is_set():
            with self._lock:
                if len(self._cancel_events) >= self._max_workers:
                    return
            run_id = self._claim_next()
            if run_id is None:
                return
            assert self._pool is not None
            self._pool.submit(self._run_task, run_id)

    def _claim_next(self) -> int | None:
        """Atomically move the oldest QUEUED run to RUNNING. Returns its id or None."""
        with SessionLocal() as s:
            candidates = s.scalars(
                select(Run.id)
                .where(Run.status == RunStatus.QUEUED)
                .order_by(Run.created_at, Run.id)
                .limit(5)
            ).all()
            for run_id in candidates:
                event = threading.Event()
                with self._lock:
                    self._cancel_events[run_id] = event
                now = utcnow()
                res = s.execute(
                    update(Run)
                    .where(Run.id == run_id, Run.status == RunStatus.QUEUED)
                    .values(status=RunStatus.RUNNING, started_at=now, heartbeat_at=now)
                )
                if res.rowcount == 1:  # type: ignore[attr-defined]
                    run = s.get(Run, run_id)
                    with audit.audit_context(origin="worker", request_id=None):
                        audit.record(
                            s,
                            "run.start",
                            object_type="run",
                            object_id=run_id,
                            evidence_id=run.evidence_id if run else None,
                            summary=f"Started run {run_id}",
                        )
                    s.commit()
                    return run_id
                s.commit()
                # Lost the race (e.g. cancelled meanwhile): unregister and try the next one.
                with self._lock:
                    self._cancel_events.pop(run_id, None)
        return None

    # -- execution ---------------------------------------------------------------------------

    def _run_task(self, run_id: int) -> None:
        with audit.audit_context(origin="worker", request_id=None):
            self._run_task_inner(run_id)

    def _run_task_inner(self, run_id: int) -> None:
        with self._lock:
            cancel_event = self._cancel_events.get(run_id) or threading.Event()
        try:
            with SessionLocal() as s:
                try:
                    self._process(s, run_id, cancel_event)
                except ArgValidationError as exc:
                    # Args were validated at creation; this means the allowlist changed since.
                    s.rollback()
                    self._finish(s, run_id, RunStatus.FAILED, f"invalid request: {exc}")
                except Exception as exc:
                    logger.exception("run %s failed with an internal error", run_id)
                    s.rollback()
                    self._finish(s, run_id, RunStatus.FAILED, f"internal error: {exc}")
        except Exception:
            logger.exception("could not record failure of run %s", run_id)
        finally:
            with self._lock:
                self._cancel_events.pop(run_id, None)

    @staticmethod
    def _finish(
        s: Session, run_id: int, status: RunStatus, error: str | None, **values: Any
    ) -> None:
        run = s.get(Run, run_id)
        audit.record(
            s,
            "run.finish",
            object_type="run",
            object_id=run_id,
            evidence_id=run.evidence_id if run else None,
            summary=f"Run {run_id} {status.value}"
            + (f" ({values['row_count']} rows)" if "row_count" in values else ""),
            details={
                "status": status.value,
                "row_count": values.get("row_count"),
                "returncode": run.returncode if run else None,
                "stdout_sha256": run.stdout_sha256 if run else None,
                "tool_version": run.tool_version if run else None,
                "argv": run.argv if run else None,
                "error": (error or "")[:500] or None,
            },
        )
        values.setdefault("phase", None)
        s.execute(
            update(Run)
            .where(Run.id == run_id)
            .values(status=status, error=error, finished_at=utcnow(), **values)
        )
        s.commit()

    @staticmethod
    def _heartbeat_callback(run_id: int) -> Callable[[], None]:
        def _beat() -> None:
            try:
                with SessionLocal() as hs:
                    hs.execute(update(Run).where(Run.id == run_id).values(heartbeat_at=utcnow()))
                    hs.commit()
            except Exception:
                logger.warning("heartbeat update failed for run %s", run_id, exc_info=True)

        return _beat

    def _process(self, s: Session, run_id: int, cancel_event: threading.Event) -> None:
        settings = get_settings()
        run = s.get(Run, run_id)
        if run is None:
            logger.warning("claimed run %s vanished", run_id)
            return
        evidence = s.get(Evidence, run.evidence_id)
        if evidence is None:
            self._finish(s, run_id, RunStatus.FAILED, "evidence record not found")
            return
        try:
            evidence_path = resolve_evidence_path(evidence)
        except ValueError as exc:
            self._finish(s, run_id, RunStatus.FAILED, str(exc))
            return
        if not evidence_path.is_file():
            self._finish(s, run_id, RunStatus.FAILED, f"evidence file missing: {evidence.rel_path}")
            return

        runner = runs_service.get_runner(run.tool)
        request = ToolRequest(plugin=run.plugin, args=dict(run.args or {}))
        run.started_at = utcnow()
        s.commit()

        # Integrity gate: hash the image if needed, check it is unchanged and matches the
        # expected hashes, and snapshot what the tool runs against (app/services/integrity.py).
        heartbeat = self._heartbeat_callback(run_id)

        def set_phase(name: str) -> None:
            run.phase = name
            s.commit()

        try:
            integrity.prepare_for_run(
                s,
                run,
                evidence,
                evidence_path,
                should_stop=cancel_event.is_set,
                on_progress=lambda _done: heartbeat(),
                set_phase=set_phase,
            )
        except integrity.IntegrityBlocked as exc:
            self._finish(s, run_id, RunStatus.FAILED, f"integrity check failed: {exc}")
            return
        except integrity.HashCancelled:
            reason = "cancelled: worker shutting down" if self._stop.is_set() else "cancelled"
            self._finish(s, run_id, RunStatus.CANCELLED, f"{reason} (while hashing evidence)")
            return
        except Exception as exc:  # hashing failed (unreadable file, changed while hashing...)
            self._finish(s, run_id, RunStatus.FAILED, f"integrity check failed: {exc}")
            return
        set_phase("running")

        run_dir = settings.runs_dir / str(run_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        logger.info("run %s: executing %s on %s", run_id, run.plugin, evidence.rel_path)
        result = execute(
            runner,
            evidence_path,
            request,
            run_dir,
            settings.run_timeout_seconds,
            cancel_event,
            on_heartbeat=self._heartbeat_callback(run_id),
            max_output_bytes=settings.max_artifact_bytes,
        )

        # Persist execution provenance before parsing, so it survives a parse failure.
        run.argv = list(result.argv)
        run.returncode = result.returncode
        run.tool_version = result.tool_version
        run.stdout_path = _rel_to_data_dir(result.stdout_path, settings)
        run.stderr_path = _rel_to_data_dir(result.stderr_path, settings)
        run.stdout_sha256 = result.stdout_sha256
        s.commit()

        # Files the tool wrote (e.g. --dump) are registered whatever the outcome, so partial
        # output is hashed and accounted for. Successful runs register after their rows are
        # stored (below) so files can be linked to the rows that name them.
        succeeded = (
            result.returncode == 0
            and not (result.cancelled or cancel_event.is_set())
            and not result.timed_out
            and not result.output_limit_exceeded
        )
        if not succeeded:
            self._register_artifacts(s, run, run_dir)

        if result.cancelled or cancel_event.is_set():
            reason = "cancelled: worker shutting down" if self._stop.is_set() else "cancelled"
            self._finish(
                s, run_id, RunStatus.CANCELLED, _with_tail(reason, _stderr_tail(result.stderr_path))
            )
            return
        if result.timed_out:
            msg = f"timed out after {settings.run_timeout_seconds}s"
            self._finish(
                s, run_id, RunStatus.FAILED, _with_tail(msg, _stderr_tail(result.stderr_path))
            )
            return
        if result.output_limit_exceeded:
            msg = (
                f"stopped: files written by the tool exceeded the per-run limit of "
                f"{settings.max_artifact_bytes} bytes (FT_MAX_ARTIFACT_BYTES); files written so "
                "far were kept"
            )
            self._finish(
                s, run_id, RunStatus.FAILED, _with_tail(msg, _stderr_tail(result.stderr_path))
            )
            return
        if result.returncode != 0:
            msg = f"tool exited with code {result.returncode}"
            self._finish(
                s, run_id, RunStatus.FAILED, _with_tail(msg, _stderr_tail(result.stderr_path))
            )
            return

        try:
            count = self._store_rows(s, run_id, runner, result.stdout_path)
        except Exception as exc:
            logger.warning("run %s: output parse failed", run_id, exc_info=True)
            s.rollback()  # discard any rows inserted so far
            self._register_artifacts(s, run, run_dir)
            self._finish(s, run_id, RunStatus.FAILED, f"output parse failed: {exc}", row_count=0)
            return
        self._register_artifacts(s, run, run_dir)
        self._finish(s, run_id, RunStatus.SUCCEEDED, None, row_count=count, phase="post-processing")
        logger.info("run %s: succeeded with %d rows", run_id, count)
        run_post_hooks(s, run_id)
        s.execute(update(Run).where(Run.id == run_id).values(phase=None))
        s.commit()

    @staticmethod
    def _register_artifacts(s: Session, run: Run, run_dir: Path) -> None:
        """Hash/record files in the run's output dir. Never fails the run: errors are logged and
        only this step is rolled back (savepoint), keeping e.g. freshly inserted rows."""
        from app.services import artifacts
        from app.tools.executor import OUTPUT_DIR_NAME

        try:
            with s.begin_nested():
                artifacts.register_run_outputs(s, run, run_dir / OUTPUT_DIR_NAME)
        except Exception:
            logger.exception("run %s: registering output files failed", run.id)

    @staticmethod
    def _store_rows(s: Session, run_id: int, runner: ToolRunner, stdout_path: Path) -> int:
        """Insert parsed rows in batches within the current (uncommitted) transaction."""
        batch: list[dict[str, Any]] = []
        count = 0
        for idx, row in enumerate(runner.parse_output(stdout_path)):
            batch.append(
                {
                    "run_id": run_id,
                    "row_idx": idx,
                    "depth": row.depth,
                    "parent_idx": row.parent_idx,
                    "data": row.data,
                }
            )
            count += 1
            if len(batch) >= ROW_BATCH_SIZE:
                s.execute(insert(ResultRow), batch)
                batch = []
        if batch:
            s.execute(insert(ResultRow), batch)
        return count


_worker: Worker | None = None
_worker_lock = threading.Lock()


def get_worker() -> Worker:
    """Process-wide Worker singleton."""
    global _worker
    with _worker_lock:
        if _worker is None:
            _worker = Worker()
        return _worker
