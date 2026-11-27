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
import os
import signal
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db import SessionLocal
from app.models import Evidence, Run, RunStatus, utcnow
from app.services import audit, integrity, resources
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
    on_start: Callable[[int, list[str]], None] | None = None,
    should_stop: Callable[[], str | None] | None = None,
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
        on_start=on_start,
        should_stop=should_stop,
    )


def run_post_hooks(
    session: Session, run_id: int, on_progress: Callable[[], None] | None = None
) -> None:
    """Run post-run hooks for a succeeded run. Hook failures are recorded on the run by
    app.tools.hooks and never change its status; anything unexpected is only logged."""
    from app.tools import hooks

    try:
        hooks.run_hooks(session, run_id, on_progress=on_progress)
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


INTERRUPTED_HOOKS_ERROR = "interrupted: the app stopped while hooks were running; re-run hooks"


def _kill_orphan(pid: int | None, run_dir: Path) -> bool:
    """Stop the tool process group left behind by a crashed app. Only acts when the process
    still runs in this run's directory (guards against pid reuse); Linux only (uses /proc).
    Returns True if a signal was sent."""
    killpg = getattr(os, "killpg", None)
    if not pid or killpg is None:
        return False
    try:
        cwd = Path(os.readlink(f"/proc/{pid}/cwd"))
    except OSError:
        return False  # gone, not ours to inspect, or no /proc
    try:
        if cwd.resolve() != run_dir.resolve():
            return False
        killpg(pid, signal.SIGKILL)  # executor starts the tool in its own session: pgid == pid
    except OSError:
        return False
    logger.warning("killed orphaned tool process group %s (%s)", pid, run_dir)
    return True


def _salvage_output(s: Session, run: Run, settings: Settings) -> dict[str, Any]:
    """Keep whatever an interrupted run wrote: record and hash its stdout/stderr and register
    files in its output dir. Never raises."""
    from app.services import artifacts
    from app.tools.executor import OUTPUT_DIR_NAME, STDERR_NAME, STDOUT_NAME, sha256_file

    info: dict[str, Any] = {}
    run_dir = settings.runs_dir / str(run.id)
    try:
        stdout = run_dir / STDOUT_NAME
        if stdout.is_file():
            run.stdout_path = _rel_to_data_dir(stdout, settings)
            run.stdout_sha256 = sha256_file(stdout)
            info["stdout_bytes"] = stdout.stat().st_size
            info["stdout_sha256"] = run.stdout_sha256
        stderr = run_dir / STDERR_NAME
        if stderr.is_file():
            run.stderr_path = _rel_to_data_dir(stderr, settings)
        with s.begin_nested():
            created = artifacts.register_run_outputs(s, run, run_dir / OUTPUT_DIR_NAME)
        info["artifacts"] = len(created)
    except Exception:
        logger.exception("run %s: could not keep partial output", run.id)
    return info


def recover_interrupted_runs(session: Session) -> int:
    """At startup, finish off what a previous process left behind:

    - RUNNING runs -> INTERRUPTED: stop the orphaned tool process if it still runs, keep and
      hash its partial output, and say what it was doing when the app stopped.
    - SUCCEEDED runs stuck in "post-processing" (hooks were running) get a hook error entry so
      the UI offers "re-run hooks".

    QUEUED runs are left alone: the worker starts them as usual. Returns the number of runs
    marked interrupted.
    """
    settings = get_settings()
    count = 0
    stale = session.scalars(select(Run).where(Run.status == RunStatus.RUNNING)).all()
    for run in stale:
        phase = run.phase or "starting"
        killed = _kill_orphan(run.pid, settings.runs_dir / str(run.id))
        salvaged = _salvage_output(session, run, settings)
        run.status = RunStatus.INTERRUPTED
        run.error = f"interrupted: the app stopped while this run was {phase}"
        run.finished_at = utcnow()
        run.phase = None
        run.pid = None
        audit.record(
            session,
            "run.interrupted",
            object_type="run",
            object_id=run.id,
            evidence_id=run.evidence_id,
            summary=f"Run {run.id} was interrupted while {phase} (found at startup)",
            details={"phase": phase, "orphan_process_killed": killed, **salvaged},
        )
        count += 1

    hooks_stuck = session.scalars(
        select(Run).where(Run.status == RunStatus.SUCCEEDED, Run.phase.is_not(None))
    ).all()
    for run in hooks_stuck:
        run.hook_results = [
            *(run.hook_results or []),
            {"hook": "(post-processing)", "status": "error", "error": INTERRUPTED_HOOKS_ERROR},
        ]
        run.phase = None
        audit.record(
            session,
            "run.hooks_interrupted",
            object_type="run",
            object_id=run.id,
            evidence_id=run.evidence_id,
            summary=f"Post-run hooks of run {run.id} were interrupted (found at startup)",
        )
    session.commit()
    if count:
        logger.warning("marked %d run(s) left running by a previous process as interrupted", count)
    return count


def _timeout_for(runner: ToolRunner, plugin: str, settings: Settings) -> int:
    """The catalog entry's timeout_seconds, else FT_RUN_TIMEOUT_SECONDS."""
    try:
        spec = runner.get_plugin(plugin)
    except Exception:
        return settings.run_timeout_seconds
    return spec.timeout_seconds or settings.run_timeout_seconds


class Worker:
    def __init__(self, poll_interval: float = 1.0) -> None:
        self.poll_interval = poll_interval
        self._lock = threading.Lock()
        self._cancel_events: dict[int, threading.Event] = {}  # active run id -> cancel event
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._run_threads: dict[int, threading.Thread] = {}
        # Last sign of progress per active run (time.monotonic()), for the stall watchdog. Kept
        # in memory: a DB heartbeat cannot be written while the run's own ingest transaction
        # holds SQLite's write lock.
        self._progress: dict[int, float] = {}
        self._last_watchdog = 0.0
        self._max_workers = 1
        self._last_disk_warning = 0.0
        # Why queued runs are currently waiting (shown on the health page), or None.
        self.disk_problem: str | None = None

    # -- lifecycle ---------------------------------------------------------------------------

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        self._max_workers = max(1, get_settings().max_concurrent_runs)
        self._stop.clear()
        self._thread = threading.Thread(target=self._poll_loop, name="run-poller", daemon=True)
        self._thread.start()
        logger.info("worker started (max_concurrent_runs=%d)", self._max_workers)

    def stop(self, timeout: float = 30.0) -> None:
        """Stop polling, cancel active runs and wait for them to wind down."""
        self._stop.set()
        with self._lock:
            for ev in self._cancel_events.values():
                ev.set()
        deadline = time.monotonic() + timeout
        if self._thread is not None:
            self._thread.join(timeout)
            self._thread = None
        with self._lock:
            threads = list(self._run_threads.values())
        for t in threads:  # a stalled (abandoned) run thread may never finish: don't wait forever
            t.join(max(0.0, deadline - time.monotonic()))
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
                self._watchdog()
            except Exception:
                logger.exception("stall watchdog failed")
            try:
                self._claim_and_submit()
            except Exception:
                logger.exception("worker poll iteration failed")
            self._stop.wait(self.poll_interval)

    # -- stall watchdog ----------------------------------------------------------------------

    def touch(self, run_id: int) -> None:
        """Record progress for an active run (resets its stall timer)."""
        with self._lock:
            if run_id in self._cancel_events:
                self._progress[run_id] = time.monotonic()

    def _watchdog(self, now: float | None = None) -> list[int]:
        """Give up on active runs without progress for FT_RUN_STALL_SECONDS: stop their tool
        process, record them as interrupted (or their hooks as failed) and free their slot so
        queued runs can start. Returns the run ids given up on."""
        stall = get_settings().run_stall_seconds
        now = time.monotonic() if now is None else now
        if not stall or now - self._last_watchdog < min(5.0, stall / 4):
            return []
        self._last_watchdog = now
        with self._lock:
            stalled = [rid for rid, t in self._progress.items() if now - t > stall]
        return [rid for rid in stalled if self._abandon(rid, stall)]

    def _abandon(self, run_id: int, stall: int) -> bool:
        settings = get_settings()
        with self._lock:
            event = self._cancel_events.get(run_id)
        if event is not None:
            event.set()  # in case the thread is alive enough to notice
        try:
            with SessionLocal() as s, audit.audit_context(origin="worker", request_id=None):
                run = s.get(Run, run_id)
                if run is None:
                    return False
                minutes = f"{stall // 60} min" if stall >= 60 else f"{stall} s"
                if run.status == RunStatus.RUNNING:
                    phase = run.phase or "starting"
                    killed = _kill_orphan(run.pid, settings.runs_dir / str(run.id))
                    salvaged = _salvage_output(s, run, settings)
                    run.status = RunStatus.INTERRUPTED
                    run.error = (
                        f"stalled: no progress for {minutes} while {phase}; stopped by the "
                        "watchdog (FT_RUN_STALL_SECONDS)"
                    )
                    run.finished_at = utcnow()
                    run.phase = None
                    run.pid = None
                    audit.record(
                        s,
                        "run.stalled",
                        object_type="run",
                        object_id=run.id,
                        evidence_id=run.evidence_id,
                        summary=f"Run {run.id} stalled while {phase}; marked interrupted",
                        details={
                            "phase": phase,
                            "stall_seconds": stall,
                            "orphan_process_killed": killed,
                            **salvaged,
                        },
                    )
                elif run.status == RunStatus.SUCCEEDED and run.phase:
                    run.hook_results = [
                        *(run.hook_results or []),
                        {
                            "hook": "(post-processing)",
                            "status": "error",
                            "error": f"stalled: a hook made no progress for {minutes}; stopped "
                            "waiting for it (re-run hooks to try again)",
                        },
                    ]
                    run.phase = None
                    audit.record(
                        s,
                        "run.hooks_stalled",
                        object_type="run",
                        object_id=run.id,
                        evidence_id=run.evidence_id,
                        summary=f"Post-run hooks of run {run.id} stalled",
                        details={"stall_seconds": stall},
                    )
                s.commit()
        except Exception:
            # e.g. the stuck thread holds SQLite's write lock: try again on the next round.
            logger.exception("could not record stalled run %s; will retry", run_id)
            return False
        logger.error("run %s stalled (no progress for %ss); its slot was freed", run_id, stall)
        with self._lock:
            self._cancel_events.pop(run_id, None)
            self._progress.pop(run_id, None)
        return True

    def _disk_blocked(self) -> bool:
        """True (queued runs wait) while there is not enough disk space; logged once a minute."""
        try:
            problem = resources.disk_status().problem
        except OSError:
            return False
        if problem and time.monotonic() - self._last_disk_warning > 60:
            self._last_disk_warning = time.monotonic()
            logger.warning("not enough disk space, runs will not start: %s", problem)
        self.disk_problem = problem
        return problem is not None

    def _claim_and_submit(self) -> None:
        while not self._stop.is_set():
            with self._lock:
                if len(self._cancel_events) >= self._max_workers:
                    return
            if self._disk_blocked():
                return
            run_id = self._claim_next()
            if run_id is None:
                return
            # One thread per run (not a fixed pool) so a stalled, abandoned run thread does not
            # keep holding a slot.
            t = threading.Thread(
                target=self._run_task, args=(run_id,), name=f"run-{run_id}", daemon=True
            )
            with self._lock:
                self._run_threads[run_id] = t
            t.start()

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
                    self._progress[run_id] = time.monotonic()
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
                self._progress.pop(run_id, None)
                self._run_threads.pop(run_id, None)

    @staticmethod
    def _finish(
        s: Session, run_id: int, status: RunStatus, error: str | None, **values: Any
    ) -> bool:
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
        values.setdefault("pid", None)
        res = s.execute(
            update(Run)
            .where(Run.id == run_id, Run.status == RunStatus.RUNNING)
            .values(status=status, error=error, finished_at=utcnow(), **values)
        )
        if res.rowcount != 1:  # type: ignore[attr-defined]
            # Already finished elsewhere (e.g. the watchdog marked it stalled): keep that.
            s.rollback()
            logger.warning("run %s was already finished; not recording %s", run_id, status.value)
            return False
        s.commit()
        return True

    def _heartbeat_callback(self, run_id: int) -> Callable[[], None]:
        def _beat() -> None:
            self.touch(run_id)
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
            if self._stop.is_set():
                self._finish(
                    s,
                    run_id,
                    RunStatus.INTERRUPTED,
                    "interrupted: the app stopped while this run was hashing",
                )
            else:
                self._finish(s, run_id, RunStatus.CANCELLED, "cancelled (while hashing evidence)")
            return
        except Exception as exc:  # hashing failed (unreadable file, changed while hashing...)
            self._finish(s, run_id, RunStatus.FAILED, f"integrity check failed: {exc}")
            return
        set_phase("running")

        run_dir = settings.runs_dir / str(run_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        logger.info("run %s: executing %s on %s", run_id, run.plugin, evidence.rel_path)
        timeout = _timeout_for(runner, run.plugin, settings)

        def record_start(pid: int, argv: list[str]) -> None:
            run.pid = pid
            run.argv = argv
            s.commit()

        result = execute(
            runner,
            evidence_path,
            request,
            run_dir,
            timeout,
            cancel_event,
            on_heartbeat=self._heartbeat_callback(run_id),
            max_output_bytes=settings.max_artifact_bytes,
            on_start=record_start,
            should_stop=lambda: resources.hard_floor_problem(settings),
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
            and not result.stop_reason
        )
        if not succeeded:
            self._register_artifacts(s, run, run_dir)

        if result.cancelled or cancel_event.is_set():
            tail = _stderr_tail(result.stderr_path)
            if self._stop.is_set():
                msg = "interrupted: the app stopped while this run was running"
                self._finish(s, run_id, RunStatus.INTERRUPTED, _with_tail(msg, tail))
            else:
                self._finish(s, run_id, RunStatus.CANCELLED, _with_tail("cancelled", tail))
            return
        if result.stop_reason:
            self._finish(
                s,
                run_id,
                RunStatus.FAILED,
                _with_tail(result.stop_reason, _stderr_tail(result.stderr_path)),
            )
            return
        if result.timed_out:
            msg = f"timed out after {timeout}s"
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
        if not self._finish(
            s, run_id, RunStatus.SUCCEEDED, None, row_count=count, phase="post-processing"
        ):
            return
        logger.info("run %s: succeeded with %d rows", run_id, count)
        self.touch(run_id)
        run_post_hooks(s, run_id, on_progress=lambda: self.touch(run_id))
        s.execute(
            update(Run).where(Run.id == run_id, Run.phase == "post-processing").values(phase=None)
        )
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

    def _store_rows(self, s: Session, run_id: int, runner: ToolRunner, stdout_path: Path) -> int:
        """Insert parsed rows in batches within the current (uncommitted) transaction, record
        the run's columns and, with FT_SEARCH_INDEX, add them to the full-text index."""
        from app.services import results

        def rows_with_progress() -> Any:
            last = time.monotonic()
            for row in runner.parse_output(stdout_path):
                yield row
                if time.monotonic() - last >= 5:
                    last = time.monotonic()
                    self.touch(run_id)  # in memory only: this transaction holds the write lock

        return results.store_rows(
            s,
            run_id,
            rows_with_progress(),
            search_index=get_settings().search_index,
            batch_size=ROW_BATCH_SIZE,
        )


_worker: Worker | None = None
_worker_lock = threading.Lock()


def get_worker() -> Worker:
    """Process-wide Worker singleton."""
    global _worker
    with _worker_lock:
        if _worker is None:
            _worker = Worker()
        return _worker
