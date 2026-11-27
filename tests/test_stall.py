"""Stall watchdog: a run (or its hooks) without progress is given up on and its slot freed."""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.jobs import worker as worker_mod
from app.jobs.worker import Worker
from app.models import AuditEvent, Evidence, Run, RunStatus
from app.services import evidence as evidence_service
from app.services import runs as runs_service
from app.tools.base import ToolRequest
from tests.test_backend_fakes import FakeRunner, install_fake_runner, make_fake_execute


@pytest.fixture
def fake_runner(monkeypatch: pytest.MonkeyPatch) -> FakeRunner:
    return install_fake_runner(monkeypatch)


@pytest.fixture
def evidence(session: Session) -> Evidence:
    (ev,) = evidence_service.scan_evidence(session)
    return ev


def _stall(monkeypatch: pytest.MonkeyPatch, seconds: str) -> None:
    monkeypatch.setenv("FT_RUN_STALL_SECONDS", seconds)
    get_settings.cache_clear()


def _wait(session: Session, run_id: int, statuses: set[RunStatus], timeout: float = 10) -> Run:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        session.expire_all()
        run = session.get(Run, run_id)
        if run.status in statuses:
            return run
        time.sleep(0.02)
    raise AssertionError(f"run {run_id} stuck in {run.status}")


def test_stalled_run_is_interrupted_and_slot_freed(
    session: Session, evidence: Evidence, fake_runner: FakeRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stall(monkeypatch, "1")
    release = threading.Event()
    normal = make_fake_execute([{"PID": 4}])
    hung_ids: list[int] = []

    def fake_execute(runner, evidence_path, request, run_dir, *args, **kwargs):
        if not hung_ids:  # the first run hangs and ignores cancellation (no heartbeats)
            hung_ids.append(int(Path(run_dir).name))
            (Path(run_dir) / "stdout.jsonl").write_text('{"PID": 1}\n')
            release.wait(30)
        return normal(runner, evidence_path, request, run_dir, *args, **kwargs)

    monkeypatch.setattr(worker_mod, "execute", fake_execute)
    first = runs_service.create_run(session, evidence.id, ToolRequest("windows.info.Info"))
    second = runs_service.create_run(session, evidence.id, ToolRequest("windows.pstree.PsTree"))
    w = Worker(poll_interval=0.05)
    w.start()
    try:
        stalled = _wait(session, first.id, {RunStatus.INTERRUPTED})
        assert stalled.error.startswith("stalled: no progress for 1 s while running")
        assert stalled.stdout_sha256  # partial output kept
        # max_concurrent_runs=1: the second run only starts because the slot was freed.
        assert _wait(session, second.id, {RunStatus.SUCCEEDED}).row_count == 1
        (event,) = session.scalars(select(AuditEvent).where(AuditEvent.action == "run.stalled"))
        assert event.object_id == first.id and event.details["stall_seconds"] == 1
    finally:
        release.set()
        w.stop(timeout=5)
    # The hung thread finishing later must not overwrite the interrupted status.
    time.sleep(0.2)
    session.expire_all()
    assert session.get(Run, first.id).status == RunStatus.INTERRUPTED
    assert session.get(Run, first.id).row_count == 0


def test_progress_keeps_a_run_alive(monkeypatch: pytest.MonkeyPatch) -> None:
    _stall(monkeypatch, "10")
    w = Worker()
    w._cancel_events[1] = threading.Event()
    w._progress[1] = time.monotonic() - 9
    assert w._watchdog() == []
    w.touch(1)
    w._last_watchdog = 0
    assert w._watchdog(now=time.monotonic() + 5) == []


def test_watchdog_off(monkeypatch: pytest.MonkeyPatch) -> None:
    _stall(monkeypatch, "0")
    w = Worker()
    w._cancel_events[1] = threading.Event()
    w._progress[1] = 0.0
    assert w._watchdog() == []


def test_stalled_hooks_are_recorded(
    session: Session, evidence: Evidence, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stall(monkeypatch, "10")
    run = Run(
        evidence_id=evidence.id,
        plugin="windows.info.Info",
        status=RunStatus.SUCCEEDED,
        phase="post-processing",
    )
    session.add(run)
    session.commit()
    w = Worker()
    event = threading.Event()
    w._cancel_events[run.id] = event
    w._progress[run.id] = time.monotonic() - 100
    assert w._watchdog() == [run.id]
    assert event.is_set() and run.id not in w.active_run_ids()
    session.expire_all()
    run = session.get(Run, run.id)
    assert run.status == RunStatus.SUCCEEDED and run.phase is None
    assert "a hook made no progress" in run.hook_results[-1]["error"]


def test_hooks_report_progress(session: Session, evidence: Evidence) -> None:
    from app.tools import hooks

    run = Run(evidence_id=evidence.id, plugin="windows.pslist.PsList", status=RunStatus.SUCCEEDED)
    session.add(run)
    session.commit()
    calls: list[int] = []
    hooks.run_hooks(session, run.id, on_progress=lambda: calls.append(1))
    assert len(calls) == len(hooks.hooks_for(run.tool, run.plugin))
