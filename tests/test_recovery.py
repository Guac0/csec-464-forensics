"""Crash recovery: interrupted runs, orphaned tool processes, stuck hooks, re-run, timeouts."""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.jobs import worker as worker_mod
from app.jobs.worker import Worker, _timeout_for, recover_interrupted_runs
from app.models import AuditEvent, DerivedArtifact, Evidence, Run, RunOrigin, RunStatus
from app.services import evidence as evidence_service
from app.services import runs as runs_service
from app.tools.base import PluginSpec, ToolRequest
from tests.test_backend_fakes import FakeRunner, install_fake_runner, make_fake_execute


@pytest.fixture
def fake_runner(monkeypatch: pytest.MonkeyPatch) -> FakeRunner:
    return install_fake_runner(monkeypatch)


@pytest.fixture
def evidence(session: Session) -> Evidence:
    (ev,) = evidence_service.scan_evidence(session)
    return ev


def _stale_run(session: Session, evidence: Evidence, **kw) -> Run:
    run = Run(
        evidence_id=evidence.id,
        plugin="windows.info.Info",
        status=RunStatus.RUNNING,
        phase="running",
        **kw,
    )
    session.add(run)
    session.commit()
    return run


def _actions(session: Session, action: str) -> list[AuditEvent]:
    return list(session.scalars(select(AuditEvent).where(AuditEvent.action == action)))


def test_recovery_keeps_partial_output(
    session: Session, settings: Settings, evidence: Evidence
) -> None:
    run = _stale_run(session, evidence)
    run_dir = settings.runs_dir / str(run.id)
    (run_dir / "output").mkdir(parents=True)
    (run_dir / "stdout.jsonl").write_text('{"PID": 4}\n')
    (run_dir / "stderr.txt").write_text("progress...\n")
    (run_dir / "output" / "pid.4.dmp").write_bytes(b"MZ" + b"\x00" * 10)

    assert recover_interrupted_runs(session) == 1
    session.expire_all()
    run = session.get(Run, run.id)
    assert run.status == RunStatus.INTERRUPTED
    assert run.error == "interrupted: the app stopped while this run was running"
    assert run.finished_at is not None and run.phase is None and run.pid is None
    assert run.stdout_path == f"runs/{run.id}/stdout.jsonl" and len(run.stdout_sha256) == 64
    assert run.stderr_path == f"runs/{run.id}/stderr.txt"
    (artifact,) = session.scalars(select(DerivedArtifact).where(DerivedArtifact.run_id == run.id))
    assert artifact.filename == "pid.4.dmp"
    (event,) = _actions(session, "run.interrupted")
    assert event.details["phase"] == "running" and event.details["artifacts"] == 1
    assert event.details["stdout_sha256"] == run.stdout_sha256
    assert event.details["orphan_process_killed"] is False
    # Idempotent.
    assert recover_interrupted_runs(session) == 0


def test_recovery_without_output_and_queued_runs_untouched(
    session: Session, evidence: Evidence
) -> None:
    run = _stale_run(session, evidence)
    run.phase = "hashing"
    queued = Run(evidence_id=evidence.id, plugin="windows.info.Info", status=RunStatus.QUEUED)
    session.add(queued)
    session.commit()
    recover_interrupted_runs(session)
    session.expire_all()
    assert session.get(Run, run.id).error.endswith("while this run was hashing")
    assert session.get(Run, run.id).stdout_path is None
    assert session.get(Run, queued.id).status == RunStatus.QUEUED


@pytest.mark.skipif(not Path("/proc/self/cwd").exists(), reason="needs /proc (Linux)")
def test_recovery_kills_orphaned_tool_process(
    session: Session, settings: Settings, evidence: Evidence
) -> None:
    run = _stale_run(session, evidence)
    run_dir = settings.runs_dir / str(run.id)
    run_dir.mkdir(parents=True)
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        cwd=run_dir,
        start_new_session=True,
    )
    # An unrelated process (different cwd) with a recorded pid must not be touched.
    other = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True
    )
    other_run = _stale_run(session, evidence, pid=other.pid)
    run.pid = proc.pid
    session.commit()
    try:
        recover_interrupted_runs(session)
        assert proc.wait(timeout=5) != 0
        assert other.poll() is None
        events = {e.object_id: e for e in _actions(session, "run.interrupted")}
        assert events[run.id].details["orphan_process_killed"] is True
        assert events[other_run.id].details["orphan_process_killed"] is False
    finally:
        for p in (proc, other):
            if p.poll() is None:
                p.kill()
                p.wait()


def test_recovery_flags_interrupted_hooks(session: Session, evidence: Evidence) -> None:
    run = Run(
        evidence_id=evidence.id,
        plugin="windows.info.Info",
        status=RunStatus.SUCCEEDED,
        phase="post-processing",
        hook_results=[{"hook": "a", "status": "ok"}],
    )
    session.add(run)
    session.commit()
    assert recover_interrupted_runs(session) == 0
    session.expire_all()
    run = session.get(Run, run.id)
    assert run.status == RunStatus.SUCCEEDED and run.phase is None
    assert run.hook_results[0]["status"] == "ok"
    assert run.hook_results[-1]["status"] == "error"
    assert "re-run hooks" in run.hook_results[-1]["error"]
    assert _actions(session, "run.hooks_interrupted")


def test_worker_shutdown_marks_run_interrupted(
    session: Session, evidence: Evidence, fake_runner: FakeRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(worker_mod, "execute", make_fake_execute([], block_until_cancel=True))
    run = runs_service.create_run(session, evidence.id, ToolRequest("windows.info.Info"))
    w = Worker(poll_interval=0.02)
    w.start()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        session.expire_all()
        if session.get(Run, run.id).status == RunStatus.RUNNING:
            break
        time.sleep(0.02)
    w.stop()
    session.expire_all()
    run = session.get(Run, run.id)
    assert run.status == RunStatus.INTERRUPTED
    assert run.error.startswith("interrupted: the app stopped while this run was running")


def test_user_cancel_is_still_cancelled(
    session: Session, evidence: Evidence, fake_runner: FakeRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(worker_mod, "execute", make_fake_execute([], block_until_cancel=True))
    w = Worker(poll_interval=0.02)
    monkeypatch.setattr(worker_mod, "get_worker", lambda: w)
    run = runs_service.create_run(session, evidence.id, ToolRequest("windows.info.Info"))
    w.start()
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            session.expire_all()
            if session.get(Run, run.id).status == RunStatus.RUNNING:
                break
            time.sleep(0.02)
        runs_service.cancel_run(session, run.id)
        while time.monotonic() < deadline:
            session.expire_all()
            if session.get(Run, run.id).status != RunStatus.RUNNING:
                break
            time.sleep(0.02)
    finally:
        w.stop()
    assert session.get(Run, run.id).status == RunStatus.CANCELLED


def test_pid_recorded_while_running_and_cleared_after(
    session: Session, evidence: Evidence, fake_runner: FakeRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[int | None] = []
    inner = make_fake_execute([{"PID": 4}])

    def fake_execute(*args, on_start=None, **kwargs):
        on_start(4242, ["vol", "x"])
        with worker_mod.SessionLocal() as s:
            seen.append(s.get(Run, run.id).pid)
            seen.append(s.get(Run, run.id).argv)
        return inner(*args, **kwargs)

    monkeypatch.setattr(worker_mod, "execute", fake_execute)
    run = runs_service.create_run(session, evidence.id, ToolRequest("windows.info.Info"))
    run.status = RunStatus.RUNNING  # as if claimed by the worker
    session.commit()
    Worker()._process(session, run.id, threading.Event())
    session.expire_all()
    assert seen == [4242, ["vol", "x"]]
    assert session.get(Run, run.id).status == RunStatus.SUCCEEDED
    assert session.get(Run, run.id).pid is None


def test_rerun(session: Session, evidence: Evidence, fake_runner: FakeRunner) -> None:
    run = runs_service.create_run(
        session, evidence.id, ToolRequest("windows.pslist.PsList", {"pid": [4]})
    )
    with pytest.raises(ValueError, match="only finished runs"):
        runs_service.rerun(session, run.id)
    run.status = RunStatus.INTERRUPTED
    session.commit()
    new = runs_service.rerun(session, run.id)
    assert new.id != run.id and new.status == RunStatus.QUEUED
    assert new.plugin == run.plugin and new.args == {"pid": [4]}
    assert new.rerun_of_id == run.id and new.origin == RunOrigin.MANUAL
    (event,) = [e for e in _actions(session, "run.create") if e.object_id == new.id]
    assert event.details["rerun_of_id"] == run.id


def test_rerun_api_and_ui(
    client: TestClient, session: Session, evidence: Evidence, fake_runner: FakeRunner
) -> None:
    run = Run(
        evidence_id=evidence.id,
        plugin="windows.info.Info",
        status=RunStatus.INTERRUPTED,
        error="interrupted: the app stopped while this run was running",
    )
    active = Run(evidence_id=evidence.id, plugin="windows.info.Info", status=RunStatus.QUEUED)
    session.add_all([run, active])
    session.commit()

    page = client.get(f"/runs/{run.id}").text
    assert "status-interrupted" in page and "Re-run" in page
    assert "Re-run" in client.get(f"/ui/evidence/{evidence.id}/runs").text

    r = client.post(f"/api/runs/{run.id}/rerun")
    assert r.status_code == 201 and r.json()["rerun_of_id"] == run.id
    assert client.post(f"/api/runs/{active.id}/rerun").status_code == 409

    r = client.post(f"/ui/runs/{run.id}/rerun", follow_redirects=False)
    assert r.status_code in (302, 303)
    new_id = int(r.headers["location"].rsplit("/", 1)[1])
    assert f're-run of <a href="/runs/{run.id}">' in client.get(f"/runs/{new_id}").text

    r = client.post(f"/ui/runs/{run.id}/rerun", headers={"HX-Request": "true"})
    assert "re-run of" in r.text and "Queued run" in r.text


def test_timeout_per_plugin(settings: Settings) -> None:
    class Runner(FakeRunner):
        def plugins(self) -> list[PluginSpec]:
            return [PluginSpec("slow.Plugin", timeout_seconds=7200), PluginSpec("fast.Plugin")]

    runner = Runner()
    assert _timeout_for(runner, "slow.Plugin", settings) == 7200
    assert _timeout_for(runner, "fast.Plugin", settings) == settings.run_timeout_seconds
    assert _timeout_for(runner, "gone.Plugin", settings) == settings.run_timeout_seconds


def test_migration_converts_old_interrupted_runs(settings: Settings) -> None:
    """Runs the old code marked failed with "interrupted by restart" become interrupted."""
    from alembic import command
    from sqlalchemy import text

    from app import db

    engine = db.init_engine()
    cfg = db.alembic_config()
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "0006_results")
        conn.execute(
            text(
                "INSERT INTO evidence (rel_path, size_bytes, mtime, description, created_at) "
                "VALUES ('old.raw', 1, 0, '', '2026-01-01 00:00:00')"
            )
        )
        for error in ("interrupted by restart", "tool exited with code 1"):
            conn.execute(
                text(
                    "INSERT INTO runs (evidence_id, tool, plugin, args, origin, status, "
                    "created_at, row_count, chain_depth, search_indexed, error) VALUES "
                    "(1, 'volatility3', 'p', '{}', 'MANUAL', 'FAILED', '2026-01-01', 0, 0, 0, :e)"
                ),
                {"e": error},
            )
    db.migrate(engine)
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT error, status FROM runs ORDER BY id")).all()
    assert [r[1] for r in rows] == ["INTERRUPTED", "FAILED"]
