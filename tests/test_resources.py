"""Disk-space guard: refusing new runs, holding queued runs, stopping running ones."""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.jobs import worker as worker_mod
from app.jobs.worker import Worker
from app.models import Evidence, Run, RunStatus
from app.services import evidence as evidence_service
from app.services import resources
from app.services import runs as runs_service
from app.tools.base import ExecutionResult, ToolRequest
from tests.test_backend_fakes import FakeRunner, install_fake_runner, make_fake_execute

PIB = str(1024**5)  # more free space than any test machine has


@pytest.fixture
def fake_runner(monkeypatch: pytest.MonkeyPatch) -> FakeRunner:
    return install_fake_runner(monkeypatch)


@pytest.fixture
def evidence(session: Session) -> Evidence:
    (ev,) = evidence_service.scan_evidence(session)
    return ev


def _set(monkeypatch: pytest.MonkeyPatch, **env: str) -> Settings:
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    get_settings.cache_clear()
    return get_settings()


def test_status_problems_and_warnings(settings: Settings) -> None:
    def status(free: int, data: int = 0, cap: int = 0) -> resources.DiskStatus:
        return resources.DiskStatus(free, 100 * 2**30, data, 5 * 2**30, 2**30, cap)

    assert status(free=50 * 2**30).problem is None and status(free=50 * 2**30).warning is None
    assert "only 4.0 GiB free" in status(free=4 * 2**30).problem
    assert "getting low" in status(free=8 * 2**30).warning
    assert "cap" in status(free=50 * 2**30, data=10, cap=10).problem
    capped = status(free=50 * 2**30, data=9, cap=10)
    assert capped.problem is None and "of its" in capped.warning
    assert resources.fmt_bytes(512) == "512 B" and resources.fmt_bytes(3 * 2**20) == "3.0 MiB"


def test_create_run_refused_when_disk_low(
    session: Session, evidence: Evidence, fake_runner: FakeRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set(monkeypatch, FT_MIN_FREE_DISK_BYTES=PIB)
    with pytest.raises(resources.DiskSpaceError, match="FT_MIN_FREE_DISK_BYTES"):
        runs_service.create_run(session, evidence.id, ToolRequest("windows.info.Info"))
    with pytest.raises(resources.DiskSpaceError):
        runs_service.enqueue_auto(session, evidence.id)
    assert session.query(Run).count() == 0


def test_data_folder_cap(
    session: Session, evidence: Evidence, fake_runner: FakeRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _set(monkeypatch, FT_MAX_DATA_BYTES="1")
    resources.data_dir_size(settings, fresh=True)  # the DB file alone is over 1 byte
    with pytest.raises(resources.DiskSpaceError, match="FT_MAX_DATA_BYTES"):
        runs_service.create_run(session, evidence.id, ToolRequest("windows.info.Info"))


def test_api_and_ui_report_disk_errors(
    client: TestClient, evidence: Evidence, fake_runner: FakeRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set(monkeypatch, FT_MIN_FREE_DISK_BYTES=PIB)
    r = client.post("/api/runs", json={"evidence_id": evidence.id, "plugin": "windows.info.Info"})
    assert r.status_code == 507 and "not enough disk space" in r.json()["detail"]
    assert client.post(f"/api/evidence/{evidence.id}/auto").status_code == 507
    r = client.post(
        f"/ui/evidence/{evidence.id}/runs",
        data={"plugin": "windows.info.Info"},
        headers={"HX-Request": "true"},
    )
    assert "not enough disk space" in r.text
    r = client.post(f"/ui/evidence/{evidence.id}/auto", headers={"HX-Request": "true"})
    assert "not enough disk space" in r.text


def test_queued_runs_wait_for_disk_space(
    session: Session, evidence: Evidence, fake_runner: FakeRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(worker_mod, "execute", make_fake_execute([{"PID": 4}]))
    run = runs_service.create_run(session, evidence.id, ToolRequest("windows.info.Info"))
    _set(monkeypatch, FT_MIN_FREE_DISK_BYTES=PIB)
    w = Worker(poll_interval=0.02)
    w.start()
    try:
        time.sleep(0.3)
        session.expire_all()
        assert session.get(Run, run.id).status == RunStatus.QUEUED  # waiting, not failed
        assert w.disk_problem and "FT_MIN_FREE_DISK_BYTES" in w.disk_problem
        _set(monkeypatch, FT_MIN_FREE_DISK_BYTES="0")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            session.expire_all()
            if session.get(Run, run.id).status == RunStatus.SUCCEEDED:
                break
            time.sleep(0.02)
        assert session.get(Run, run.id).status == RunStatus.SUCCEEDED
    finally:
        w.stop()


def test_hard_floor_problem(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    assert resources.hard_floor_problem(settings) is None  # 0 = off in tests
    settings = _set(monkeypatch, FT_HARD_MIN_FREE_DISK_BYTES=PIB)
    assert "FT_HARD_MIN_FREE_DISK_BYTES" in resources.hard_floor_problem(settings)


def test_worker_fails_run_stopped_for_disk_space(
    session: Session, evidence: Evidence, fake_runner: FakeRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, object] = {}

    def fake_execute(runner, evidence_path, request, run_dir, timeout, cancel_event, **kw):
        seen["should_stop"] = kw["should_stop"]
        stdout, stderr = Path(run_dir) / "stdout.jsonl", Path(run_dir) / "stderr.txt"
        stdout.write_text('{"PID": 4}\n')
        stderr.write_text("")
        return ExecutionResult(
            argv=["vol"],
            returncode=-9,
            stdout_path=stdout,
            stderr_path=stderr,
            stdout_sha256="0" * 64,
            tool_version="x",
            stop_reason="stopped: free disk space fell to 1 B",
        )

    monkeypatch.setattr(worker_mod, "execute", fake_execute)
    run = runs_service.create_run(session, evidence.id, ToolRequest("windows.info.Info"))
    Worker()._process(session, run.id, threading.Event())
    session.expire_all()
    run = session.get(Run, run.id)
    assert run.status == RunStatus.FAILED
    assert run.error.startswith("stopped: free disk space fell to 1 B")
    assert run.row_count == 0 and run.stdout_path  # output kept, rows not stored
    assert seen["should_stop"]() is None  # hard floor off in tests


def test_executor_stops_on_should_stop(settings: Settings, tmp_path: Path) -> None:
    from app.tools.executor import execute

    class SleepRunner(FakeRunner):
        def build_argv(self, evidence_path, request, output_dir):
            return ["sleep", "30"]

    started_with: list[tuple[int, list[str]]] = []
    started = time.monotonic()
    result = execute(
        SleepRunner(),
        tmp_path / "x.raw",
        ToolRequest("windows.info.Info"),
        tmp_path / "run",
        30,
        threading.Event(),
        kill_grace=1,
        output_check_interval=0.1,
        on_start=lambda pid, argv: started_with.append((pid, argv)),
        should_stop=lambda: "disk full",
    )
    assert result.stop_reason == "disk full"
    assert not result.cancelled and not result.timed_out
    assert time.monotonic() - started < 10
    assert len(started_with) == 1 and started_with[0][0] > 0
    assert started_with[0][1] == ["sleep", "30"]
