"""Backend service tests: evidence, runs, notes, worker."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.config import Settings
from app.db import SessionLocal
from app.jobs import worker as worker_mod
from app.jobs.worker import Worker, recover_stale_runs
from app.models import Evidence, ResultRow, Run, RunOrigin, RunStatus
from app.services import evidence as evidence_service
from app.services import notes as notes_service
from app.services import runs as runs_service
from app.tools.base import ArgValidationError, ToolRequest
from tests.test_backend_fakes import FakeRunner, install_fake_runner, make_fake_execute


@pytest.fixture
def fake_runner(monkeypatch: pytest.MonkeyPatch) -> FakeRunner:
    return install_fake_runner(monkeypatch)


# -- evidence -------------------------------------------------------------------------------


def test_scan_finds_files_and_skips_hidden_and_escaping_links(
    settings: Settings, session: Session, tmp_path: Path
) -> None:
    ev_dir = settings.evidence_dir
    (ev_dir / "sub").mkdir()
    (ev_dir / "sub" / "b.mem").write_bytes(b"abc")
    (ev_dir / ".hidden").write_bytes(b"x")
    (ev_dir / ".dir").mkdir()
    (ev_dir / ".dir" / "c.raw").write_bytes(b"x")
    outside = tmp_path / "outside.raw"
    outside.write_bytes(b"secret")
    os.symlink(outside, ev_dir / "escape.raw")
    os.symlink(ev_dir / "sample.raw", ev_dir / "inside-link.raw")

    found = evidence_service.scan_evidence(session)
    assert sorted(e.rel_path for e in found) == ["inside-link.raw", "sample.raw", "sub/b.mem"]
    sample = next(e for e in found if e.rel_path == "sample.raw")
    assert sample.size_bytes == 4096

    # Rescan is idempotent (upsert by rel_path).
    again = evidence_service.scan_evidence(session)
    assert {e.id for e in again} == {e.id for e in found}


def test_scan_clears_hash_when_file_changes(settings: Settings, session: Session) -> None:
    (ev,) = evidence_service.scan_evidence(session)
    evidence_service.hash_evidence(session, ev.id)
    assert ev.sha256
    path = settings.evidence_dir / "sample.raw"
    path.write_bytes(b"\x01" * 10)
    os.utime(path, (1_000_000, 1_000_000))
    (ev2,) = evidence_service.scan_evidence(session)
    assert ev2.id == ev.id
    assert ev2.size_bytes == 10
    assert ev2.sha256 is None


@pytest.mark.parametrize("bad", ["../outside.raw", "/etc/passwd", "sub/../../x", ""])
def test_resolve_evidence_path_rejects_traversal(settings: Settings, bad: str) -> None:
    with pytest.raises(ValueError):
        evidence_service.resolve_evidence_path(Evidence(rel_path=bad, size_bytes=0, mtime=0))


def test_resolve_evidence_path_ok(settings: Settings) -> None:
    p = evidence_service.resolve_evidence_path(
        Evidence(rel_path="sample.raw", size_bytes=0, mtime=0)
    )
    assert p == (settings.evidence_dir / "sample.raw").resolve()


def test_hash_evidence_and_cache(session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    import hashlib

    (ev,) = evidence_service.scan_evidence(session)
    evidence_service.hash_evidence(session, ev.id)
    assert ev.sha256 == hashlib.sha256(b"\x00" * 4096).hexdigest()
    assert ev.hashed_at is not None

    def boom(_path: Path) -> str:
        raise AssertionError("should be cached")

    monkeypatch.setattr(evidence_service, "_sha256_file", boom)
    assert evidence_service.hash_evidence(session, ev.id).sha256 == ev.sha256


def test_hash_in_background(session: Session) -> None:
    (ev,) = evidence_service.scan_evidence(session)
    evidence_service.start_hash_in_background(ev.id)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        session.expire_all()
        if session.get(Evidence, ev.id).sha256:  # type: ignore[union-attr]
            break
        time.sleep(0.02)
    assert session.get(Evidence, ev.id).sha256  # type: ignore[union-attr]


# -- runs -----------------------------------------------------------------------------------


@pytest.fixture
def evidence(session: Session) -> Evidence:
    (ev,) = evidence_service.scan_evidence(session)
    return ev


def test_create_run_validates(
    session: Session, evidence: Evidence, fake_runner: FakeRunner
) -> None:
    run = runs_service.create_run(
        session, evidence.id, ToolRequest("windows.pslist.PsList", {"pid": [4]})
    )
    assert run.status == RunStatus.QUEUED
    assert run.args == {"pid": [4]}
    assert run.origin == RunOrigin.MANUAL
    with pytest.raises(ArgValidationError):
        runs_service.create_run(session, evidence.id, ToolRequest("windows.evil.Evil"))
    with pytest.raises(ArgValidationError):
        runs_service.create_run(
            session, evidence.id, ToolRequest("windows.pslist.PsList", {"bogus": 1})
        )
    with pytest.raises(LookupError):
        runs_service.create_run(session, 999, ToolRequest("windows.info.Info"))


def test_enqueue_auto_dedupes(
    session: Session, evidence: Evidence, fake_runner: FakeRunner
) -> None:
    created = runs_service.enqueue_auto(session, evidence.id)
    assert sorted(r.plugin for r in created) == ["windows.info.Info", "windows.pslist.PsList"]
    assert all(r.origin == RunOrigin.AUTO and r.args == {} for r in created)
    assert runs_service.enqueue_auto(session, evidence.id) == []
    # A failed run does not block re-enqueueing.
    created[0].status = RunStatus.FAILED
    session.commit()
    again = runs_service.enqueue_auto(session, evidence.id)
    assert [r.plugin for r in again] == [created[0].plugin]


def test_cancel_queued_run(session: Session, evidence: Evidence, fake_runner: FakeRunner) -> None:
    run = runs_service.create_run(session, evidence.id, ToolRequest("windows.info.Info"))
    cancelled = runs_service.cancel_run(session, run.id)
    assert cancelled.status == RunStatus.CANCELLED
    assert cancelled.finished_at is not None
    # Idempotent on finished runs.
    assert runs_service.cancel_run(session, run.id).status == RunStatus.CANCELLED


def test_get_rows_paging_and_filter(session: Session, evidence: Evidence) -> None:
    run = Run(evidence_id=evidence.id, plugin="windows.pslist.PsList", status=RunStatus.SUCCEEDED)
    session.add(run)
    session.flush()
    names = ["System", "smss.exe", "csrss.exe", "explorer.exe", "100%_real.exe"]
    for i, name in enumerate(names):
        session.add(ResultRow(run_id=run.id, row_idx=i, data={"ImageFileName": name, "PID": i}))
    session.commit()

    rows, total = runs_service.get_rows(session, run.id, offset=1, limit=2)
    assert total == 5
    assert [r.row_idx for r in rows] == [1, 2]
    assert rows[0].citation == f"R{run.id}:1"

    rows, total = runs_service.get_rows(session, run.id, q="EXE")
    assert total == 4
    rows, total = runs_service.get_rows(session, run.id, q="SYSTEM")
    assert [r.data["ImageFileName"] for r in rows] == ["System"]
    # LIKE wildcards in q are literal.
    rows, total = runs_service.get_rows(session, run.id, q="0%_")
    assert total == 1
    rows, total = runs_service.get_rows(session, run.id, q="s_ss")
    assert total == 0


# -- notes ----------------------------------------------------------------------------------


def test_notes_crud(session: Session, evidence: Evidence) -> None:
    g = notes_service.create_note(session, "global note")
    n = notes_service.create_note(session, "  evidence note ", evidence_id=evidence.id)
    assert n.body == "evidence note"
    assert [x.id for x in notes_service.list_notes(session)] == [g.id, n.id]
    assert [x.id for x in notes_service.list_notes(session, evidence.id)] == [n.id]

    before = n.updated_at
    time.sleep(0.01)
    updated = notes_service.update_note(session, n.id, "changed")
    assert updated.body == "changed"
    assert updated.updated_at > before

    with pytest.raises(ValueError):
        notes_service.update_note(session, n.id, "   ")
    with pytest.raises(LookupError):
        notes_service.create_note(session, "x", evidence_id=999)

    notes_service.delete_note(session, n.id)
    assert [x.id for x in notes_service.list_notes(session)] == [g.id]
    with pytest.raises(LookupError):
        notes_service.delete_note(session, n.id)


# -- worker ---------------------------------------------------------------------------------


def _wait_for_status(session: Session, run_id: int, statuses: set[RunStatus]) -> Run:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        session.expire_all()
        run = session.get(Run, run_id)
        assert run is not None
        if run.status in statuses:
            return run
        time.sleep(0.02)
    raise AssertionError(f"run {run_id} stuck in {run.status}")


_DONE = {RunStatus.SUCCEEDED, RunStatus.FAILED, RunStatus.CANCELLED}


@pytest.fixture
def worker() -> Worker:
    w = Worker(poll_interval=0.02)
    yield w  # type: ignore[misc]
    w.stop()


def test_worker_runs_end_to_end(
    settings: Settings,
    session: Session,
    evidence: Evidence,
    fake_runner: FakeRunner,
    worker: Worker,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_service.hash_evidence(session, evidence.id)
    rows = [{"PID": 4, "name": "System"}, {"PID": 88, "name": "smss.exe", "depth": 1, "parent": 0}]
    rows += [{"PID": 1000 + i} for i in range(2500)]  # exercise batching
    monkeypatch.setattr(worker_mod, "execute", make_fake_execute(rows))

    run = runs_service.create_run(session, evidence.id, ToolRequest("windows.pstree.PsTree"))
    worker.start()
    run = _wait_for_status(session, run.id, _DONE)

    assert run.status == RunStatus.SUCCEEDED, run.error
    assert run.row_count == len(rows)
    assert run.evidence_sha256 == evidence.sha256
    assert run.argv and run.argv[-1] == "windows.pstree.PsTree"
    assert run.tool_version == "fake-1.0"
    assert run.returncode == 0
    assert run.stdout_path == f"runs/{run.id}/stdout.jsonl"
    assert (settings.data_dir / run.stdout_path).is_file()
    assert run.stdout_sha256 and run.started_at and run.finished_at and run.heartbeat_at
    page, total = runs_service.get_rows(session, run.id, limit=2)
    assert total == len(rows)
    assert page[1].depth == 1 and page[1].parent_idx == 0
    assert page[1].data["name"] == "smss.exe"


def test_worker_failure_records_stderr_tail(
    session: Session,
    evidence: Evidence,
    fake_runner: FakeRunner,
    worker: Worker,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stderr = "x" * 5000 + "Unsatisfied requirement: symbols"
    monkeypatch.setattr(worker_mod, "execute", make_fake_execute([], returncode=1, stderr=stderr))
    run = runs_service.create_run(session, evidence.id, ToolRequest("windows.info.Info"))
    worker.start()
    run = _wait_for_status(session, run.id, _DONE)
    assert run.status == RunStatus.FAILED
    assert run.error is not None
    assert "exited with code 1" in run.error
    assert run.error.endswith("Unsatisfied requirement: symbols")
    assert len(run.error) < 2200


def test_worker_parse_error_rolls_back_rows(
    session: Session,
    evidence: Evidence,
    fake_runner: FakeRunner,
    worker: Worker,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_runner.fail_parse_after = 1500
    monkeypatch.setattr(worker_mod, "execute", make_fake_execute([{"i": i} for i in range(2000)]))
    run = runs_service.create_run(session, evidence.id, ToolRequest("windows.info.Info"))
    worker.start()
    run = _wait_for_status(session, run.id, _DONE)
    assert run.status == RunStatus.FAILED
    assert "parse failed" in (run.error or "")
    assert run.argv  # provenance kept
    assert runs_service.get_rows(session, run.id)[1] == 0


def test_worker_cancel_running_run(
    session: Session,
    evidence: Evidence,
    fake_runner: FakeRunner,
    worker: Worker,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(worker_mod, "execute", make_fake_execute([], block_until_cancel=True))
    monkeypatch.setattr(worker_mod, "get_worker", lambda: worker)
    run = runs_service.create_run(session, evidence.id, ToolRequest("windows.info.Info"))
    queued = runs_service.create_run(session, evidence.id, ToolRequest("windows.pstree.PsTree"))
    worker.start()
    _wait_for_status(session, run.id, {RunStatus.RUNNING})
    # max_concurrent_runs=1: the second run must stay QUEUED while the first is running.
    time.sleep(0.1)
    session.expire_all()
    assert session.get(Run, queued.id).status == RunStatus.QUEUED  # type: ignore[union-attr]
    assert runs_service.cancel_run(session, queued.id).status == RunStatus.CANCELLED

    runs_service.cancel_run(session, run.id)
    run = _wait_for_status(session, run.id, _DONE)
    assert run.status == RunStatus.CANCELLED


def test_cancel_running_without_worker_marks_cancelled(
    session: Session, evidence: Evidence, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(worker_mod, "get_worker", lambda: Worker())
    run = Run(evidence_id=evidence.id, plugin="windows.info.Info", status=RunStatus.RUNNING)
    session.add(run)
    session.commit()
    assert runs_service.cancel_run(session, run.id).status == RunStatus.CANCELLED


def test_recover_stale_runs(session: Session, evidence: Evidence) -> None:
    for st in (RunStatus.RUNNING, RunStatus.RUNNING, RunStatus.QUEUED, RunStatus.SUCCEEDED):
        session.add(Run(evidence_id=evidence.id, plugin="windows.info.Info", status=st))
    session.commit()
    assert recover_stale_runs(session) == 2
    session.expire_all()
    with SessionLocal() as s:
        failed = s.query(Run).filter(Run.status == RunStatus.FAILED).all()
        assert len(failed) == 2
        assert all(r.error == "interrupted by restart" for r in failed)
    assert recover_stale_runs(session) == 0
