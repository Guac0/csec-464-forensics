"""Deleting runs (tombstones) and bulk clean-up."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import AIMessage, AuditEvent, Evidence, ResultRow, Run, RunStatus
from app.services import artifacts, export, notes, results, run_deletion
from app.services import evidence as evidence_service
from app.services import runs as runs_service
from app.tools.base import ParsedRow
from tests.test_backend_fakes import FakeRunner, install_fake_runner


@pytest.fixture
def fake_runner(monkeypatch: pytest.MonkeyPatch) -> FakeRunner:
    return install_fake_runner(monkeypatch)


@pytest.fixture
def evidence(session: Session) -> Evidence:
    (ev,) = evidence_service.scan_evidence(session)
    return ev


def _run(
    session: Session,
    settings: Settings,
    evidence: Evidence,
    status: RunStatus = RunStatus.SUCCEEDED,
    *,
    indexed: bool = True,
) -> Run:
    """A finished run with 3 rows, raw output and one dumped file."""
    run = Run(evidence_id=evidence.id, plugin="windows.pslist.PsList", status=status)
    session.add(run)
    session.flush()
    run_dir = settings.runs_dir / str(run.id)
    (run_dir / "output").mkdir(parents=True)
    (run_dir / "stdout.jsonl").write_text('{"PID": 4}\n' * 3)
    (run_dir / "output" / "pid.4.dmp").write_bytes(b"MZ" + b"\0" * 2000)
    run.stdout_path = f"runs/{run.id}/stdout.jsonl"
    run.stdout_sha256 = "a" * 64
    results.store_rows(
        session,
        run.id,
        [ParsedRow({"PID": i, "File output": "pid.4.dmp"}) for i in range(3)],
        search_index=indexed,
    )
    run.search_indexed = indexed
    run.row_count = 3
    artifacts.register_run_outputs(session, run, run_dir / "output")
    session.commit()
    return run


def _fts_count(session: Session) -> int:
    return session.execute(text("SELECT count(*) FROM result_rows_fts")).scalar()


def test_delete_run_leaves_a_tombstone(
    session: Session, settings: Settings, evidence: Evidence
) -> None:
    run = _run(session, settings, evidence)
    keep = _run(session, settings, evidence)
    session.add(
        AIMessage(
            evidence_id=evidence.id,
            role="assistant",
            content=f"see [R{run.id}:0]",
            citations=[{"key": f"R{run.id}:0", "valid": True}],
        )
    )
    notes.create_note(session, f"odd [R{run.id}:1]", evidence_id=evidence.id)
    session.commit()

    preview = run_deletion.preview(session, run.id)
    assert (preview.rows, preview.dumped_files, preview.problem) == (3, 1, None)
    assert preview.bytes_on_disk > 2000
    assert (preview.ai_answers_citing, preview.notes_citing) == (1, 1)

    result = run_deletion.delete_run(session, run.id, "  superseded by a re-run  ")
    assert result.rows_deleted == 3 and result.files_removed and result.bytes_freed > 2000
    session.expire_all()
    run = session.get(Run, run.id)
    assert run.deleted_at is not None and run.delete_reason == "superseded by a re-run"
    assert run.status == RunStatus.SUCCEEDED and run.row_count == 3  # what it was
    assert run.stdout_sha256 == "a" * 64 and len(run.artifacts) == 1  # hashes kept
    assert not (settings.runs_dir / str(run.id)).exists()
    assert (settings.runs_dir / str(keep.id)).exists()
    counts = dict(
        session.execute(select(ResultRow.run_id, func.count()).group_by(ResultRow.run_id)).all()
    )
    assert counts == {keep.id: 3}
    assert _fts_count(session) == 3  # only the kept run's index entries
    (event,) = session.scalars(select(AuditEvent).where(AuditEvent.action == "run.delete"))
    assert event.details["reason"] == "superseded by a re-run"
    assert event.details["rows_deleted"] == 3
    assert event.details["dumped_files"][0]["filename"] == "pid.4.dmp"

    with pytest.raises(artifacts.ArtifactIntegrityError, match="was deleted with run"):
        artifacts.prepare_download(session, run.artifacts[0].id)
    with pytest.raises(ValueError, match="already deleted"):
        run_deletion.delete_run(session, run.id, "again")

    report = export.build_report(session, evidence.id)
    assert "succeeded (deleted)" in report  # runs table
    assert export.esc("superseded by a re-run") in report
    bundle = export.build_bundle(session, evidence.id)
    try:
        assert not any(f"run-{run.id}-" in f["path"] for f in bundle.files)
    finally:
        bundle.path.unlink()


def test_delete_refuses_active_runs_and_needs_a_reason(
    session: Session, settings: Settings, evidence: Evidence
) -> None:
    run = _run(session, settings, evidence, RunStatus.RUNNING)
    with pytest.raises(ValueError, match="reason is required"):
        run_deletion.delete_run(session, run.id, " ")
    with pytest.raises(ValueError, match="cancel it first"):
        run_deletion.delete_run(session, run.id, "x")
    with pytest.raises(LookupError):
        run_deletion.delete_run(session, 999, "x")


def test_bulk_cleanup(session: Session, settings: Settings, evidence: Evidence) -> None:
    ok = _run(session, settings, evidence)
    failed = _run(session, settings, evidence, RunStatus.FAILED)
    stopped = _run(session, settings, evidence, RunStatus.INTERRUPTED)
    cancelled = _run(session, settings, evidence, RunStatus.CANCELLED, indexed=False)
    assert {r.id for r in run_deletion.cleanup_candidates(session, evidence.id)} == {
        failed.id,
        stopped.id,
        cancelled.id,
    }
    with pytest.raises(ValueError, match="only deletes failed"):
        run_deletion.delete_runs(session, evidence.id, "x", (RunStatus.SUCCEEDED,))
    deleted = run_deletion.delete_runs(session, evidence.id, "freeing space")
    assert sorted(r.run_id for r in deleted) == sorted([failed.id, stopped.id, cancelled.id])
    session.expire_all()
    assert session.get(Run, ok.id).deleted_at is None
    assert run_deletion.cleanup_candidates(session, evidence.id) == []
    events = session.scalars(select(AuditEvent).where(AuditEvent.action == "run.delete")).all()
    assert len(events) == 3 and all(e.details["bulk"] for e in events)
    assert [r.id for r, _ in run_deletion.biggest_runs(session)] == [ok.id]


def test_deleted_succeeded_run_does_not_block_auto_enumerate(
    session: Session, settings: Settings, evidence: Evidence, fake_runner: FakeRunner
) -> None:
    first = runs_service.enqueue_auto(session, evidence.id)
    for r in first:
        r.status = RunStatus.SUCCEEDED
    session.commit()
    assert runs_service.enqueue_auto(session, evidence.id) == []
    for r in first:
        run_deletion.delete_run(session, r.id, "redo")
    assert len(runs_service.enqueue_auto(session, evidence.id)) == len(first)


def test_api_and_ui(
    client: TestClient, session: Session, settings: Settings, evidence: Evidence
) -> None:
    run = _run(session, settings, evidence)
    failed = _run(session, settings, evidence, RunStatus.FAILED)
    session.add(
        AIMessage(
            evidence_id=evidence.id,
            role="assistant",
            content=f"see [R{run.id}:0]",
            citations=[{"key": f"R{run.id}:0", "valid": True}],
        )
    )
    session.commit()

    page = client.get(f"/runs/{run.id}").text
    assert "Delete…" in page and "Cited by 1 AI answer(s)" in page
    assert client.get(f"/api/runs/{run.id}/delete-preview").json()["rows"] == 3
    assert client.post(f"/api/runs/{run.id}/delete", json={"reason": ""}).status_code == 422

    r = client.post(f"/ui/runs/{run.id}/delete", data={"reason": ""})
    assert "Delete failed: a reason is required" in r.text
    r = client.post(
        f"/ui/runs/{run.id}/delete", data={"reason": "not needed"}, follow_redirects=False
    )
    assert r.status_code in (302, 303) and r.headers["location"] == f"/runs/{run.id}"
    page = client.get(f"/runs/{run.id}").text
    assert "not needed" in page and "status-deleted" in page and "rows were deleted" in page
    assert "Encrypted zip" not in page and "deleted (hashes kept)" in page
    assert client.post(f"/api/runs/{run.id}/delete", json={"reason": "x"}).status_code == 409
    assert client.get(f"/api/runs/{run.id}").json()["delete_reason"] == "not needed"
    assert client.get(f"/api/runs/{run.id}/export?format=raw").status_code == 410

    ev_page = client.get(f"/evidence/{evidence.id}").text
    assert "cite-deleted" in ev_page  # AI citation to the deleted run is marked
    assert "Clean up… (1," in ev_page
    r = client.post(
        f"/ui/evidence/{evidence.id}/cleanup",
        data={"reason": "failed attempts"},
        headers={"HX-Request": "true"},
    )
    assert "Deleted the data of 1 run(s)" in r.text
    session.expire_all()
    assert session.get(Run, failed.id).deleted_at is not None
    r = client.post(f"/api/evidence/{evidence.id}/cleanup", json={"reason": "again"})
    assert r.json() == {"deleted_run_ids": [], "bytes_freed": 0}
    assert "Runs using the most disk" in client.get("/system").text
