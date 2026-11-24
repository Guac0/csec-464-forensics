"""Evidence integrity: hashing, states, expected hashes, acknowledgement, the pre-run gate in
strict and warn mode, full verification before runs, API/UI and migration backfill."""

from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import DatabaseError
from sqlalchemy.orm import Session

from app import db
from app.config import Settings, get_settings
from app.jobs import worker as worker_mod
from app.jobs.worker import Worker
from app.models import AuditEvent, Evidence, IntegrityCheck, Run, RunStatus
from app.services import evidence as evidence_service
from app.services import integrity
from app.services import runs as runs_service
from app.tools.base import ToolRequest
from tests.test_backend_fakes import install_fake_runner, make_fake_execute

DATA = b"\x00" * 4096
SHA256 = hashlib.sha256(DATA).hexdigest()
MD5 = hashlib.md5(DATA).hexdigest()  # noqa: S324
SHA1 = hashlib.sha1(DATA).hexdigest()  # noqa: S324
INFO = "windows.info.Info"


@pytest.fixture
def mode(monkeypatch: pytest.MonkeyPatch):
    def set_mode(value: str, verify_on_run: bool = False) -> None:
        monkeypatch.setenv("FT_INTEGRITY_MODE", value)
        monkeypatch.setenv("FT_VERIFY_ON_RUN", "true" if verify_on_run else "false")
        get_settings.cache_clear()

    return set_mode


@pytest.fixture
def evidence(session: Session) -> Evidence:
    (ev,) = evidence_service.scan_evidence(session)
    return ev


@pytest.fixture
def image(settings: Settings) -> Path:
    return settings.evidence_dir / "sample.raw"


def checks(session: Session, ev: Evidence) -> list[IntegrityCheck]:
    session.expire_all()
    return list(
        session.scalars(
            select(IntegrityCheck)
            .where(IntegrityCheck.evidence_id == ev.id)
            .order_by(IntegrityCheck.id)
        )
    )


def audit_actions(session: Session) -> list[str]:
    session.expire_all()
    return [e.action for e in session.scalars(select(AuditEvent).order_by(AuditEvent.seq))]


def run_to_completion(
    session: Session, evidence: Evidence, monkeypatch: pytest.MonkeyPatch, plugin: str = INFO
) -> Run:
    install_fake_runner(monkeypatch)
    monkeypatch.setattr(worker_mod, "execute", make_fake_execute([{"Variable": "A"}]))
    run = runs_service.create_run(session, evidence.id, ToolRequest(plugin))
    return wait_for_worker(session, run.id)


def wait_for_worker(session: Session, run_id: int) -> Run:
    w = Worker(poll_interval=0.02)
    w.start()
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            session.expire_all()
            run = session.get(Run, run_id)
            if run.status in (RunStatus.SUCCEEDED, RunStatus.FAILED, RunStatus.CANCELLED):
                if run.phase is None:
                    return run
            time.sleep(0.02)
    finally:
        w.stop()
    raise AssertionError("run did not finish")


def change_content_keep_stat(path: Path) -> None:
    """Same size and mtime, different bytes: only a full re-hash can notice."""
    st = path.stat()
    path.write_bytes(b"\x01" + DATA[1:])
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))


# ------------------------------------------------------------------------------- hashing


def test_compute_hashes_and_cancel(image: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    res = integrity.compute_hashes(image)
    assert (res.sha256, res.md5, res.sha1, res.size_bytes) == (SHA256, MD5, SHA1, 4096)
    monkeypatch.setattr(integrity, "HASH_CHUNK_SIZE", 512)
    monkeypatch.setattr(integrity, "PROGRESS_EVERY_BYTES", 1024)
    progress: list[int] = []
    with pytest.raises(integrity.HashCancelled):
        integrity.compute_hashes(image, should_stop=lambda: True, on_progress=progress.append)
    assert progress == [1024]


def test_states_expected_hashes_and_acknowledgement(session: Session, evidence: Evidence) -> None:
    assert integrity.status(evidence) == integrity.NOT_HASHED
    evidence_service.hash_evidence(session, evidence.id)
    assert (evidence.sha256, evidence.md5, evidence.sha1) == (SHA256, MD5, SHA1)
    assert integrity.status(evidence) == integrity.HASHED

    integrity.set_expected_hashes(session, evidence.id, md5=MD5.upper(), sha1=SHA1)
    assert evidence.expected_md5 == MD5  # normalised to lower case
    assert integrity.status(evidence) == integrity.MATCHES_EXPECTED

    integrity.set_expected_hashes(session, evidence.id, sha256="a" * 64, md5=MD5, sha1=SHA1)
    assert integrity.status(evidence) == integrity.MISMATCH
    assert integrity.mismatched_algorithms(evidence) == ["sha256"]
    with pytest.raises(ValueError, match="reason"):
        integrity.acknowledge_mismatch(session, evidence.id, "  ")
    integrity.acknowledge_mismatch(session, evidence.id, "report lists the zip's hash")
    assert integrity.status(evidence) == integrity.MISMATCH_ACKNOWLEDGED
    with pytest.raises(ValueError, match="no unacknowledged"):
        integrity.acknowledge_mismatch(session, evidence.id, "again")

    # Changing the expected hashes withdraws the acknowledgement.
    integrity.set_expected_hashes(session, evidence.id, sha256="b" * 64)
    assert integrity.status(evidence) == integrity.MISMATCH and evidence.mismatch_ack_at is None
    for bad in ("xyz", "a" * 63):
        with pytest.raises(ValueError, match="hex"):
            integrity.set_expected_hashes(session, evidence.id, sha256=bad)
    integrity.set_expected_hashes(session, evidence.id)  # clear all
    assert integrity.status(evidence) == integrity.HASHED

    actions = audit_actions(session)
    assert actions.count("evidence.expected_hashes") == 4
    assert "evidence.mismatch_acknowledged" in actions


def test_scan_flags_change_and_verify_accepts_new_content(
    session: Session, evidence: Evidence, image: Path
) -> None:
    evidence_service.hash_evidence(session, evidence.id)
    image.write_bytes(b"\x01" * 10)
    evidence_service.scan_evidence(session)
    evidence_service.scan_evidence(session)  # flagged once, not on every scan
    assert integrity.status(evidence) == integrity.CHANGED
    assert audit_actions(session).count("evidence.changed_on_disk") == 1

    evidence_service.hash_evidence(session, evidence.id)  # the analyst's "Verify"
    assert integrity.status(evidence) == integrity.HASHED
    assert evidence.size_bytes == 10 and evidence.sha256 == hashlib.sha256(b"\x01" * 10).hexdigest()
    assert [(c.kind, c.result) for c in checks(session, evidence)] == [
        ("initial", "ok"),
        ("verify", "changed"),
    ]


def test_integrity_checks_are_append_only(session: Session, evidence: Evidence) -> None:
    evidence_service.hash_evidence(session, evidence.id)
    for stmt in ("UPDATE integrity_checks SET result = 'ok'", "DELETE FROM integrity_checks"):
        with pytest.raises(DatabaseError, match="append-only"):
            session.execute(text(stmt))
        session.rollback()


# ------------------------------------------------------------------------------- gate


def test_strict_mode_refuses_new_runs(
    session: Session, evidence: Evidence, monkeypatch: pytest.MonkeyPatch, mode
) -> None:  # noqa: ANN001
    mode("strict")
    install_fake_runner(monkeypatch)
    evidence_service.hash_evidence(session, evidence.id)
    integrity.set_expected_hashes(session, evidence.id, sha256="c" * 64)
    with pytest.raises(integrity.IntegrityError, match="does not match its expected SHA-256"):
        runs_service.create_run(session, evidence.id, ToolRequest(INFO))
    with pytest.raises(integrity.IntegrityError):
        runs_service.enqueue_auto(session, evidence.id)
    integrity.acknowledge_mismatch(session, evidence.id, "known")
    assert runs_service.create_run(session, evidence.id, ToolRequest(INFO)).id

    mode("warn")
    integrity.set_expected_hashes(session, evidence.id, sha256="d" * 64)
    assert runs_service.create_run(session, evidence.id, ToolRequest(INFO)).id


def test_worker_hashes_unhashed_image_first(
    session: Session, evidence: Evidence, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = run_to_completion(session, evidence, monkeypatch)
    assert run.status == RunStatus.SUCCEEDED, run.error
    assert (run.evidence_sha256, run.evidence_size_bytes) == (SHA256, 4096)
    assert run.integrity_warning is None and run.phase is None
    (check,) = checks(session, evidence)
    assert (check.kind, check.result, check.run_id) == ("initial", "ok", run.id)
    hash_event = next(e for e in session.scalars(select(AuditEvent)) if e.action == "evidence.hash")
    assert hash_event.origin == "worker"


def test_worker_rehashes_legacy_image_without_md5(
    session: Session, evidence: Evidence, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence.sha256, evidence.mtime = (
        SHA256,
        Path(evidence_service.resolve_evidence_path(evidence)).stat().st_mtime,
    )
    session.commit()
    run = run_to_completion(session, evidence, monkeypatch)
    assert run.status == RunStatus.SUCCEEDED
    session.refresh(evidence)
    assert evidence.md5 == MD5 and checks(session, evidence)[-1].kind == "rehash"


def test_changed_image_fails_in_strict_and_warns_in_warn_mode(
    session: Session, evidence: Evidence, image: Path, monkeypatch: pytest.MonkeyPatch, mode
) -> None:  # noqa: ANN001
    mode("strict")
    evidence_service.hash_evidence(session, evidence.id)
    install_fake_runner(monkeypatch)
    monkeypatch.setattr(worker_mod, "execute", make_fake_execute([{"Variable": "A"}]))
    run = runs_service.create_run(session, evidence.id, ToolRequest(INFO))
    image.write_bytes(b"\x02" * 100)  # changes after the run was queued
    run = wait_for_worker(session, run.id)
    assert run.status == RunStatus.FAILED
    assert "integrity check failed" in run.error and "changed since it was hashed" in run.error
    session.refresh(evidence)
    assert integrity.status(evidence) == integrity.CHANGED

    mode("warn")
    run = wait_for_worker(
        session, runs_service.create_run(session, evidence.id, ToolRequest(INFO)).id
    )
    assert run.status == RunStatus.SUCCEEDED
    assert "re-hashed" in run.integrity_warning
    assert run.evidence_sha256 == hashlib.sha256(b"\x02" * 100).hexdigest()


def test_verify_on_run_catches_same_size_content_change(
    session: Session, evidence: Evidence, image: Path, monkeypatch: pytest.MonkeyPatch, mode
) -> None:  # noqa: ANN001
    mode("strict", verify_on_run=True)
    evidence_service.hash_evidence(session, evidence.id)
    change_content_keep_stat(image)
    run = run_to_completion(session, evidence, monkeypatch)
    assert run.status == RunStatus.FAILED and "changed since it was hashed" in run.error
    session.refresh(evidence)
    assert evidence.sha256 == SHA256  # baseline kept in strict mode
    assert checks(session, evidence)[-1].kind == "pre_run"
    assert checks(session, evidence)[-1].result == "changed"


def test_verify_on_run_ok_and_mismatch_at_run_time(
    session: Session, evidence: Evidence, monkeypatch: pytest.MonkeyPatch, mode
) -> None:  # noqa: ANN001
    mode("strict", verify_on_run=True)
    run = run_to_completion(session, evidence, monkeypatch)
    assert run.status == RunStatus.SUCCEEDED
    run = run_to_completion(session, evidence, monkeypatch)
    assert [c.kind for c in checks(session, evidence)] == ["initial", "pre_run"]

    # Expected hash set after a run was queued: the worker catches it.
    mode("strict")
    install_fake_runner(monkeypatch)
    queued = runs_service.create_run(session, evidence.id, ToolRequest(INFO))
    integrity.set_expected_hashes(session, evidence.id, md5="0" * 32)
    run = wait_for_worker(session, queued.id)
    assert run.status == RunStatus.FAILED and "expected MD5" in run.error

    integrity.acknowledge_mismatch(session, evidence.id, "test image")
    run = run_to_completion(session, evidence, monkeypatch)
    assert run.status == RunStatus.SUCCEEDED
    assert run.integrity_warning == "hash mismatch acknowledged: test image"


def test_hook_follow_ups_respect_integrity(
    session: Session, evidence: Evidence, monkeypatch: pytest.MonkeyPatch, mode
) -> None:  # noqa: ANN001
    from app.models import ResultRow
    from app.tools import hooks
    from app.tools.hooks import HookSpec

    mode("strict")
    install_fake_runner(monkeypatch)
    evidence_service.hash_evidence(session, evidence.id)
    done = Run(evidence_id=evidence.id, plugin=INFO, status=RunStatus.SUCCEEDED, row_count=1)
    session.add(done)
    session.flush()
    session.add(ResultRow(run_id=done.id, row_idx=0, data={}))
    session.commit()
    integrity.set_expected_hashes(session, evidence.id, sha256="e" * 64)
    hooks.load_hooks()
    saved = dict(hooks._registry)
    try:
        hooks.register(
            HookSpec(
                name="follow",
                func=lambda ctx: ctx.queue_follow_up("windows.pslist.PsList", {"pid": [1]}),
                plugins=(INFO,),
            )
        )
        results = hooks.run_hooks(session, done.id)
    finally:
        hooks._registry.clear()
        hooks._registry.update(saved)
    follow = next(r for r in results if r["hook"] == "follow")
    assert follow["follow_ups_queued"] == []
    assert follow["follow_ups_skipped"][0]["skipped"].startswith("evidence integrity")


# ------------------------------------------------------------------------------- API / UI


def test_api(client: TestClient, session: Session, mode) -> None:  # noqa: ANN001
    mode("strict")
    client.post("/api/evidence/scan")
    ev_id = client.get("/api/evidence").json()[0]["id"]
    assert client.post(f"/api/evidence/{ev_id}/verify").status_code == 202
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not client.get(f"/api/evidence/{ev_id}").json()["md5"]:
        time.sleep(0.02)
    body = client.get(f"/api/evidence/{ev_id}").json()
    assert body["integrity_status"] == "hashed" and body["sha1"] == SHA1

    r = client.patch(f"/api/evidence/{ev_id}", json={"expected_md5": "nothex"})
    assert r.status_code == 422
    body = client.patch(f"/api/evidence/{ev_id}", json={"expected_md5": "1" * 32}).json()
    assert body["integrity_status"] == "mismatch" and "expected MD5" in body["integrity_problem"]
    r = client.post("/api/runs", json={"evidence_id": ev_id, "plugin": INFO})
    assert r.status_code == 409
    assert client.post(f"/api/evidence/{ev_id}/auto").status_code == 409
    r = client.post(f"/api/evidence/{ev_id}/acknowledge-mismatch", json={"reason": "ok"})
    assert r.json()["integrity_status"] == "mismatch_acknowledged"
    body = client.patch(f"/api/evidence/{ev_id}", json={"expected_md5": ""}).json()
    assert body["integrity_status"] == "hashed" and body["expected_md5"] is None
    history = client.get(f"/api/evidence/{ev_id}/integrity").json()
    assert history[0]["kind"] == "initial" and history[0]["sha256"] == SHA256


def test_ui(client: TestClient, session: Session, mode) -> None:  # noqa: ANN001
    mode("strict")
    client.post("/api/evidence/scan")
    ev_id = client.get("/api/evidence").json()[0]["id"]
    with db.SessionLocal() as s:
        evidence_service.hash_evidence(s, ev_id)

    page = client.get(f"/evidence/{ev_id}").text
    assert 'id="integrity"' in page and SHA256 in page and "Verify now" in page

    r = client.post(f"/ui/evidence/{ev_id}/expected-hashes", data={"expected_sha256": "zz"})
    assert r.status_code == 422 and "64 hex characters" in r.text
    r = client.post(
        f"/ui/evidence/{ev_id}/expected-hashes",
        data={"expected_sha256": "f" * 64},
        follow_redirects=False,
    )
    assert r.status_code == 303
    page = client.get(f"/evidence/{ev_id}").text
    assert "HASH MISMATCH" in page and "New runs are blocked" in page
    assert "Acknowledge and allow runs" in page
    r = client.post(
        f"/ui/evidence/{ev_id}/runs",
        data={"plugin": INFO},
        headers={"HX-Request": "true"},
    )
    assert "does not match its expected SHA-256" in r.text
    assert "HASH MISMATCH" in client.get("/").text

    client.post(f"/ui/evidence/{ev_id}/acknowledge", data={"reason": "lab copy"})
    page = client.get(f"/evidence/{ev_id}").text
    assert "mismatch (acknowledged)" in page and "lab copy" in page


def test_migration_backfills_existing_hashes(settings: Settings) -> None:
    engine = create_engine(f"sqlite:///{settings.data_dir / 'upgrade.db'}")
    cfg = db.alembic_config()
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "0003_audit")
        conn.execute(
            text(
                "INSERT INTO evidence (id, rel_path, size_bytes, mtime, sha256, description, "
                "created_at) VALUES (3, 'old.raw', 10, 1.5, :h, '', '2026-01-01 00:00:00')"
            ),
            {"h": SHA256},
        )
    db.migrate(engine)
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT evidence_id, kind, result, sha256 FROM integrity_checks")
        ).one()
    assert tuple(row) == (3, "initial", "ok", SHA256)
