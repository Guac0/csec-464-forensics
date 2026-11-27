"""Audit log: chain integrity, append-only enforcement, levels, request logging, and a coverage
matrix checking that every state-changing action records an event."""

from __future__ import annotations

import sqlite3
import threading
import time
from typing import Any

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import DatabaseError
from sqlalchemy.orm import Session

from app import db
from app.ai import service as ai_service
from app.ai.client import AIClient
from app.config import Settings, get_settings
from app.models import AuditEvent, AuditHead, Evidence, NoteVersion, ResultRow, Run, RunStatus
from app.services import audit
from app.services import evidence as evidence_service
from tests.test_ai_helpers import mock_transport, respond_with
from tests.test_backend_fakes import install_fake_runner

HX = {"HX-Request": "true"}


def events(session: Session, **filters: Any) -> list[AuditEvent]:
    session.expire_all()
    stmt = select(AuditEvent).order_by(AuditEvent.seq)
    for key, value in filters.items():
        stmt = stmt.where(getattr(AuditEvent, key) == value)
    return list(session.scalars(stmt))


def actions(session: Session, category: str | None = None) -> list[str]:
    return [e.action for e in events(session) if category is None or e.category == category]


def raw(settings: Settings) -> sqlite3.Connection:
    """A plain sqlite3 connection (as an attacker editing the DB file would have)."""
    return sqlite3.connect(settings.data_dir / "forensics.db")


@pytest.fixture
def level(monkeypatch: pytest.MonkeyPatch):
    def set_level(value: str) -> None:
        monkeypatch.setenv("FT_AUDIT_LEVEL", value)
        get_settings.cache_clear()

    return set_level


# ------------------------------------------------------------------------------- chain


def test_record_builds_a_valid_chain(session: Session) -> None:
    for i in range(5):
        audit.record(session, "test.event", summary=f"event {i}", details={"i": i, "x": [1.5]})
    session.commit()
    evs = events(session)
    assert [e.seq for e in evs] == [1, 2, 3, 4, 5]
    assert evs[0].prev_hash == audit.GENESIS_HASH
    assert all(b.prev_hash == a.hash for a, b in zip(evs, evs[1:], strict=False))
    report = audit.verify_chain(session)
    assert report.ok and report.events == 5 and report.head_hash == evs[-1].hash


def test_rolled_back_actions_leave_no_event(session: Session) -> None:
    audit.record(session, "kept")
    session.commit()
    audit.record(session, "discarded")
    session.rollback()
    assert actions(session) == ["kept"]
    assert session.get(AuditHead, 1).seq == 1
    assert audit.verify_chain(session).ok


def test_concurrent_writers_keep_the_chain_linear(session: Session) -> None:
    errors: list[BaseException] = []

    def writer(n: int) -> None:
        try:
            for i in range(20):
                with db.SessionLocal() as s:
                    audit.record(s, "test.concurrent", details={"writer": n, "i": i})
                    s.commit()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    report = audit.verify_chain(session)
    assert report.ok and report.events == 120


def test_append_only_triggers(session: Session, settings: Settings) -> None:
    audit.record(session, "x")
    session.commit()
    with pytest.raises(DatabaseError, match="append-only"):
        session.execute(text("UPDATE audit_events SET summary = 'changed'"))
    session.rollback()
    with pytest.raises(DatabaseError, match="append-only"):
        session.execute(text("DELETE FROM audit_events"))
    session.rollback()
    with pytest.raises(DatabaseError, match="must not be deleted"):
        session.execute(text("DELETE FROM audit_head"))
    session.rollback()
    session.add(
        NoteVersion(note_id=1, version=1, action="create", body="b", evidence_id=None, actor="t")
    )
    session.commit()
    for stmt in ("UPDATE note_versions SET body = 'x'", "DELETE FROM note_versions"):
        with pytest.raises(DatabaseError, match="append-only"):
            session.execute(text(stmt))
        session.rollback()
    triggers = {
        r[0] for r in raw(settings).execute("SELECT name FROM sqlite_master WHERE type='trigger'")
    }
    assert {
        "audit_events_no_update",
        "audit_events_no_delete",
        "note_versions_no_update",
        "note_versions_no_delete",
        "audit_head_no_delete",
    } <= triggers


def _tamper(settings: Settings, *sql: str) -> None:
    """Edit the DB file directly, bypassing the triggers (what verification must catch)."""
    con = raw(settings)
    con.execute("DROP TRIGGER audit_events_no_update")
    con.execute("DROP TRIGGER audit_events_no_delete")
    for stmt in sql:
        con.execute(stmt)
    con.commit()
    con.close()


@pytest.mark.parametrize(
    ("sql", "bad_seq", "error"),
    [
        (("UPDATE audit_events SET summary = 'innocent' WHERE seq = 2",), 2, "content"),
        (("DELETE FROM audit_events WHERE seq = 2",), 3, "sequence gap"),
        (("UPDATE audit_events SET prev_hash = hash WHERE seq = 3",), 3, "prev_hash"),
        (("DELETE FROM audit_events WHERE seq = 4",), None, "truncated"),
    ],
)
def test_tampering_is_detected(
    session: Session, settings: Settings, sql: tuple[str, ...], bad_seq: int | None, error: str
) -> None:
    for i in range(4):
        audit.record(session, "test.event", summary=f"event {i}")
    session.commit()
    _tamper(settings, *sql)
    report = audit.verify_chain(session)
    assert not report.ok and report.bad_seq == bad_seq and error in report.error


# ------------------------------------------------------------------------------- levels


def test_levels_filter_categories(session: Session, level) -> None:  # noqa: ANN001
    level("changes")
    assert audit.record(session, "c") is not None
    assert audit.record(session, "k", category=audit.KEY_READ) is None
    level("key_reads")
    assert audit.record(session, "k", category=audit.KEY_READ) is not None
    assert audit.record(session, "r", category=audit.REQUEST) is None
    level("all")
    assert audit.record(session, "r", category=audit.REQUEST) is not None
    with pytest.raises(ValueError):
        audit.record(session, "x", category="bogus")


def test_default_level_is_all_for_now(settings: Settings) -> None:
    assert settings.audit_level == "all"


# ------------------------------------------------------------------------------- requests


def test_requests_are_logged_with_context(client: TestClient, session: Session, level) -> None:  # noqa: ANN001
    client.get("/api/evidence", params={"x": "1"})
    client.get("/static/style.css")
    client.get("/health")
    client.post("/api/evidence/scan")
    reqs = [e for e in events(session) if e.action == "http.request"]
    paths = [(e.details["method"], e.details["path"]) for e in reqs]
    assert ("GET", "/api/evidence") in paths and ("POST", "/api/evidence/scan") in paths
    assert not any(p.startswith(("/static", "/health")) for _, p in paths)
    get_ev = next(e for e in reqs if e.details["path"] == "/api/evidence")
    assert get_ev.origin == "api" and get_ev.details["status"] == 200
    assert get_ev.details["query"] == "x=1" and get_ev.category == "request"
    # The semantic event and the request event of the same request share a request id.
    scan = events(session, action="evidence.scan")[0]
    scan_req = next(e for e in reqs if e.details["path"] == "/api/evidence/scan")
    assert scan.request_id == scan_req.request_id and scan.origin == "api"

    level("key_reads")
    before = len(events(session))
    client.get("/api/evidence")
    assert len(events(session)) == before


# ------------------------------------------------------------------------------- coverage


def test_every_state_change_is_audited(
    client: TestClient,
    session: Session,
    monkeypatch: pytest.MonkeyPatch,
    level,  # noqa: ANN001
) -> None:
    level("changes")  # semantic events only, to keep the assertions readable
    install_fake_runner(monkeypatch)
    monkeypatch.setattr(
        ai_service,
        "AIClient",
        lambda settings: AIClient(settings, transport=mock_transport(respond_with("ok [R1:0]"))),
    )

    client.post("/api/evidence/scan")
    ev_id = client.get("/api/evidence").json()[0]["id"]
    client.patch(f"/api/evidence/{ev_id}", json={"description": "laptop RAM"})
    with db.SessionLocal() as s:
        evidence_service.hash_evidence(s, ev_id)
    run = client.post("/api/runs", json={"evidence_id": ev_id, "plugin": "windows.info.Info"})
    run_id = run.json()["id"]
    client.post(f"/api/runs/{run_id}/cancel")
    client.post(f"/api/evidence/{ev_id}/auto")
    note_id = client.post("/api/notes", json={"body": "first", "evidence_id": ev_id}).json()["id"]
    client.patch(f"/api/notes/{note_id}", json={"body": "second"})
    client.delete(f"/api/notes/{note_id}")
    # A succeeded run so AI and hooks have something to work on.
    with db.SessionLocal() as s:
        done = Run(evidence_id=ev_id, plugin="windows.info.Info", status=RunStatus.SUCCEEDED)
        done.row_count = 1
        s.add(done)
        s.flush()
        s.add(ResultRow(run_id=done.id, row_idx=0, data={"Variable": "A", "Value": "1"}))
        s.commit()
        done_id = done.id
    client.post(f"/api/runs/{done_id}/hooks/rerun")
    client.post("/api/ai/ask", json={"evidence_id": ev_id, "question": "anything?"})
    client.post(f"/api/ai/summarize/{done_id}")
    client.get("/api/audit/verify")  # key_read: not recorded at level "changes"

    recorded = set(actions(session))
    expected = {
        "app.start",
        "evidence.register",
        "evidence.scan",
        "evidence.describe",
        "evidence.hash",
        "run.create",
        "run.cancel",
        "evidence.auto_enumerate",
        "note.create",
        "note.edit",
        "note.delete",
        "hooks.run",
        "ai.ask.request",
        "ai.ask.response",
        "ai.summarize.request",
        "ai.summarize.response",
    }
    assert expected <= recorded, expected - recorded
    assert "audit.verify" not in recorded

    describe = events(session, action="evidence.describe")[0]
    assert describe.details == {"before": "", "after": "laptop RAM"}
    assert describe.evidence_id == ev_id and describe.origin == "api"
    assert audit.verify_chain(session).ok


def test_worker_and_restart_events(
    session: Session, monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    from app.jobs import worker as worker_mod
    from app.services import runs as runs_service
    from app.tools.base import ToolRequest
    from tests.test_backend_fakes import make_fake_execute

    install_fake_runner(monkeypatch)
    (ev,) = evidence_service.scan_evidence(session)
    monkeypatch.setattr(worker_mod, "execute", make_fake_execute([{"PID": 4}]))
    run = runs_service.create_run(session, ev.id, ToolRequest("windows.info.Info"))
    w = worker_mod.Worker(poll_interval=0.02)
    w.start()
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not events(session, action="run.finish"):
            time.sleep(0.02)
    finally:
        w.stop()
    start, finish = events(session, action="run.start")[0], events(session, action="run.finish")[0]
    assert start.origin == finish.origin == "worker" and finish.object_id == run.id
    assert finish.details["status"] == "succeeded" and finish.details["row_count"] == 1
    assert finish.details["argv"][-1] == "windows.info.Info"

    stale = runs_service.create_run(session, ev.id, ToolRequest("windows.info.Info"))
    stale.status = RunStatus.RUNNING
    session.commit()
    worker_mod.recover_interrupted_runs(session)
    (interrupted,) = events(session, action="run.interrupted")
    assert interrupted.object_id == stale.id


def test_background_hash_keeps_request_origin(client: TestClient, session: Session) -> None:
    client.post("/api/evidence/scan")
    ev_id = client.get("/api/evidence").json()[0]["id"]
    client.post(f"/api/evidence/{ev_id}/hash")
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not events(session, action="evidence.hash"):
        time.sleep(0.02)
    (hashed,) = events(session, action="evidence.hash")
    assert hashed.origin == "api" and hashed.request_id
    assert hashed.details["sha256"] == session.get(Evidence, ev_id).sha256


# ------------------------------------------------------------------------------- notes


def test_note_versions_and_history(client: TestClient, session: Session) -> None:
    note_id = client.post("/api/notes", json={"body": "v1"}).json()["id"]
    client.patch(f"/api/notes/{note_id}", json={"body": "v2 <b>bold</b>"})
    client.delete(f"/api/notes/{note_id}")

    versions = client.get(f"/api/notes/{note_id}/versions").json()
    assert [(v["version"], v["action"], v["body"]) for v in versions] == [
        (1, "create", "v1"),
        (2, "edit", "v2 <b>bold</b>"),
        (3, "delete", "v2 <b>bold</b>"),
    ]
    edit = events(session, action="note.edit")[0]
    import hashlib

    assert edit.details["body_sha256"] == hashlib.sha256(b"v2 <b>bold</b>").hexdigest()
    assert edit.details["previous_body_sha256"] == hashlib.sha256(b"v1").hexdigest()

    page = client.get(f"/notes/{note_id}/history").text
    assert "Version 3" in page and "v2 &lt;b&gt;bold&lt;/b&gt;" in page
    assert client.get("/api/notes/999/versions").status_code == 404


def test_existing_notes_get_a_first_version_on_upgrade(settings: Settings) -> None:
    engine = create_engine(f"sqlite:///{settings.data_dir / 'upgrade.db'}")
    cfg = db.alembic_config()
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "0002_hooks")
        conn.execute(
            text(
                "INSERT INTO notes (id, body, created_at, updated_at) "
                "VALUES (7, 'old note', '2026-01-01 00:00:00', '2026-01-01 00:00:00')"
            )
        )
    db.migrate(engine)
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT note_id, version, action, body FROM note_versions"))
        assert rows.all() == [(7, 1, "create", "old note")]
        assert conn.execute(text("SELECT seq, last_hash FROM audit_head")).one() == (
            0,
            audit.GENESIS_HASH,
        )


# ------------------------------------------------------------------------------- API / UI


def test_audit_api_and_activity_page(client: TestClient, session: Session) -> None:
    client.post("/api/notes", json={"body": "hello"})
    page = client.get("/api/audit", params={"action": "note.", "limit": 5}).json()
    assert page["total"] == 1 and page["events"][0]["action"] == "note.create"
    assert client.get("/api/audit", params={"category": "change"}).json()["total"] >= 2

    report = client.get("/api/audit/verify").json()
    assert report["ok"] is True
    assert events(session, action="audit.verify")[0].category == "key_read"

    html = client.get("/activity", params={"category": "change"}).text
    assert "Activity log" in html and "note.create" in html and "http.request" not in html
    verified = client.post("/ui/audit/verify").text
    assert "Integrity verified" in verified

    # Evidence-controlled text in summaries is escaped.
    audit.record(session, "test.xss", summary="<script>alert(1)</script>")
    session.commit()
    assert "&lt;script&gt;" in client.get("/activity").text


def test_activity_page_reports_broken_chain(
    client: TestClient, session: Session, settings: Settings
) -> None:
    client.post("/api/notes", json={"body": "hello"})
    _tamper(settings, "UPDATE audit_events SET summary = 'x' WHERE seq = 1")
    html = client.post("/ui/audit/verify").text
    assert "Integrity check FAILED at event #1" in html
