"""Backups: create, list, verify, restore, schedule, prune, audit anchor, UI and CLI."""

from __future__ import annotations

import json
import time
import zipfile
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import db
from app.backup import main as cli
from app.config import Settings, get_settings
from app.models import AuditEvent, DerivedArtifact, Evidence, Note, Run, RunStatus
from app.services import artifacts, backup, health, notes
from app.services import evidence as evidence_service


@pytest.fixture
def evidence(session: Session) -> Evidence:
    (ev,) = evidence_service.scan_evidence(session)
    return ev


def _run_with_files(session: Session, settings: Settings, evidence: Evidence, status=None) -> Run:
    run = Run(
        evidence_id=evidence.id,
        plugin="windows.pslist.PsList",
        status=status or RunStatus.SUCCEEDED,
    )
    session.add(run)
    session.flush()
    run_dir = settings.runs_dir / str(run.id)
    (run_dir / "output").mkdir(parents=True)
    (run_dir / "stdout.jsonl").write_text('{"PID": 4}\n')
    (run_dir / "stderr.txt").write_text("")
    (run_dir / "output" / "pid.4.dmp").write_bytes(b"MZ" * 100)
    artifacts.register_run_outputs(session, run, run_dir / "output")
    session.commit()
    return run


def test_create_list_verify(session: Session, settings: Settings, evidence: Evidence) -> None:
    run = _run_with_files(session, settings, evidence)
    active = _run_with_files(session, settings, evidence, RunStatus.RUNNING)
    info = backup.create_backup("manual")
    assert info.path.parent == settings.backup_dir and info.trigger == "manual"
    assert [b.name for b in backup.list_backups()] == [info.name]

    with zipfile.ZipFile(info.path) as zf:
        names = set(zf.namelist())
        manifest = json.loads(zf.read("manifest.json"))
    assert {"forensics.db", "manifest.json", f"runs/{run.id}/stdout.jsonl"} <= names
    assert not any("output" in n for n in names)  # dumped files are not backed up
    assert f"runs/{active.id}/stdout.jsonl" not in names  # still being written
    assert manifest["excluded"] == {
        "dumped_files": 2,
        "dumped_bytes": 400,
        "active_runs": [active.id],
    }
    assert manifest["audit_chain"]["ok"] and manifest["schema"].startswith("0008")

    report = backup.verify_backup(info.name)
    assert report.ok, report.problems
    assert report.files == len(manifest["files"]) and report.audit_events > 0

    anchor = backup.last_anchor()
    assert anchor["backup"] == info.name
    assert anchor["head_hash"] == manifest["audit_chain"]["head_hash"]
    (event,) = session.scalars(select(AuditEvent).where(AuditEvent.action == "backup.create"))
    assert event.details["backup"] == info.name and event.details["dumped_files_excluded"] == 2

    # Two backups in the same second get different names.
    second = backup.create_backup("cli")
    assert second.name != info.name and len(backup.list_backups()) == 2


def test_verify_detects_tampering(session: Session, settings: Settings) -> None:
    info = backup.create_backup("manual")
    tampered = settings.backup_dir / "forensics-backup-20200101T000000Z-manual.zip"
    with zipfile.ZipFile(info.path) as src, zipfile.ZipFile(tampered, "w") as dst:
        for name in src.namelist():
            data = src.read(name)
            if name == "manifest.json":
                manifest = json.loads(data)
                manifest["files"][0]["sha256"] = "0" * 64
                data = json.dumps(manifest).encode()
            dst.writestr(name, data)
    report = backup.verify_backup(tampered.name)
    assert not report.ok and "forensics.db: SHA-256 does not match" in report.problems[0]
    (settings.backup_dir / "forensics-backup-20200102T000000Z-manual.zip").write_text("junk")
    assert (
        "not a readable ZIP"
        in backup.verify_backup("forensics-backup-20200102T000000Z-manual.zip").problems[0]
    )
    with pytest.raises(LookupError):
        backup.verify_backup("nope.zip")


def test_restore(session: Session, settings: Settings, evidence: Evidence) -> None:
    run = _run_with_files(session, settings, evidence)
    notes.create_note(session, "before backup", evidence_id=evidence.id)
    info = backup.create_backup("manual")
    notes.create_note(session, "after backup", evidence_id=evidence.id)
    (settings.runs_dir / str(run.id) / "stdout.jsonl").write_text("changed later\n")
    session.close()

    assert backup.hold_app_lock()
    try:
        with pytest.raises(backup.BackupError, match="stop it before restoring"):
            backup.restore_backup(info.name)
    finally:
        backup.release_app_lock()

    report = backup.restore_backup(info.name)
    assert report.moved_aside_to and Path(report.moved_aside_to).is_dir()
    assert (Path(report.moved_aside_to) / "forensics.db").is_file()
    assert (report.dumped_ok, report.dumped_missing, report.dumped_mismatch) == (1, 0, 0)
    assert (settings.runs_dir / str(run.id) / "stdout.jsonl").read_text() == '{"PID": 4}\n'
    with db.SessionLocal() as s:
        assert [n.body for n in s.scalars(select(Note))] == ["before backup"]
        (event,) = s.scalars(select(AuditEvent).where(AuditEvent.action == "backup.restore"))
        assert event.details["backup"] == info.name
        assert s.scalar(select(DerivedArtifact.filename)) == "pid.4.dmp"


def test_restore_refuses_bad_backup(settings: Settings, session: Session) -> None:
    bad = settings.backup_dir / "forensics-backup-20200101T000000Z-manual.zip"
    settings.backup_dir.mkdir(parents=True, exist_ok=True)
    bad.write_text("junk")
    with pytest.raises(backup.BackupError, match="failed verification"):
        backup.restore_backup(bad.name)


def test_schedule_and_prune(
    session: Session, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FT_BACKUP_KEEP", "2")
    get_settings.cache_clear()
    sched = backup.BackupScheduler()
    assert sched.due()
    assert sched.run_once() is not None
    assert not sched.due()  # newest is fresh
    later = backup.list_backups()[0].created_at + timedelta(hours=25)
    assert sched.due(now=later)
    for _ in range(2):
        backup.create_backup("scheduled")
    manual = backup.create_backup("manual")
    kept = backup.list_backups()
    assert [b.trigger for b in kept].count("scheduled") == 2
    assert manual.name in [b.name for b in kept]
    assert session.scalars(select(AuditEvent).where(AuditEvent.action == "backup.prune")).all()

    monkeypatch.setenv("FT_BACKUP_INTERVAL_HOURS", "0")
    get_settings.cache_clear()
    assert not backup.BackupScheduler().due()


def test_failed_backup_is_reported(
    session: Session, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(backup, "estimate_size", lambda settings=None: 1024**5)
    with pytest.raises(backup.BackupError, match="not enough space"):
        backup.create_backup("manual")
    assert session.scalars(select(AuditEvent).where(AuditEvent.action == "backup.failed")).all()
    sched = backup.BackupScheduler()
    assert sched.run_once() is None and "not enough space" in sched.last_error
    assert not sched.due()  # waits before retrying


def test_health_check_and_anchor(session: Session, settings: Settings, evidence: Evidence) -> None:
    check = health.check_backups(session, settings)
    assert check.status == "warn" and check.summary == "No backup yet."
    backup.create_backup("manual")
    check = health.check_backups(session, settings)
    assert check.status == "ok" and dict(check.details)["Audit anchor"].endswith("matches")

    anchors = settings.backup_dir / backup.ANCHORS
    entry = json.loads(anchors.read_text().splitlines()[-1])
    entry["head_hash"] = "f" * 64  # as if the DB's chain had been rebuilt since
    anchors.write_text(anchors.read_text() + json.dumps(entry) + "\n")
    check = health.check_backups(session, settings)
    assert check.status == "fail" and "no longer contains the event anchored" in check.summary


def test_ui_and_api(client: TestClient, settings: Settings) -> None:
    page = client.get("/system").text
    assert "Back up now" in page and "No backups yet." in page
    r = client.post("/ui/system/backup", headers={"HX-Request": "true"})
    assert r.status_code == 200 and 'id="backup-status"' in r.text
    deadline = time.monotonic() + 10
    while backup.manual_state()["running"] and time.monotonic() < deadline:
        time.sleep(0.05)
    state = backup.manual_state()
    assert state["result"] and not state["error"]
    assert state["result"] in client.get("/ui/system/backup-status").text

    data = client.get("/api/system/backups").json()
    assert data["backups"][0]["name"] == state["result"]
    r = client.post(f"/ui/system/backups/{state['result']}/verify", headers={"HX-Request": "true"})
    assert "verified" in r.text
    assert client.post(f"/api/system/backups/{state['result']}/verify").json()["ok"]
    assert client.post("/api/system/backups/nope.zip/verify").status_code == 404
    assert state["result"] in client.get("/system").text


def test_cli(session: Session, settings: Settings, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli(["list"]) == 0 and "no backups" in capsys.readouterr().out
    assert cli(["create"]) == 0
    name = backup.list_backups()[0].name
    assert name.endswith("-cli.zip")
    assert cli(["verify", name]) == 0 and "OK" in capsys.readouterr().out
    assert cli(["verify", "missing.zip"]) == 2
    session.close()
    assert cli(["restore", name, "--yes"]) == 0
    assert "restored" in capsys.readouterr().out
