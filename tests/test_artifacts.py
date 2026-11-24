"""Derived artifacts: registration, hashing, typing, row linking, size limit, hooks access,
downloads (encrypted zip / raw), integrity re-check, audit and UI."""

from __future__ import annotations

import hashlib
import io
import time
from pathlib import Path

import pytest
import pyzipper
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.jobs.worker import Worker
from app.models import AuditEvent, DerivedArtifact, Evidence, Run, RunStatus
from app.services import artifacts
from app.services import evidence as evidence_service
from app.services import runs as runs_service
from app.tools import executor, hooks
from app.tools.base import ToolRequest
from app.tools.hooks import HookContext, HookSpec

FAKE_VOL = Path(__file__).parent / "fixtures" / "fake_vol.py"
PSLIST = "windows.pslist.PsList"


@pytest.fixture
def real_vol(settings: Settings, monkeypatch: pytest.MonkeyPatch):
    """Use the real registry/runner/executor with fake_vol.py in place of `vol`."""
    if not FAKE_VOL.stat().st_mode & 0o111:
        FAKE_VOL.chmod(0o755)
    monkeypatch.setenv("FT_VOL_EXECUTABLE", str(FAKE_VOL))

    def set_mode(mode: str, **env: str) -> None:
        monkeypatch.setenv("FAKE_VOL_MODE", mode)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        get_settings.cache_clear()

    set_mode("dump")
    return set_mode


@pytest.fixture
def evidence(session: Session) -> Evidence:
    (ev,) = evidence_service.scan_evidence(session)
    return ev


def run_and_wait(session: Session, evidence: Evidence, args: dict | None = None) -> Run:
    run = runs_service.create_run(session, evidence.id, ToolRequest(PSLIST, args or {"dump": True}))
    w = Worker(poll_interval=0.02)
    w.start()
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            session.expire_all()
            run = session.get(Run, run.id)
            if run.status not in (RunStatus.QUEUED, RunStatus.RUNNING) and run.phase is None:
                return run
            time.sleep(0.05)
    finally:
        w.stop()
    raise AssertionError("run did not finish")


# ------------------------------------------------------------------------------- unit


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (b"MZ" + bytes(58) + (64).to_bytes(4, "little") + b"PE\0\0" + bytes(18) + b"\x02\x01",
         "PE executable"),
        (b"MZ" + bytes(58) + (64).to_bytes(4, "little") + b"PE\0\0" + bytes(18) + b"\x02\x21",
         "PE DLL"),
        (b"MZ" + bytes(100), "MZ executable"),
        (b"\x7fELF\x02\x01", "ELF executable"),
        (b"PK\x03\x04rest", "ZIP archive"),
        (b"regf" + bytes(10), "Windows registry hive"),
        (b"hello world\n", "text"),
        (b"\xff\xfe\x00\x81\x82", "data"),
        (b"", "empty"),
    ],
)  # fmt: skip
def test_guess_file_type(tmp_path: Path, content: bytes, expected: str) -> None:
    f = tmp_path / "x"
    f.write_bytes(content)
    assert artifacts.guess_file_type(f) == expected


def test_dir_size_ignores_symlinks(tmp_path: Path) -> None:
    (tmp_path / "a").write_bytes(b"x" * 10)
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b").write_bytes(b"x" * 5)
    (tmp_path / "link").symlink_to(tmp_path / "a")
    assert executor.dir_size(tmp_path) == 15


# ------------------------------------------------------------------------------- worker


def test_dumped_files_are_registered_hashed_and_linked(
    session: Session, evidence: Evidence, real_vol
) -> None:  # noqa: ANN001
    seen: dict[str, list] = {}
    hooks.load_hooks()
    saved = dict(hooks._registry)

    def look(ctx: HookContext) -> None:
        seen["artifacts"] = ctx.artifacts()

    hooks.register(HookSpec(name="look", func=look, plugins=(PSLIST,)))
    try:
        run = run_and_wait(session, evidence)
    finally:
        hooks._registry.clear()
        hooks._registry.update(saved)

    assert run.status == RunStatus.SUCCEEDED, run.error
    assert "--dump" in run.argv
    arts = artifacts.list_for_run(session, run.id)
    assert [a.filename for a in arts] == ["pid.101.0x1000.dmp", "pid.4.0x1000.dmp"]
    content = b"MZ" + bytes(62) + b"fake process 4"
    a4 = arts[1]
    assert a4.sha256 == hashlib.sha256(content).hexdigest()
    assert a4.md5 == hashlib.md5(content).hexdigest()  # noqa: S324
    assert a4.size_bytes == len(content) and a4.file_type == "MZ executable"
    assert (a4.source_row_idx, arts[0].source_row_idx) == (0, 1)  # rows naming the files
    assert run.artifact_count == 2
    assert [a.filename for a in seen["artifacts"]] == [a.filename for a in arts]
    (event,) = session.scalars(select(AuditEvent).where(AuditEvent.action == "artifacts.register"))
    assert event.object_id == run.id and len(event.details["files"]) == 2

    # Registration is idempotent.
    assert artifacts.register_run_outputs(session, run, Path(arts[0].rel_path).parent) == []


def test_files_from_failed_runs_are_kept(
    session: Session, evidence: Evidence, real_vol, settings: Settings
) -> None:  # noqa: ANN001
    real_vol("flood", FT_MAX_ARTIFACT_BYTES=str(256 * 1024))
    run = run_and_wait(session, evidence)
    assert run.status == RunStatus.FAILED
    assert "exceeded the per-run limit of 262144 bytes" in run.error
    (flood,) = artifacts.list_for_run(session, run.id)
    assert flood.filename == "flood.bin" and flood.size_bytes > 256 * 1024
    assert flood.source_row_idx is None


def test_artifact_path_cannot_escape(session: Session, evidence: Evidence) -> None:
    bad = DerivedArtifact(
        run_id=1, evidence_id=evidence.id, rel_path="runs/1/output/../../../etc/passwd",
        filename="x", size_bytes=0, sha256="", md5="", sha1="",
    )  # fmt: skip
    with pytest.raises(ValueError, match="escapes"):
        artifacts.artifact_path(bad)


# ------------------------------------------------------------------------------- downloads


def test_downloads(
    client: TestClient, session: Session, evidence: Evidence, real_vol, settings: Settings
) -> None:  # noqa: ANN001
    run = run_and_wait(session, evidence)
    arts = client.get(f"/api/runs/{run.id}/artifacts").json()
    a = next(x for x in arts if x["filename"] == "pid.4.0x1000.dmp")
    content = b"MZ" + bytes(62) + b"fake process 4"

    r = client.get(f"/api/artifacts/{a['id']}/download")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/octet-stream"
    assert "pid.4.0x1000.dmp.zip" in r.headers["content-disposition"]
    assert r.headers["x-content-type-options"] == "nosniff"
    with pyzipper.AESZipFile(io.BytesIO(r.content)) as zf:
        with pytest.raises(RuntimeError):
            zf.read("pid.4.0x1000.dmp")  # encrypted: no password, no content
        zf.setpassword(b"infected")
        assert zf.read("pid.4.0x1000.dmp") == content
    assert not list((settings.data_dir / "tmp").iterdir())  # temp zip cleaned up

    raw = client.get(f"/ui/artifacts/{a['id']}/download", params={"format": "raw"})
    assert raw.status_code == 200 and raw.content == content

    events = list(
        session.scalars(select(AuditEvent).where(AuditEvent.action == "artifact.download"))
    )
    assert [(e.category, e.details["format"]) for e in events] == [
        ("key_read", "zip"),
        ("key_read", "raw"),
    ]

    # Tampered file: refused and recorded.
    (settings.data_dir / f"runs/{run.id}/output/pid.4.0x1000.dmp").write_bytes(b"MZ evil")
    r = client.get(f"/api/artifacts/{a['id']}/download")
    assert r.status_code == 409 and "no longer matches" in r.json()["detail"]
    assert session.scalars(
        select(AuditEvent).where(AuditEvent.action == "artifact.download_refused")
    ).first()
    assert client.get("/api/artifacts/999/download").status_code == 404
    assert client.get(f"/api/artifacts/{a['id']}/download?format=exe").status_code == 422


def test_run_page_and_runs_list(
    client: TestClient, session: Session, evidence: Evidence, real_vol
) -> None:  # noqa: ANN001
    run = run_and_wait(session, evidence)
    page = client.get(f"/runs/{run.id}").text
    assert "Dumped files (2)" in page and "may be live malware" in page
    assert "Encrypted zip" in page and "Download raw file anyway" in page
    assert 'href="#artifact-' in page  # File column in the results table
    runs = client.get(f"/ui/evidence/{evidence.id}/runs", headers={"HX-Request": "true"}).text
    assert "2 files" in runs
    assert client.get(f"/api/runs/{run.id}").json()["artifact_count"] == 2


def test_ai_context_lists_dumped_files(session: Session, evidence: Evidence, real_vol) -> None:  # noqa: ANN001
    from app.ai.context import build_context

    run = run_and_wait(session, evidence)
    text, _ = build_context(session, evidence.id)
    assert "dumped files: pid.101.0x1000.dmp (MZ executable" in text
    assert f"row R{run.id}:0" in text
