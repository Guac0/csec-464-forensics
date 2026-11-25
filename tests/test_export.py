"""Case export: escaping, report content and scope, golden file, ZIP bundle + manifest,
encrypted dumped files, API/UI and audit."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
import pyzipper
from fastapi.testclient import TestClient
from markdown_it import MarkdownIt
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai import service as ai_service
from app.ai.client import AIClient
from app.config import Settings, get_settings
from app.models import AuditEvent, DerivedArtifact, Evidence, Run, RunStatus
from app.services import audit, export, integrity, results
from app.services import evidence as evidence_service
from app.services import notes as notes_service
from app.tools.base import ParsedRow

GOLDEN = Path(__file__).parent / "fixtures" / "export_golden.md"
WHEN = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
EVIL = "<script>alert(1)</script> | `tick` ``` *bold* [link](http://x) # head"


# ------------------------------------------------------------------------------- fixtures


def _ai_client(content: str) -> AIClient:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "model": body["model"],
                "choices": [{"message": {"role": "assistant", "content": content}}],
                "usage": {"total_tokens": 42},
            },
        )

    return AIClient(get_settings(), transport=httpx.MockTransport(handler))


@pytest.fixture
def case(session: Session, settings: Settings) -> dict:
    """Two evidence items with notes, a run (rows, findings, dumped file, raw output), AI."""
    (settings.evidence_dir / "other.raw").write_bytes(b"\1" * 10)
    evs = evidence_service.scan_evidence(session)
    ev = next(e for e in evs if e.rel_path == "sample.raw")
    other = next(e for e in evs if e.rel_path == "other.raw")
    evidence_service.update_description(session, ev.id, f"Laptop {EVIL}")
    evidence_service.hash_evidence(session, ev.id)
    integrity.set_expected_hashes(session, ev.id, md5="0" * 32)
    notes_service.create_note(session, f"Analyst note {EVIL}", evidence_id=ev.id)
    notes_service.create_note(session, "Global note", evidence_id=None)
    notes_service.create_note(session, "Note on the other image", evidence_id=other.id)

    run = Run(
        evidence_id=ev.id,
        plugin="windows.pslist.PsList",
        args={"pid": [4]},
        status=RunStatus.SUCCEEDED,
        tool_version="2.28.2",
        argv=["vol", "-f", "/evidence/sample.raw", "windows.pslist.PsList", "--pid", "4"],
        evidence_sha256=ev.sha256,
        evidence_size_bytes=ev.size_bytes,
        findings=[
            {"hook": "h", "title": f"Odd {EVIL}", "detail": "d", "severity": "high", "rows": [1]}
        ],
    )
    session.add(run)
    session.flush()
    rows = [{"PID": 4, "Name": "System"}, {"PID": 666, "Name": f"=evil {EVIL}"}]
    run.row_count = results.store_rows(
        session, run.id, (ParsedRow(data=r) for r in rows), search_index=False
    )
    run_dir = settings.data_dir / "runs" / str(run.id)
    (run_dir / "output").mkdir(parents=True)
    raw = b'\n{"PID": 4}\n'
    (run_dir / "stdout.jsonl").write_bytes(raw)
    run.stdout_path = f"runs/{run.id}/stdout.jsonl"
    run.stdout_sha256 = hashlib.sha256(raw).hexdigest()
    dumped = b"MZ malware"
    (run_dir / "output" / "pid.4.dmp").write_bytes(dumped)
    session.add(
        DerivedArtifact(
            run_id=run.id,
            evidence_id=ev.id,
            rel_path=f"runs/{run.id}/output/pid.4.dmp",
            filename="pid.4.dmp",
            size_bytes=len(dumped),
            sha256=hashlib.sha256(dumped).hexdigest(),
            md5=hashlib.md5(dumped).hexdigest(),  # noqa: S324
            sha1=hashlib.sha1(dumped).hexdigest(),  # noqa: S324
            file_type="MZ executable",
            source_row_idx=0,
        )
    )
    session.commit()
    ai_service.ask(
        session,
        ev.id,
        f"What stands out? {EVIL}",
        client=_ai_client(f"PID 666 [R{run.id}:1] and [R{run.id}:99]. {EVIL}"),
    )
    return {"ev": ev, "other": other, "run": run, "dumped": dumped, "raw": raw}


def _render(markdown: str) -> str:
    return MarkdownIt("commonmark", {"html": True}).enable("table").render(markdown)


# ------------------------------------------------------------------------------- escaping


def test_escaping_helpers() -> None:
    assert export.esc("a|b\nc") == "a\\|b c"
    assert export.esc("<b>") == "\\<b\\>"
    assert export.esc(None) == "—"
    assert export.code("x`y") == "``x`y``"
    assert export.code("`start") == "`` `start ``"
    block = export.fenced("has ```` four")
    assert block.startswith("`````text\n") and block.endswith("\n`````")


def test_evidence_text_cannot_inject_markup(session: Session, case: dict) -> None:
    html = _render(export.build_report(session, None, generated_at=WHEN))
    assert "<script>" not in html  # escaped or inside code blocks only
    assert "<a href" not in html  # [link](...) from evidence is not a live link
    assert "&lt;script&gt;" in html
    # Pipes in evidence did not break the description row: one cell holds all of it.
    assert re.search(r"<td>Description</td>\s*<td>Laptop &lt;script&gt;[^<]*\| `tick`", html)


# ------------------------------------------------------------------------------- content


def test_evidence_report_content_and_scope(session: Session, case: dict) -> None:
    ev, run = case["ev"], case["run"]
    report = export.build_report(session, ev.id, generated_at=WHEN)
    assert report.startswith("# Evidence export: sample\\.raw")
    assert "| Generated (UTC) | 2026-01-02T03:04:05Z |" in report
    assert "**mismatch**" in report and "| MD5 |" in report and "**NO**" in report
    assert "| initial | ok |" in report  # integrity history
    assert "vol -f /evidence/sample.raw windows.pslist.PsList --pid 4" in report
    assert "**high** Odd" in report and f"rows R{run.id}:1" in report
    assert "`pid.4.dmp`" in report and hashlib.sha256(case["dumped"]).hexdigest() in report
    assert export.AI_LABEL.split(" — ")[0].replace("-", "\\-") in report
    assert "2 (1 invalid: R" in report and "`placeholder-1`" in report
    assert "Analyst note" in report
    # Scope: other evidence's notes and the global note are not in a per-evidence export.
    assert "Note on the other image" not in report and "Global note" not in report
    assert "verified" in report.split("| Audit log |")[1].split("\n")[0]
    # Activity log: changes only, this evidence only.
    assert "`note.create`" in report and "http.request" not in report


def test_investigation_report_includes_everything(session: Session, case: dict) -> None:
    report = export.build_report(session, None, generated_at=WHEN)
    assert report.startswith("# Investigation export")
    assert f"## Evidence {case['ev'].id}: sample\\.raw" in report
    assert f"## Evidence {case['other'].id}: other\\.raw" in report
    assert "## Investigation notes" in report and "Global note" in report
    assert "Note on the other image" in report


def test_report_is_deterministic(session: Session, case: dict) -> None:
    a = export.build_report(session, None, generated_at=WHEN)
    b = export.build_report(session, None, generated_at=WHEN)
    assert a == b


def _normalise(report: str) -> str:
    report = re.sub(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z", "<TIME>", report)
    report = re.sub(
        r"(\| Audit log \| verified, \d+ events, head #\d+ )`[0-9a-f]{64}`", r"\1`<HEAD>`", report
    )  # noqa: E501
    report = re.sub(r"(Application version \| )\S+", r"\1<VERSION>", report)
    report = re.sub(r"(\| Provider \| )`[^`]*`", r"\1`<PROVIDER>`", report)
    # Changes whenever the AI prompts change (owned by the forensics team), not the export format.
    report = re.sub(r"(\| Prompt SHA-256 \| )`[0-9a-f]{64}`", r"\1`<PROMPT-SHA256>`", report)
    return report


def test_golden_file(session: Session, case: dict) -> None:
    """Exact report layout. If you change the format on purpose, regenerate with
    UPDATE_GOLDEN=1 pytest tests/test_export.py and review the diff."""
    report = _normalise(export.build_report(session, case["ev"].id, generated_at=WHEN))
    if os.environ.get("UPDATE_GOLDEN") or not GOLDEN.exists():
        GOLDEN.write_text(report, encoding="utf-8")
    assert report == GOLDEN.read_text(encoding="utf-8")


# ------------------------------------------------------------------------------- bundle


def test_bundle_contents_and_manifest(session: Session, case: dict) -> None:
    bundle = export.build_bundle(session, case["ev"].id, generated_at=WHEN)
    assert not bundle.encrypted and bundle.filename.startswith("evidence-sample.raw-")
    with zipfile.ZipFile(bundle.path) as zf:
        names = set(zf.namelist())
        manifest = json.loads(zf.read("manifest.json"))
        for entry in manifest["files"]:
            assert hashlib.sha256(zf.read(entry["path"])).hexdigest() == entry["sha256"]
        report = zf.read("report.md").decode()
        rows_csv = zf.read(next(n for n in names if n.endswith("rows.csv"))).decode()
    run = case["run"]
    base = f"evidence-{case['ev'].id}/run-{run.id}-pslist"
    assert {"report.md", "manifest.json", f"{base}/rows.csv", f"{base}/raw-output.jsonl"} == names
    assert manifest["includes_dumped_files"] is False and manifest["audit_chain"]["ok"]
    assert "## Files in this bundle" in report and f"{base}/rows.csv" in report
    assert "'=evil" in rows_csv  # CSV formula escaping carried over
    bundle.path.unlink()


def test_bundle_with_dumped_files_is_encrypted(
    session: Session, case: dict, settings: Settings
) -> None:
    bundle = export.build_bundle(session, case["ev"].id, include_dumped=True, generated_at=WHEN)
    assert bundle.encrypted
    with pyzipper.AESZipFile(bundle.path) as zf:
        dumped_name = next(n for n in zf.namelist() if n.endswith("dumped/pid.4.dmp"))
        with pytest.raises(RuntimeError):
            zf.read(dumped_name)  # needs the password
        zf.setpassword(settings.artifact_zip_password.encode())
        assert zf.read(dumped_name) == case["dumped"]
        assert json.loads(zf.read("manifest.json"))["includes_dumped_files"] is True
    bundle.path.unlink()


def test_bundle_skips_tampered_raw_output(session: Session, case: dict, settings: Settings) -> None:
    run = case["run"]
    (settings.data_dir / run.stdout_path).write_bytes(b"tampered")
    bundle = export.build_bundle(session, case["ev"].id, generated_at=WHEN)
    with zipfile.ZipFile(bundle.path) as zf:
        assert not any(n.endswith("raw-output.jsonl") for n in zf.namelist())
        assert "SKIPPED, hash differs" in zf.read("report.md").decode()
        assert json.loads(zf.read("manifest.json"))["warnings"]
    bundle.path.unlink()


# ------------------------------------------------------------------------------- API / UI


def test_api_and_audit(
    client: TestClient, session: Session, case: dict, settings: Settings
) -> None:
    ev = case["ev"]
    r = client.get("/api/export", params={"evidence_id": ev.id})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/markdown")
    assert re.search(
        r'filename="evidence-sample\.raw-\d{8}T\d{6}Z\.md"', r.headers["content-disposition"]
    )
    assert r.text.startswith("# Evidence export")

    r = client.get("/api/export", params={"format": "zip"})
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
        assert "report.md" in zf.namelist()
    assert not list((settings.data_dir / "tmp").iterdir())  # temp file removed

    events = list(session.scalars(select(AuditEvent).where(AuditEvent.action == "case.export")))
    assert [(e.category, e.details["format"], e.evidence_id) for e in events] == [
        (audit.KEY_READ, "md", ev.id),
        (audit.KEY_READ, "zip", None),
    ]
    md_sha = hashlib.sha256(
        client.get("/api/export", params={"evidence_id": ev.id}).content
    ).hexdigest()
    session.expire_all()
    last = session.scalars(
        select(AuditEvent).where(AuditEvent.action == "case.export").order_by(AuditEvent.seq.desc())
    ).first()
    assert last.details["report_sha256"] == md_sha  # the audit log pins the exact file
    assert client.get("/api/export", params={"evidence_id": 999}).status_code == 404
    assert client.get("/api/export", params={"format": "pdf"}).status_code == 422


def test_ui_dialogs_and_download(client: TestClient, session: Session, case: dict) -> None:
    ev = case["ev"]
    assert 'id="case-export-dialog"' in client.get("/").text
    page = client.get(f"/evidence/{ev.id}").text
    assert 'id="case-export-dialog"' in page and f'name="evidence_id" value="{ev.id}"' in page
    r = client.get(
        "/ui/export", params={"evidence_id": ev.id, "format": "zip", "include_dumped": "true"}
    )
    assert r.status_code == 200
    with pyzipper.AESZipFile(io.BytesIO(r.content)) as zf:
        assert any(n.endswith("dumped/pid.4.dmp") for n in zf.namelist())
    r = client.get("/ui/export", params={"format": "md", "include_dumped": "true"})
    assert r.text.startswith("# Investigation export")
    assert client.get("/ui/export", params={"evidence_id": "999"}).status_code == 404


def test_scope_lookup_error(session: Session) -> None:
    with pytest.raises(LookupError):
        export.get_scope(session, 12345)
    assert isinstance(export.get_scope(session, None).evidence, list)
    _ = Evidence  # model import used for typing in fixtures
