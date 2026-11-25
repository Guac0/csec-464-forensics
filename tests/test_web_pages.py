"""Tests for the temporary Jinja/HTMX UI (app.web.pages).

The app factory and service modules are built in parallel, so these tests use a minimal app
containing only the web router and replace every service the UI calls with small fakes.
"""

from __future__ import annotations

import importlib
import json
import re
import sys
import types
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import get_session
from app.models import AIMessage, Evidence, Note, ResultRow, Run, RunOrigin, RunStatus
from app.tools.base import ArgSpec, ArgValidationError, PluginSpec, ToolRequest, ToolRunner

HX = {"HX-Request": "true"}


def _ensure_module(name: str) -> None:
    """Stub a service module that a parallel engineer has not written yet, so pages imports."""
    try:
        importlib.import_module(name)
    except ModuleNotFoundError as exc:
        if exc.name != name:
            raise
        parent, _, child = name.rpartition(".")
        mod = types.ModuleType(name)
        sys.modules[name] = mod
        setattr(importlib.import_module(parent), child, mod)


for _name in (
    "app.services.evidence",
    "app.services.runs",
    "app.services.notes",
    "app.ai.service",
    "app.tools.registry",
):
    _ensure_module(_name)

from app.web import pages  # noqa: E402

# --------------------------------------------------------------------------- fakes

PLUGINS = [
    PluginSpec(
        name="windows.pslist.PsList",
        description="List processes",
        args=(
            ArgSpec("pid", "--pid", "int_list", help="Process IDs"),
            ArgSpec("physical", "--physical", "bool", help="Physical offsets"),
        ),
        auto_enumerate=True,
        presets=(("Only PID 4", {"pid": [4]}),),
    ),
    PluginSpec(
        name="windows.dumpfiles.DumpFiles",
        description="Dump cached files",
        args=(
            ArgSpec("virtaddr", "--virtaddr", "int", required=True),
            ArgSpec("filter", "--filter", "str"),
        ),
    ),
]


class FakeRunner(ToolRunner):
    name = "volatility3"

    def plugins(self) -> list[PluginSpec]:
        return PLUGINS

    def validate(self, request: ToolRequest) -> dict[str, Any]:
        spec = self.get_plugin(request.plugin)
        known = {a.name: a for a in spec.args}
        for key in request.args:
            if key not in known:
                raise ArgValidationError(f"unknown argument {key!r}")
        for a in spec.args:
            if a.required and a.name not in request.args:
                raise ArgValidationError(f"missing required argument {a.name!r}")
        return dict(request.args)

    def build_argv(self, evidence_path, request, output_dir):  # pragma: no cover
        raise NotImplementedError

    def version(self) -> str | None:  # pragma: no cover
        return "2.7.0"

    def parse_output(self, stdout_path):  # pragma: no cover
        return iter(())


def _make_fakes(session: Session) -> dict[str, SimpleNamespace]:
    runner = FakeRunner()
    calls: list[tuple] = []

    def create_run(sess, evidence_id, request, origin=RunOrigin.MANUAL, tool="volatility3"):
        args = runner.validate(request)
        run = Run(
            evidence_id=evidence_id,
            plugin=request.plugin,
            args=args,
            origin=origin,
            tool=tool,
            status=RunStatus.QUEUED,
        )
        sess.add(run)
        sess.commit()
        calls.append(("create_run", evidence_id, request, origin))
        return run

    def enqueue_auto(sess, evidence_id):
        return [
            create_run(sess, evidence_id, ToolRequest(p.name), RunOrigin.AUTO)
            for p in PLUGINS
            if p.auto_enumerate
        ]

    def cancel_run(sess, run_id):
        run = sess.get(Run, run_id)
        run.status = RunStatus.CANCELLED
        sess.commit()
        return run

    def get_rows(sess, run_id, offset=0, limit=100, q=None, annotated=False, tag=None, **_view):
        rows = list(
            sess.scalars(
                select(ResultRow).where(ResultRow.run_id == run_id).order_by(ResultRow.row_idx)
            )
        )
        if q:
            rows = [r for r in rows if q.lower() in json.dumps(r.data).lower()]
        if annotated or tag:
            rows = [r for r in rows if r.annotations]
        if tag:
            rows = [r for r in rows if any(a.get("tag") == tag for a in r.annotations)]
        return rows[offset : offset + limit], len(rows)

    def annotation_tags(sess, run_id):
        counts: dict[str, int] = {}
        for r in sess.scalars(select(ResultRow).where(ResultRow.run_id == run_id)):
            for t in {a.get("tag") for a in r.annotations or []}:
                counts[t] = counts.get(t, 0) + 1
        return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))

    def list_notes(sess, evidence_id=None):
        stmt = select(Note).order_by(Note.id)
        if evidence_id is not None:
            stmt = stmt.where(Note.evidence_id == evidence_id)
        return list(sess.scalars(stmt))

    def create_note(sess, body, evidence_id=None):
        note = Note(body=body, evidence_id=evidence_id)
        sess.add(note)
        sess.commit()
        return note

    def update_note(sess, note_id, body):
        note = sess.get(Note, note_id)
        note.body = body
        sess.commit()
        return note

    def delete_note(sess, note_id):
        sess.delete(sess.get(Note, note_id))
        sess.commit()

    def scan_evidence(sess):
        ev = sess.scalar(select(Evidence).where(Evidence.rel_path == "scanned.raw"))
        if ev is None:
            ev = Evidence(rel_path="scanned.raw", size_bytes=2048, mtime=0.0)
            sess.add(ev)
            sess.commit()
        return [ev]

    def get_messages(sess, evidence_id):
        return list(
            sess.scalars(
                select(AIMessage).where(AIMessage.evidence_id == evidence_id).order_by(AIMessage.id)
            )
        )

    def ask(sess, evidence_id, question, run_ids=None, row_refs=None):
        calls.append(("ask", evidence_id, question, run_ids))
        sess.add(AIMessage(evidence_id=evidence_id, role="user", content=question))
        msg = AIMessage(evidence_id=evidence_id, role="assistant", content=f"answer to {question}")
        sess.add(msg)
        sess.commit()
        return msg

    def summarize_run(sess, run_id):
        run = sess.get(Run, run_id)
        msg = AIMessage(
            evidence_id=run.evidence_id,
            role="assistant",
            content=f"summary of run {run_id} [R{run_id}:0]",
            model_requested="test-model",
        )
        sess.add(msg)
        sess.commit()
        return msg

    return {
        "registry": SimpleNamespace(get_runner=lambda name="volatility3": runner),
        "runs_svc": SimpleNamespace(
            create_run=create_run,
            enqueue_auto=enqueue_auto,
            cancel_run=cancel_run,
            get_rows=get_rows,
            annotation_tags=annotation_tags,
        ),
        "notes_svc": SimpleNamespace(
            list_notes=list_notes,
            create_note=create_note,
            update_note=update_note,
            delete_note=delete_note,
        ),
        "evidence_svc": SimpleNamespace(
            scan_evidence=scan_evidence,
            start_hash_in_background=lambda evidence_id: None,
            is_hashing=lambda evidence_id: False,
        ),
        "ai_svc": SimpleNamespace(ask=ask, summarize_run=summarize_run, get_messages=get_messages),
        "calls": calls,
    }


@pytest.fixture
def fakes(session: Session, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    f = _make_fakes(session)
    for attr in ("registry", "runs_svc", "notes_svc", "evidence_svc", "ai_svc"):
        monkeypatch.setattr(pages, attr, f[attr])
    return f


@pytest.fixture
def web(session: Session, fakes: dict[str, Any]) -> Iterator[TestClient]:
    app = FastAPI()
    app.include_router(pages.router)
    static = Path(pages.__file__).parent / "static"
    app.mount("/static", StaticFiles(directory=static), name="static")
    app.dependency_overrides[get_session] = lambda: session
    with TestClient(app) as c:
        yield c


@pytest.fixture
def ev(session: Session) -> Evidence:
    e = Evidence(
        rel_path="case1/mem.raw",
        size_bytes=3 * 1024**3,
        mtime=0.0,
        os_info={"os": "windows", "build": "19041"},
        description="Laptop <b>RAM</b>",
    )
    session.add(e)
    session.commit()
    return e


def _run(session: Session, ev: Evidence, status=RunStatus.SUCCEEDED, **kw) -> Run:
    run = Run(evidence_id=ev.id, plugin="windows.pslist.PsList", args={}, status=status, **kw)
    session.add(run)
    session.commit()
    return run


# --------------------------------------------------------------------------- pages


def test_static_assets_served(web: TestClient) -> None:
    assert web.get("/static/style.css").status_code == 200
    assert "htmx" in web.get("/static/htmx.min.js").text[:200]


def test_index_renders(web: TestClient, session: Session, ev: Evidence) -> None:
    session.add(Note(body="global <i>note</i>"))
    session.add(Note(body="evidence note", evidence_id=ev.id))
    session.commit()
    _run(session, ev)
    r = web.get("/")
    assert r.status_code == 200
    html = r.text
    assert "Temporary UI — proof of concept" in html
    assert "case1/mem.raw" in html
    assert "3.0 GiB" in html
    assert "not hashed" in html and 'action="/ui/evidence/1/hash"' in html
    assert "os=windows" in html
    assert 'hx-post="/ui/scan"' in html
    assert "global &lt;i&gt;note&lt;/i&gt;" in html
    assert "evidence note" not in html  # only global notes on the index
    assert '<script src="/static/htmx.min.js"' in html


def test_scan_htmx_and_plain(web: TestClient) -> None:
    r = web.post("/ui/scan", headers=HX)
    assert r.status_code == 200 and 'id="evidence-list"' in r.text and "scanned.raw" in r.text
    assert "<html" not in r.text
    r = web.post("/ui/scan", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"


def test_cross_site_post_refused(web: TestClient) -> None:
    assert web.post("/ui/scan", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert web.post("/ui/scan", headers={"Origin": "http://evil.example"}).status_code == 403


def test_evidence_page_renders_plugins(web: TestClient, ev: Evidence) -> None:
    r = web.get(f"/evidence/{ev.id}")
    assert r.status_code == 200
    html = r.text
    assert "Laptop &lt;b&gt;RAM&lt;/b&gt;" in html
    assert "windows.pslist.PsList — List processes" in html
    assert "windows.dumpfiles.DumpFiles" in html
    assert f'hx-get="/ui/evidence/{ev.id}/plugin-form"' in html
    assert 'id="ai-spinner"' in html and "Asking AI..." in html
    assert f'action="/ui/evidence/{ev.id}/auto"' in html


def test_evidence_404(web: TestClient) -> None:
    assert web.get("/evidence/999").status_code == 404


def test_plugin_form_renders_argspecs(web: TestClient, ev: Evidence) -> None:
    r = web.get(
        f"/ui/evidence/{ev.id}/plugin-form", params={"plugin": "windows.pslist.PsList"}, headers=HX
    )
    html = r.text
    assert r.status_code == 200 and 'id="plugin-form"' in html
    assert 'name="arg_pid"' in html and 'placeholder="1, 2, 3"' in html
    assert re.search(r'type="checkbox"[^>]*name="arg_physical"', html)
    assert "Only PID 4" in html and "value='{\"pid\": [4]}'" in html
    assert 'name="origin" value="preset"' in html

    r = web.get(
        f"/ui/evidence/{ev.id}/plugin-form",
        params={"plugin": "windows.dumpfiles.DumpFiles"},
        headers=HX,
    )
    assert re.search(r'name="arg_virtaddr"\s+value=""\s+type="number"', r.text)
    assert "required" in r.text

    # Non-HTMX falls back to the full page with the form pre-rendered.
    r = web.get(f"/ui/evidence/{ev.id}/plugin-form", params={"plugin": "windows.pslist.PsList"})
    assert r.status_code == 200 and 'name="arg_pid"' in r.text and "<html" in r.text


def test_create_run_manual(
    web: TestClient, session: Session, ev: Evidence, fakes: dict[str, Any]
) -> None:
    r = web.post(
        f"/ui/evidence/{ev.id}/runs",
        headers=HX,
        data={
            "plugin": "windows.pslist.PsList",
            "origin": "manual",
            "arg_pid": "4, 8 12",
            "arg_physical": "on",
        },
    )
    assert r.status_code == 200
    assert 'id="runs"' in r.text and "windows.pslist.PsList" in r.text
    assert 'id="run-form-errors" hx-swap-oob="true"' in r.text
    _, _, request, origin = fakes["calls"][-1]
    assert request.args == {"pid": [4, 8, 12], "physical": True}
    assert origin == RunOrigin.MANUAL


def test_create_run_preset_and_ai_origin(
    web: TestClient, ev: Evidence, fakes: dict[str, Any]
) -> None:
    web.post(
        f"/ui/evidence/{ev.id}/runs",
        headers=HX,
        data={"plugin": "windows.pslist.PsList", "origin": "preset", "args_json": '{"pid": [4]}'},
    )
    assert fakes["calls"][-1][2].args == {"pid": [4]}
    assert fakes["calls"][-1][3] == RunOrigin.PRESET
    r = web.post(
        f"/ui/evidence/{ev.id}/runs",
        data={"plugin": "windows.pslist.PsList", "origin": "ai", "args_json": "{}"},
        follow_redirects=False,
    )
    assert r.status_code == 303 and r.headers["location"] == f"/evidence/{ev.id}#runs"
    assert fakes["calls"][-1][3] == RunOrigin.AI_SUGGESTED


def test_create_run_validation_error(web: TestClient, session: Session, ev: Evidence) -> None:
    # Validation error from the runner (missing required arg).
    r = web.post(
        f"/ui/evidence/{ev.id}/runs",
        headers=HX,
        data={"plugin": "windows.dumpfiles.DumpFiles", "arg_filter": "x"},
    )
    assert r.status_code == 200
    assert r.headers["HX-Retarget"] == "#run-form-errors"
    assert "missing required argument" in r.text
    # Bad int conversion in the UI.
    r = web.post(
        f"/ui/evidence/{ev.id}/runs",
        headers=HX,
        data={"plugin": "windows.pslist.PsList", "arg_pid": "4, abc"},
    )
    assert "expected comma-separated integers" in r.text
    # Unknown plugin.
    r = web.post(f"/ui/evidence/{ev.id}/runs", headers=HX, data={"plugin": "evil.Plugin"})
    assert "plugin not allowed" in r.text
    # Non-HTMX: full page with inline error and the user's values kept.
    r = web.post(
        f"/ui/evidence/{ev.id}/runs",
        data={"plugin": "windows.dumpfiles.DumpFiles", "arg_filter": "keep<me>"},
    )
    assert r.status_code == 422
    assert "Could not create run" in r.text and "keep&lt;me&gt;" in r.text
    assert session.scalar(select(func.count(Run.id))) == 0


def test_runs_fragment_polls_only_when_active(
    web: TestClient, session: Session, ev: Evidence
) -> None:
    run = _run(session, ev, status=RunStatus.SUCCEEDED, row_count=7)
    r = web.get(f"/ui/evidence/{ev.id}/runs", headers=HX)
    assert 'hx-trigger="every 3s"' not in r.text
    assert "status-succeeded" in r.text and "Cancel" not in r.text

    active = _run(session, ev, status=RunStatus.RUNNING)
    r = web.get(f"/ui/evidence/{ev.id}/runs", headers=HX)
    assert 'hx-trigger="every 3s"' in r.text
    assert f'hx-post="/ui/runs/{active.id}/cancel"' in r.text
    assert f'hx-post="/ui/runs/{run.id}/cancel"' not in r.text
    # Evidence page itself also carries the polling attribute while active.
    assert 'hx-trigger="every 3s"' in web.get(f"/evidence/{ev.id}").text

    r = web.post(f"/ui/runs/{active.id}/cancel", headers=HX)
    assert "status-cancelled" in r.text and 'hx-trigger="every 3s"' not in r.text


def test_auto_enumerate(web: TestClient, ev: Evidence, fakes: dict[str, Any]) -> None:
    r = web.post(f"/ui/evidence/{ev.id}/auto", headers=HX)
    assert "Queued 1 auto-enumeration run(s)" in r.text
    assert fakes["calls"][-1][3] == RunOrigin.AUTO


def test_notes_crud(web: TestClient, session: Session, ev: Evidence) -> None:
    r = web.post("/ui/notes", headers=HX, data={"body": "first <b>", "evidence_id": str(ev.id)})
    assert "first &lt;b&gt;" in r.text
    note = session.scalars(select(Note)).one()
    assert note.evidence_id == ev.id
    r = web.post(f"/ui/notes/{note.id}/edit", headers=HX, data={"body": "edited"})
    assert "edited" in r.text
    r = web.post(f"/ui/notes/{note.id}/delete", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/evidence/{ev.id}#notes"
    assert session.scalar(select(func.count(Note.id))) == 0


# --------------------------------------------------------------------------- run page / rows


@pytest.fixture
def big_run(session: Session, ev: Evidence) -> Run:
    run = _run(
        session,
        ev,
        argv=["vol", "-f", "/evidence/case1/mem.raw", "windows.pslist"],
        tool_version="2.7.0",
        evidence_sha256="a" * 64,
        stdout_sha256="b" * 64,
        row_count=250,
    )
    for i in range(250):
        data = {"PID": i, "ImageFileName": f"proc{i}.exe"}
        if i == 3:
            data["Extra"] = "<img src=x onerror=alert(1)>"
        session.add(ResultRow(run_id=run.id, row_idx=i, depth=1 if i == 1 else 0, data=data))
    session.commit()
    return run


def test_run_page_metadata_and_table(web: TestClient, big_run: Run) -> None:
    r = web.get(f"/runs/{big_run.id}")
    html = r.text
    assert r.status_code == 200
    assert "vol -f /evidence/case1/mem.raw windows.pslist" in html
    assert "a" * 64 in html and "b" * 64 in html and "2.7.0" in html
    assert f'hx-post="/ui/runs/{big_run.id}/summarize"' in html
    assert "Rows 1–100 of 250" in html
    assert f'id="row-{big_run.id}-0"' in html and f'id="row-{big_run.id}-99"' in html
    assert f'id="row-{big_run.id}-100"' not in html
    # Columns: citation first, then union of keys in insertion order.
    headers = re.findall(r'class="sort"[^>]*>([^<]+)</a>', html)
    assert [h.strip() for h in headers] == ["PID", "ImageFileName", "Extra"]
    assert f">R{big_run.id}:5</a>" in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html and "<img src=x" not in html
    assert "padding-left: 1.75em" in html  # depth-1 row indented


def test_rows_fragment_pagination_and_filter(web: TestClient, big_run: Run) -> None:
    r = web.get(f"/ui/runs/{big_run.id}/rows", params={"offset": 200}, headers=HX)
    assert "Rows 201–250 of 250" in r.text and "<html" not in r.text
    assert f'id="row-{big_run.id}-249"' in r.text and "Next" not in r.text
    assert f'hx-get="/ui/runs/{big_run.id}/rows?offset=100' in r.text

    r = web.get(f"/ui/runs/{big_run.id}/rows", params={"q": "proc24"}, headers=HX)
    assert "of 11" in r.text  # proc24, proc240..249
    assert f'id="row-{big_run.id}-24"' in r.text and f'id="row-{big_run.id}-1"' not in r.text

    r = web.get(f"/ui/runs/{big_run.id}/rows", params={"q": "x"}, follow_redirects=False)
    assert r.status_code == 303 and "q=x" in r.headers["location"]


def test_row_param_opens_page_and_highlights(web: TestClient, big_run: Run) -> None:
    r = web.get(f"/runs/{big_run.id}", params={"row": 134})
    assert "Rows 101–200 of 250" in r.text
    assert f'<tr id="row-{big_run.id}-134" class="highlight">' in r.text
    assert f'<tr id="row-{big_run.id}-135">' in r.text


def test_failed_run_shows_stderr_tail(
    web: TestClient, session: Session, ev: Evidence, settings
) -> None:
    (settings.data_dir / "runs").mkdir()
    (settings.data_dir / "runs" / "err.txt").write_text("x" * 10000 + "Traceback <boom>")
    run = _run(session, ev, status=RunStatus.FAILED, error="exit 1", stderr_path="runs/err.txt")
    html = web.get(f"/runs/{run.id}").text
    assert "exit 1" in html and "Traceback &lt;boom&gt;" in html
    assert "x" * 5000 not in html


def test_summarize(web: TestClient, big_run: Run) -> None:
    r = web.post(f"/ui/runs/{big_run.id}/summarize", headers=HX)
    assert "AI-generated lead — not evidence" in r.text
    assert f'href="/runs/{big_run.id}?row=0#row-{big_run.id}-0"' in r.text
    r = web.post(f"/ui/runs/{big_run.id}/summarize")
    assert r.status_code == 200 and "<html" in r.text and "summary of run" in r.text


# --------------------------------------------------------------------------- AI rendering


def test_ai_message_escapes_and_links(web: TestClient, session: Session, ev: Evidence) -> None:
    msg = AIMessage(
        evidence_id=ev.id,
        role="assistant",
        content="<script>alert(1)</script> see [R1:2] and [R1:3, R9:9]\n**not markdown**",
        model_requested="test-model",
        model_returned="test-model-2024",
        provider_base_url="http://ai.test/v1",
        params={"temperature": 0.2},
        usage={"total_tokens": 42},
        context_refs={"run_ids": [1]},
        request_messages=[{"role": "system", "content": "be careful </pre><b>x</b>"}],
        citations=[
            {"key": "R1:2", "valid": True},
            {"key": "R1:3", "valid": True},
            {"key": "R9:9", "valid": False},
        ],
        suggestions=[
            {
                "tool": "volatility3",
                "plugin": "windows.pslist.PsList",
                "args": {"pid": [4]},
                "normalized_args": {"pid": [4]},
                "reason": "check <System>",
                "valid": True,
            },
            {
                "tool": "volatility3",
                "plugin": "evil.Plugin",
                "args": {},
                "reason": "",
                "valid": False,
                "error": "plugin not allowed: 'evil.Plugin'",
            },
        ],
    )
    session.add(msg)
    session.commit()
    html = web.get(f"/ui/evidence/{ev.id}/ai", headers=HX).text
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert '<a class="cite" href="/runs/1?row=2#row-1-2">R1:2</a>' in html
    assert '<a class="cite" href="/runs/1?row=3#row-1-3">R1:3</a>' in html
    assert '<span class="cite-invalid"' in html and ">R9:9</span>" in html
    assert "**not markdown**" in html
    assert "AI-generated lead — not evidence" in html
    # Provenance
    assert "<summary>Provenance</summary>" in html
    assert "test-model-2024" in html and "http://ai.test/v1" in html
    assert "&#34;total_tokens&#34;: 42" in html or "&quot;total_tokens&quot;: 42" in html
    assert "be careful &lt;/pre&gt;&lt;b&gt;x&lt;/b&gt;" in html
    # Suggestions
    assert "check &lt;System&gt;" in html
    assert 'name="origin" value="ai"' in html and "value='{\"pid\": [4]}'" in html
    assert '<button type="button" class="small" disabled>Run</button>' in html
    assert "plugin not allowed: &#39;evil.Plugin&#39;" in html


def test_render_ai_content_unit() -> None:
    out = pages.render_ai_content('<b>"x"</b> [R12:34]', [])
    assert str(out) == (
        "&lt;b&gt;&#34;x&#34;&lt;/b&gt; "
        '[<a class="cite" href="/runs/12?row=34#row-12-34">R12:34</a>]'
    )
    assert str(pages.render_ai_content("R1:2 not bracketed")) == "R1:2 not bracketed"


def test_ai_ask(web: TestClient, ev: Evidence, fakes: dict[str, Any]) -> None:
    r = web.post(
        f"/ui/evidence/{ev.id}/ai/ask",
        headers=HX,
        data={"question": "what <ran>?", "run_ids": "3, 4"},
    )
    assert r.status_code == 200 and 'id="ai-history"' in r.text
    assert "what &lt;ran&gt;?" in r.text and "Analyst question" in r.text
    assert fakes["calls"][-1] == ("ask", ev.id, "what <ran>?", [3, 4])
    r = web.post(f"/ui/evidence/{ev.id}/ai/ask", data={"question": "again"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/evidence/{ev.id}#ai"


def test_filters() -> None:
    from datetime import UTC, datetime

    assert pages.humansize(512) == "512 B"
    assert pages.humansize(1536) == "1.5 KiB"
    assert pages.fmt_dt(datetime(2026, 1, 2, 3, 4, 5, 999)) == "2026-01-02T03:04:05Z"
    assert pages.fmt_dt(datetime(2026, 1, 2, tzinfo=UTC)) == "2026-01-02T00:00:00Z"
    assert pages.fmt_dt(None) == "—"
