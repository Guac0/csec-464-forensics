"""Temporary server-rendered UI (Jinja2 + HTMX). Proof of concept; will be replaced.

Progressive enhancement: every form has a normal action/method. Mutating endpoints return an
HTML fragment for HTMX requests (``HX-Request: true``) and a 303 redirect back otherwise.
"""

from __future__ import annotations

import json
import re
import shlex
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlencode, urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape
from sqlalchemy import func, select
from sqlalchemy.orm import Session

# Service modules are imported as modules so tests can monkeypatch their attributes.
from app.ai import service as ai_svc
from app.config import get_settings
from app.db import get_session
from app.models import AIMessage, Evidence, Note, ResultRow, Run, RunOrigin, RunStatus
from app.services import audit as audit_svc
from app.services import evidence as evidence_svc
from app.services import integrity as integrity_svc
from app.services import notes as notes_svc
from app.services import results as results_svc
from app.services import runs as runs_svc
from app.tools import hooks as hooks_mod
from app.tools import registry
from app.tools.base import ArgValidationError, PluginSpec, ToolRequest

TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter(include_in_schema=False)

PAGE_SIZE = 100
MAX_PAGE_SIZE = 500
STDERR_TAIL_BYTES = 4096
ACTIVE_STATUSES = (RunStatus.QUEUED, RunStatus.RUNNING)
SEVERITIES = hooks_mod.SEVERITIES
ANY_TAG = "*"  # tag filter value meaning "any annotated row"
UI_ORIGINS = {"manual": RunOrigin.MANUAL, "preset": RunOrigin.PRESET, "ai": RunOrigin.AI_SUGGESTED}


# --------------------------------------------------------------------------- template helpers


def humansize(value: int | None) -> str:
    if value is None:
        return "?"
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{int(size)} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{value} B"  # pragma: no cover


def fmt_dt(value: datetime | None) -> str:
    """UTC ISO 8601, seconds precision. SQLite returns naive datetimes: treat them as UTC."""
    if value is None:
        return "—"
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fmt_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, dict | list):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def fmt_args(value: Any) -> str:
    if not value:
        return ""
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def pretty_json(value: Any) -> str:
    """Indented JSON for <pre> blocks (autoescaped by Jinja like any other string)."""
    return json.dumps(value, indent=2, ensure_ascii=False, default=str)


def fmt_argv(value: list[str] | None) -> str:
    return shlex.join(value) if value else "—"


_CITE_BRACKET_RE = re.compile(r"\[\s*(R\d+:\d+(?:\s*[,;]\s*R\d+:\d+)*)\s*\]")
_CITE_KEY_RE = re.compile(r"R(\d+):(\d+)")


def render_ai_content(content: str | None, citations: list[dict[str, Any]] | None = None) -> Markup:
    """Escape AI text completely, then turn citation tokens like [R12:34] into row links.

    Never renders markdown/HTML: evidence strings quoted by the model may contain markup.
    """
    invalid = {
        str(c.get("key"))
        for c in (citations or [])
        if isinstance(c, dict) and c.get("valid") is False
    }
    escaped = str(escape(content or ""))

    def _key(m: re.Match[str]) -> str:
        run_id, row_idx = int(m.group(1)), int(m.group(2))
        key = f"R{run_id}:{row_idx}"
        if key in invalid:
            return f'<span class="cite-invalid" title="citation not found in database">{key}</span>'
        href = f"/runs/{run_id}?row={row_idx}#row-{run_id}-{row_idx}"
        return f'<a class="cite" href="{href}">{key}</a>'

    def _bracket(m: re.Match[str]) -> str:
        return "[" + _CITE_KEY_RE.sub(_key, m.group(1)) + "]"

    # The escaped text only contains digits/letters/[]:,; inside a match, so this is safe.
    return Markup(_CITE_BRACKET_RE.sub(_bracket, escaped))  # noqa: S704


def fmt_os_info(value: dict[str, Any] | None) -> str:
    if not value:
        return "—"
    parts = []
    for k, v in value.items():
        if isinstance(v, dict | list):
            parts.append(f"{k}=({len(v)} fields)")  # nested detail is shown on hover/API
        else:
            parts.append(f"{k}={v}")
    return ", ".join(parts)


def max_severity(annotations: list[dict[str, Any]] | None) -> str | None:
    """Highest severity among a row's annotations (for row highlighting)."""
    levels = [a.get("severity") for a in annotations or [] if a.get("severity") in SEVERITIES]
    return max(levels, key=SEVERITIES.index) if levels else None


templates.env.filters.update(
    humansize=humansize,
    dt=fmt_dt,
    cell=fmt_cell,
    args=fmt_args,
    argv=fmt_argv,
    pretty=pretty_json,
    ai_content=render_ai_content,
    os_info=fmt_os_info,
    max_severity=max_severity,
    integrity_status=lambda ev: integrity_svc.status(ev),
    integrity_problem=lambda ev: integrity_svc.describe_problem(ev),
)


# --------------------------------------------------------------------------- request helpers


def is_htmx(request: Request) -> bool:
    return request.headers.get("HX-Request") == "true"


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def same_origin_post(request: Request) -> None:
    """Cheap cross-site request guard for the (login-less) localhost UI."""
    if request.headers.get("Sec-Fetch-Site") == "cross-site":
        raise HTTPException(403, "cross-site request refused")
    origin = request.headers.get("Origin")
    if origin and origin != "null" and urlsplit(origin).netloc != request.headers.get("host"):
        raise HTTPException(403, "cross-origin request refused")


async def form_data(request: Request) -> dict[str, str]:
    """Parsed form as a flat dict (last value wins). Async so endpoints can stay sync."""
    form = await request.form()
    return {k: v for k, v in form.items() if isinstance(v, str)}


SessionDep = Annotated[Session, Depends(get_session)]
FormDep = Annotated[dict[str, str], Depends(form_data)]


def render(request: Request, name: str, status_code: int = 200, **context: Any) -> HTMLResponse:
    return templates.TemplateResponse(request, name, context, status_code=status_code)


def get_evidence_or_404(session: Session, evidence_id: int) -> Evidence:
    ev = session.get(Evidence, evidence_id)
    if ev is None:
        raise HTTPException(404, "evidence not found")
    return ev


def get_run_or_404(session: Session, run_id: int) -> Run:
    run = session.get(Run, run_id)
    if run is None:
        raise HTTPException(404, "run not found")
    return run


def runner_plugins(tool: str = "volatility3") -> list[PluginSpec]:
    return list(registry.get_runner(tool).plugins())


def find_plugin(name: str | None, tool: str = "volatility3") -> PluginSpec | None:
    if not name:
        return None
    return next((p for p in runner_plugins(tool) if p.name == name), None)


def parse_plugin_args(spec: PluginSpec, form: dict[str, str]) -> dict[str, Any]:
    """Convert form fields ``arg_<name>`` to typed values per ArgSpec; empty fields are omitted."""
    args: dict[str, Any] = {}
    for a in spec.args:
        key = f"arg_{a.name}"
        if a.type == "bool":
            if form.get(key) in ("on", "true", "1"):
                args[a.name] = True
            continue
        raw = (form.get(key) or "").strip()
        if not raw:
            continue
        try:
            if a.type == "int":
                args[a.name] = int(raw)
            elif a.type == "int_list":
                args[a.name] = [int(x) for x in re.split(r"[,\s]+", raw) if x]
            else:
                args[a.name] = raw
        except ValueError:
            kind = "an integer" if a.type == "int" else "comma-separated integers"
            raise ArgValidationError(f"{a.name}: expected {kind}, got {raw!r}") from None
    return args


def list_runs(session: Session, evidence_id: int) -> list[Run]:
    stmt = select(Run).where(Run.evidence_id == evidence_id).order_by(Run.id.desc())
    return list(session.scalars(stmt))


def list_scoped_notes(session: Session, evidence_id: int | None) -> list[Note]:
    notes = notes_svc.list_notes(session, evidence_id=evidence_id)
    # Robust to list_notes(None) meaning either "global only" or "all notes".
    return [n for n in notes if n.evidence_id == evidence_id]


def ai_history(session: Session, evidence_id: int) -> list[AIMessage]:
    getter = getattr(ai_svc, "get_messages", None)
    if getter is not None:
        return list(getter(session, evidence_id))
    stmt = select(AIMessage).where(AIMessage.evidence_id == evidence_id).order_by(AIMessage.id)
    return list(session.scalars(stmt))


def stderr_tail(run: Run) -> str | None:
    if not run.stderr_path:
        return None
    data_dir = get_settings().data_dir.resolve()
    path = (data_dir / run.stderr_path).resolve()
    if not path.is_relative_to(data_dir) or not path.is_file():
        return None
    with path.open("rb") as fh:
        size = fh.seek(0, 2)
        fh.seek(max(0, size - STDERR_TAIL_BYTES))
        return fh.read().decode("utf-8", errors="replace")


# --------------------------------------------------------------------------- fragments / contexts


def evidence_list_response(request: Request, session: Session, **extra: Any) -> HTMLResponse:
    evidence = list(session.scalars(select(Evidence).order_by(Evidence.rel_path)))
    counts = dict(
        session.execute(select(Run.evidence_id, func.count(Run.id)).group_by(Run.evidence_id)).all()
    )
    return render(request, "_evidence_list.html", evidence=evidence, run_counts=counts, **extra)


def runs_response(
    request: Request, session: Session, evidence_id: int, **extra: Any
) -> HTMLResponse:
    runs = list_runs(session, evidence_id)
    return render(
        request,
        "_runs.html",
        runs=runs,
        evidence_id=evidence_id,
        polling=any(r.status in ACTIVE_STATUSES for r in runs),
        **extra,
    )


def notes_response(request: Request, session: Session, evidence_id: int | None) -> HTMLResponse:
    notes = list_scoped_notes(session, evidence_id)
    return render(request, "_notes.html", notes=notes, evidence_id=evidence_id)


def evidence_context(session: Session, ev: Evidence, plugin: str | None = None) -> dict[str, Any]:
    runs = list_runs(session, ev.id)
    return {
        "ev": ev,
        "evidence_id": ev.id,
        "plugins": runner_plugins(),
        "selected_plugin": find_plugin(plugin),
        "notes": list_scoped_notes(session, ev.id),
        "runs": runs,
        "polling": any(r.status in ACTIVE_STATUSES for r in runs),
        "messages": ai_history(session, ev.id),
        "runs_panel": True,
        "values": {},
        "integrity_status": integrity_svc.status(ev),
        "integrity_problem": integrity_svc.describe_problem(ev),
        "integrity_checks": integrity_svc.list_checks(session, ev.id)[:20],
        "integrity_mode": get_settings().integrity_mode,
        "verify_on_run": get_settings().verify_on_run,
        "hashing": evidence_svc.is_hashing(ev.id),
    }


def rows_context(
    session: Session,
    run: Run,
    view: results_svc.RowView,
    offset: int,
    limit: int,
    highlight: int | None = None,
) -> dict[str, Any]:
    limit = max(1, min(limit, MAX_PAGE_SIZE))
    offset = max(0, offset)
    view_error = None
    try:
        rows, total = runs_svc.get_rows(
            session,
            run.id,
            offset=offset,
            limit=limit,
            q=view.q or None,
            annotated=view.annotated,
            tag=view.tag or None,
            filters=view.filters,
            sort=view.sort or None,
            desc=view.desc,
        )
    except ValueError as exc:  # e.g. an unsupported column name in a filter
        rows, total, view_error = [], 0, str(exc)
    # Stable columns recorded at ingest; fall back to this page's keys for older runs.
    columns = [c["name"] for c in run.columns or []]
    if not columns:
        seen: dict[str, None] = {}
        for r in rows:
            for k in r.data or {}:
                seen.setdefault(k, None)
        columns = list(seen)
    return {
        "run": run,
        "rows": rows,
        "total": total,
        "offset": offset,
        "limit": limit,
        "view": view,
        "view_error": view_error,
        "q": view.q,
        "tag": "*" if view.annotated and not view.tag else view.tag,
        "tags": runs_svc.annotation_tags(session, run.id),
        "row_artifacts": _row_artifacts(run),
        "has_annotations": any(r.annotations for r in rows) or view.annotated or bool(view.tag),
        "columns": columns,
        "column_types": {c["name"]: c["type"] for c in run.columns or []},
        "highlight": highlight,
        "prev_offset": max(0, offset - limit) if offset > 0 else None,
        "next_offset": offset + limit if offset + limit < total else None,
    }


def _row_artifacts(run: Run) -> dict[int, list[Any]]:
    """row_idx -> artifacts named by that row (for the results table's "File" column)."""
    out: dict[int, list[Any]] = {}
    for a in getattr(run, "artifacts", None) or []:
        if a.source_row_idx is not None:
            out.setdefault(a.source_row_idx, []).append(a)
    return out


def page_url(
    run_id: int, view: results_svc.RowView, fragment: bool = False, **overrides: Any
) -> str:
    """URL of the run page (or the rows fragment) for a view, e.g. with another offset/sort."""
    params = view.to_params(**overrides)
    if params.get("limit") == PAGE_SIZE:
        params.pop("limit")
    base = f"/ui/runs/{run_id}/rows" if fragment else f"/runs/{run_id}"
    return f"{base}?{urlencode(params)}" if params else base


templates.env.globals.update(page_url=page_url)


# --------------------------------------------------------------------------- pages


@router.get("/", response_class=HTMLResponse)
def index(request: Request, session: SessionDep) -> HTMLResponse:
    evidence = list(session.scalars(select(Evidence).order_by(Evidence.rel_path)))
    counts = dict(
        session.execute(select(Run.evidence_id, func.count(Run.id)).group_by(Run.evidence_id)).all()
    )
    return render(
        request,
        "index.html",
        evidence=evidence,
        run_counts=counts,
        notes=list_scoped_notes(session, None),
        evidence_id=None,
    )


@router.get("/evidence/{evidence_id}", response_class=HTMLResponse)
def evidence_page(
    request: Request,
    session: SessionDep,
    evidence_id: int,
    plugin: str | None = None,
) -> HTMLResponse:
    ev = get_evidence_or_404(session, evidence_id)
    return render(request, "evidence.html", **evidence_context(session, ev, plugin))


@router.get("/runs/{run_id}", response_class=HTMLResponse)
def run_page(
    request: Request,
    session: SessionDep,
    run_id: int,
    offset: int = 0,
    limit: int = PAGE_SIZE,
    row: int | None = None,
) -> HTMLResponse:
    """Query parameters: q, tag, sort, desc, f.<column> (see RowView), offset, limit, row."""
    run = get_run_or_404(session, run_id)
    view = results_svc.RowView.from_params(request.query_params)
    return _render_run_page(request, session, run, offset, limit, row, view=view)


def _render_run_page(
    request: Request,
    session: Session,
    run: Run,
    offset: int = 0,
    limit: int = PAGE_SIZE,
    row: int | None = None,
    summary: AIMessage | None = None,
    message: str | None = None,
    view: results_svc.RowView | None = None,
) -> HTMLResponse:
    view = view or results_svc.RowView()
    if row is not None:
        # Open the (unfiltered, unsorted) page containing the requested row.
        view = results_svc.RowView()
        before = session.scalar(
            select(func.count(ResultRow.id)).where(
                ResultRow.run_id == run.id, ResultRow.row_idx < row
            )
        )
        limit = max(1, min(limit, MAX_PAGE_SIZE))
        offset = ((before or 0) // limit) * limit
    ctx = rows_context(session, run, view, offset, limit, row)
    follow_ups = list(
        session.scalars(select(Run).where(Run.parent_run_id == run.id).order_by(Run.id))
    )
    return render(
        request,
        "run.html",
        stderr_tail=stderr_tail(run) if run.status == RunStatus.FAILED else None,
        summary=summary,
        evidence_id=run.evidence_id,
        hook_specs=hooks_mod.hooks_for(run.tool, run.plugin),
        hook_errors=[h for h in run.hook_results or [] if h.get("status") != "ok"],
        follow_ups=follow_ups,
        message=message,
        zip_password=get_settings().artifact_zip_password,
        **ctx,
    )


# --------------------------------------------------------------------------- fragments + actions


@router.post("/ui/scan", dependencies=[Depends(same_origin_post)])
def ui_scan(request: Request, session: SessionDep) -> Response:
    error = None
    try:
        evidence_svc.scan_evidence(session)
        session.commit()
    except OSError as exc:
        error = f"Scan failed: {exc}"
    if not is_htmx(request):
        return redirect("/")
    return evidence_list_response(request, session, error=error)


@router.post("/ui/evidence/{evidence_id}/hash", dependencies=[Depends(same_origin_post)])
def ui_hash(request: Request, evidence_id: int, session: SessionDep) -> Response:
    get_evidence_or_404(session, evidence_id)
    evidence_svc.start_hash_in_background(evidence_id)
    if not is_htmx(request):
        return redirect(request.headers.get("referer") or "/")
    return evidence_list_response(
        request, session, message="Hashing started in the background; refresh to see the result."
    )


@router.get("/ui/notes", response_class=HTMLResponse)
def ui_notes(request: Request, session: SessionDep, evidence_id: int | None = None) -> HTMLResponse:
    return notes_response(request, session, evidence_id)


def _notes_done(request: Request, session: Session, evidence_id: int | None) -> Response:
    session.commit()
    if not is_htmx(request):
        return redirect(f"/evidence/{evidence_id}#notes" if evidence_id else "/#notes")
    return notes_response(request, session, evidence_id)


@router.post("/ui/notes", dependencies=[Depends(same_origin_post)])
def ui_note_create(
    request: Request,
    form: FormDep,
    session: SessionDep,
) -> Response:
    raw_ev = (form.get("evidence_id") or "").strip()
    evidence_id = int(raw_ev) if raw_ev.isdigit() else None
    if evidence_id is not None:
        get_evidence_or_404(session, evidence_id)
    body = (form.get("body") or "").strip()
    if body:
        notes_svc.create_note(session, body, evidence_id=evidence_id)
    return _notes_done(request, session, evidence_id)


@router.post("/ui/notes/{note_id}/edit", dependencies=[Depends(same_origin_post)])
def ui_note_edit(
    request: Request,
    note_id: int,
    form: FormDep,
    session: SessionDep,
) -> Response:
    note = session.get(Note, note_id)
    if note is None:
        raise HTTPException(404, "note not found")
    evidence_id = note.evidence_id
    body = (form.get("body") or "").strip()
    if body:
        notes_svc.update_note(session, note_id, body)
    return _notes_done(request, session, evidence_id)


@router.post("/ui/notes/{note_id}/delete", dependencies=[Depends(same_origin_post)])
def ui_note_delete(request: Request, note_id: int, session: SessionDep) -> Response:
    note = session.get(Note, note_id)
    if note is None:
        raise HTTPException(404, "note not found")
    evidence_id = note.evidence_id
    notes_svc.delete_note(session, note_id)
    return _notes_done(request, session, evidence_id)


@router.get("/ui/evidence/{evidence_id}/plugin-form", response_class=HTMLResponse)
def ui_plugin_form(
    request: Request,
    session: SessionDep,
    evidence_id: int,
    plugin: str | None = None,
) -> Response:
    get_evidence_or_404(session, evidence_id)
    if not is_htmx(request):
        return redirect(f"/evidence/{evidence_id}?{urlencode({'plugin': plugin or ''})}#query")
    return render(
        request,
        "_plugin_form.html",
        evidence_id=evidence_id,
        selected_plugin=find_plugin(plugin),
        values={},
    )


@router.get("/ui/evidence/{evidence_id}/runs", response_class=HTMLResponse)
def ui_runs(request: Request, evidence_id: int, session: SessionDep) -> Response:
    get_evidence_or_404(session, evidence_id)
    if not is_htmx(request):
        return redirect(f"/evidence/{evidence_id}#runs")
    return runs_response(request, session, evidence_id)


@router.post("/ui/evidence/{evidence_id}/runs", dependencies=[Depends(same_origin_post)])
def ui_create_run(
    request: Request,
    evidence_id: int,
    form: FormDep,
    session: SessionDep,
) -> Response:
    ev = get_evidence_or_404(session, evidence_id)
    plugin_name = (form.get("plugin") or "").strip()
    tool = (form.get("tool") or "volatility3").strip() or "volatility3"
    origin = UI_ORIGINS.get(form.get("origin") or "manual", RunOrigin.MANUAL)
    error: str | None = None
    try:
        if not plugin_name:
            raise ArgValidationError("choose a plugin")
        if "args_json" in form:  # presets and AI suggestions carry their args as JSON
            args = json.loads(form["args_json"] or "{}")
            if not isinstance(args, dict):
                raise ArgValidationError("args must be a JSON object")
        else:
            spec = registry.get_runner(tool).get_plugin(plugin_name)
            args = parse_plugin_args(spec, form)
        runs_svc.create_run(
            session,
            evidence_id,
            ToolRequest(plugin=plugin_name, args=args),
            origin=origin,
            tool=tool,
        )
        session.commit()
    except (ValueError, KeyError) as exc:  # ArgValidationError and JSON errors are ValueErrors
        session.rollback()
        error = (
            str(exc)
            if isinstance(exc, ArgValidationError | integrity_svc.IntegrityError)
            else f"invalid request: {exc}"
        )

    if is_htmx(request):
        if error:
            resp = render(request, "_run_error.html", error=error)
            resp.headers["HX-Retarget"] = "#run-form-errors"
            resp.headers["HX-Reswap"] = "innerHTML"
            return resp
        return runs_response(request, session, evidence_id, clear_errors=True)
    if error:
        ctx = evidence_context(session, ev, plugin_name)
        values = {k.removeprefix("arg_"): v for k, v in form.items() if k.startswith("arg_")}
        ctx.update(run_error=error, values=values)
        return render(request, "evidence.html", status_code=422, **ctx)
    return redirect(f"/evidence/{evidence_id}#runs")


@router.post("/ui/evidence/{evidence_id}/auto", dependencies=[Depends(same_origin_post)])
def ui_auto(request: Request, evidence_id: int, session: SessionDep) -> Response:
    get_evidence_or_404(session, evidence_id)
    try:
        runs = runs_svc.enqueue_auto(session, evidence_id)
    except integrity_svc.IntegrityError as exc:
        session.rollback()
        if not is_htmx(request):
            return redirect(f"/evidence/{evidence_id}#integrity")
        return runs_response(request, session, evidence_id, error=str(exc))
    session.commit()
    if not is_htmx(request):
        return redirect(f"/evidence/{evidence_id}#runs")
    return runs_response(
        request, session, evidence_id, message=f"Queued {len(runs)} auto-enumeration run(s)."
    )


@router.post("/ui/runs/{run_id}/cancel", dependencies=[Depends(same_origin_post)])
def ui_cancel(request: Request, run_id: int, session: SessionDep) -> Response:
    run = get_run_or_404(session, run_id)
    error = None
    try:
        runs_svc.cancel_run(session, run_id)
        session.commit()
    except (ValueError, LookupError) as exc:
        session.rollback()
        error = f"Cancel failed: {exc}"
    if not is_htmx(request):
        return redirect(request.headers.get("referer") or f"/evidence/{run.evidence_id}#runs")
    return runs_response(request, session, run.evidence_id, error=error)


@router.get("/ui/runs/{run_id}/rows", response_class=HTMLResponse)
def ui_rows(
    request: Request,
    session: SessionDep,
    run_id: int,
    offset: int = 0,
    limit: int = PAGE_SIZE,
) -> Response:
    """Query parameters as for the run page (q, tag, sort, desc, f.<column>, offset, limit)."""
    run = get_run_or_404(session, run_id)
    view = results_svc.RowView.from_params(request.query_params)
    if not is_htmx(request):
        return redirect(page_url(run_id, view, offset=offset or None, limit=limit))
    return render(request, "_rows.html", **rows_context(session, run, view, offset, limit))


@router.get("/ui/runs/{run_id}/export")
def ui_export(
    request: Request, run_id: int, session: SessionDep, choice: str = "csv:view"
) -> Response:
    """Export dialog target: choice = "<csv|jsonl>:<view|all>" or "raw"."""
    from app.api.runs import export_response

    run = get_run_or_404(session, run_id)
    fmt, _, scope = choice.partition(":")
    if fmt not in ("csv", "jsonl", "raw"):
        raise HTTPException(422, "unknown export format")
    params = request.query_params if scope == "view" else {}
    return export_response(session, run, params, fmt)


@router.post("/ui/runs/{run_id}/hooks/rerun", dependencies=[Depends(same_origin_post)])
def ui_rerun_hooks(request: Request, run_id: int, session: SessionDep) -> Response:
    """Re-run post-processing hooks on a finished run (no re-run of the tool)."""
    run = get_run_or_404(session, run_id)
    try:
        hooks_mod.load_hooks(force=True)  # pick up edited hook code without a restart
        results = hooks_mod.run_hooks(session, run_id)
    except ValueError as exc:
        session.rollback()
        return _render_run_page(request, session, run, message=str(exc))
    session.refresh(run)
    failed = sum(1 for r in results if r.get("status") != "ok")
    message = f"Post-processing re-run: {len(results)} hook(s), {failed} failed."
    return _render_run_page(request, session, run, message=message)


@router.get("/ui/evidence/{evidence_id}/ai", response_class=HTMLResponse)
def ui_ai_history(request: Request, evidence_id: int, session: SessionDep) -> Response:
    get_evidence_or_404(session, evidence_id)
    if not is_htmx(request):
        return redirect(f"/evidence/{evidence_id}#ai")
    return render(
        request,
        "_ai_history.html",
        messages=ai_history(session, evidence_id),
        evidence_id=evidence_id,
        runs_panel=True,
    )


def _parse_int_list(raw: str | None) -> list[int] | None:
    ids = [int(x) for x in re.split(r"[,\s]+", raw or "") if x.isdigit()]
    return ids or None


@router.post("/ui/evidence/{evidence_id}/ai/ask", dependencies=[Depends(same_origin_post)])
def ui_ai_ask(
    request: Request,
    evidence_id: int,
    form: FormDep,
    session: SessionDep,
) -> Response:
    get_evidence_or_404(session, evidence_id)
    question = (form.get("question") or "").strip()
    error = None
    if question:
        ai_svc.ask(session, evidence_id, question, run_ids=_parse_int_list(form.get("run_ids")))
        session.commit()
    else:
        error = "Enter a question."
    if not is_htmx(request):
        return redirect(f"/evidence/{evidence_id}#ai")
    return render(
        request,
        "_ai_history.html",
        messages=ai_history(session, evidence_id),
        evidence_id=evidence_id,
        runs_panel=True,
        error=error,
    )


@router.post("/ui/runs/{run_id}/summarize", dependencies=[Depends(same_origin_post)])
def ui_summarize(request: Request, run_id: int, session: SessionDep) -> Response:
    run = get_run_or_404(session, run_id)
    msg = ai_svc.summarize_run(session, run_id)
    session.commit()
    if not is_htmx(request):
        return _render_run_page(request, session, run, summary=msg)
    return render(request, "_ai_message.html", msg=msg, evidence_id=run.evidence_id)


# --------------------------------------------------------------------------- audit + note history

AUDIT_PAGE_SIZE = 100


@router.get("/activity", response_class=HTMLResponse)
def activity_page(
    request: Request,
    session: SessionDep,
    category: str | None = None,
    action: str | None = None,
    evidence_id: str | None = None,
    object_type: str | None = None,
    object_id: str | None = None,
    offset: int = 0,
) -> HTMLResponse:
    return _render_activity(
        request, session, category, action, evidence_id, object_type, object_id, offset
    )


def _render_activity(
    request: Request,
    session: Session,
    category: str | None = None,
    action: str | None = None,
    evidence_id: str | None = None,
    object_type: str | None = None,
    object_id: str | None = None,
    offset: int = 0,
    report: audit_svc.ChainReport | None = None,
) -> HTMLResponse:
    filters = {
        "category": (category or "").strip() or None,
        "action": (action or "").strip() or None,
        "evidence_id": _int_or_none(evidence_id),
        "object_type": (object_type or "").strip() or None,
        "object_id": _int_or_none(object_id),
    }
    offset = max(0, offset)
    events, total = audit_svc.list_events(session, **filters, offset=offset, limit=AUDIT_PAGE_SIZE)
    query = {k: v for k, v in filters.items() if v is not None}

    def page_link(new_offset: int) -> str:
        return "/activity?" + urlencode({**query, "offset": new_offset})

    return render(
        request,
        "activity.html",
        events=events,
        total=total,
        offset=offset,
        limit=AUDIT_PAGE_SIZE,
        filters=filters,
        categories=audit_svc.CATEGORIES,
        audit_level=get_settings().audit_level,
        report=report,
        prev_link=page_link(max(0, offset - AUDIT_PAGE_SIZE)) if offset > 0 else None,
        next_link=page_link(offset + AUDIT_PAGE_SIZE) if offset + AUDIT_PAGE_SIZE < total else None,
        evidence_id=filters["evidence_id"],
    )


def _int_or_none(value: str | None) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except ValueError:
        return None


@router.post("/ui/audit/verify", dependencies=[Depends(same_origin_post)])
def ui_audit_verify(request: Request, session: SessionDep) -> Response:
    report = audit_svc.verify_and_record(session)
    return _render_activity(request, session, report=report)


@router.get("/notes/{note_id}/history", response_class=HTMLResponse)
def note_history(request: Request, note_id: int, session: SessionDep) -> HTMLResponse:
    versions = notes_svc.list_versions(session, note_id)
    if not versions:
        raise HTTPException(404, f"no history for note {note_id}")
    return render(
        request,
        "note_history.html",
        note_id=note_id,
        versions=versions,
        evidence_id=versions[-1].evidence_id,
    )


# --------------------------------------------------------------------------- integrity


@router.post("/ui/evidence/{evidence_id}/expected-hashes", dependencies=[Depends(same_origin_post)])
def ui_expected_hashes(
    request: Request, evidence_id: int, form: FormDep, session: SessionDep
) -> Response:
    ev = get_evidence_or_404(session, evidence_id)
    try:
        integrity_svc.set_expected_hashes(
            session,
            evidence_id,
            sha256=form.get("expected_sha256"),
            md5=form.get("expected_md5"),
            sha1=form.get("expected_sha1"),
        )
    except ValueError as exc:
        session.rollback()
        ctx = evidence_context(session, ev)
        ctx.update(integrity_error=str(exc), expected_values=form)
        return render(request, "evidence.html", status_code=422, **ctx)
    return redirect(f"/evidence/{evidence_id}#integrity")


@router.post("/ui/evidence/{evidence_id}/acknowledge", dependencies=[Depends(same_origin_post)])
def ui_acknowledge_mismatch(
    request: Request, evidence_id: int, form: FormDep, session: SessionDep
) -> Response:
    ev = get_evidence_or_404(session, evidence_id)
    try:
        integrity_svc.acknowledge_mismatch(session, evidence_id, form.get("reason") or "")
    except ValueError as exc:
        session.rollback()
        ctx = evidence_context(session, ev)
        ctx.update(integrity_error=str(exc))
        return render(request, "evidence.html", status_code=422, **ctx)
    return redirect(f"/evidence/{evidence_id}#integrity")


# --------------------------------------------------------------------------- artifacts


@router.get("/ui/artifacts/{artifact_id}/download")
def ui_artifact_download(
    artifact_id: int,
    session: SessionDep,
    format: str = "zip",  # noqa: A002
) -> Response:
    from app.api.artifacts import file_download

    if format not in ("zip", "raw"):
        raise HTTPException(422, "format must be zip or raw")
    return file_download(session, artifact_id, format)
