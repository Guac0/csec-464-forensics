"""Temporary server-rendered UI (Jinja2 + HTMX). Proof of concept; will be replaced.

Progressive enhancement: every form has a normal action/method. Mutating endpoints return an
HTML fragment for HTMX requests (``HX-Request: true``) and a 303 redirect back otherwise.
"""

from __future__ import annotations

import json
import logging
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
from app.services.resources import DiskSpaceError
from app.services.runs import RERUNNABLE_STATUSES
from app.tools import hooks as hooks_mod
from app.tools import registry
from app.tools.base import ArgValidationError, PluginSpec, ToolRequest

TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

logger = logging.getLogger(__name__)

router = APIRouter(include_in_schema=False)

PAGE_SIZE = 100
MAX_PAGE_SIZE = 500
STDERR_TAIL_BYTES = 4096
ACTIVE_STATUSES = (RunStatus.QUEUED, RunStatus.RUNNING)
SEVERITIES = hooks_mod.SEVERITIES
ANY_TAG = "*"  # tag filter value meaning "any annotated row"
UI_ORIGINS = {
    "manual": RunOrigin.MANUAL,
    "preset": RunOrigin.PRESET,
    "ai": RunOrigin.AI_SUGGESTED,
    "recommended": RunOrigin.RECOMMENDED,
}
# HTMX events: the runs list and the recommendations panel refresh each other.
RUNS_CHANGED = "runs-changed"  # recommendations panel queued runs -> runs list reloads
RECOMMENDATIONS_CHANGED = "recommendations-changed"  # runs queued elsewhere -> panel reloads


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


def _deleted_run_ids(run_ids: set[int]) -> set[int]:
    """Which of ``run_ids`` are deleted (tombstoned) runs."""
    if not run_ids:
        return set()
    from app.db import SessionLocal

    try:
        with SessionLocal() as s:
            return set(
                s.scalars(select(Run.id).where(Run.id.in_(run_ids), Run.deleted_at.is_not(None)))
            )
    except Exception:
        return set()


def render_ai_content(content: str | None, citations: list[dict[str, Any]] | None = None) -> Markup:
    """Escape AI text completely, then turn citation tokens like [R12:34] into row links.

    Never renders markdown/HTML: evidence strings quoted by the model may contain markup.
    """
    cits = [c for c in (citations or []) if isinstance(c, dict)]
    invalid = {str(c.get("key")) for c in cits if c.get("valid") is False}
    unsupported = {
        str(c.get("key")): ", ".join(str(v) for v in c.get("unsupported_values") or [])
        for c in cits
        if c.get("valid") and c.get("support") == "unsupported"
    }
    escaped = str(escape(content or ""))
    deleted = _deleted_run_ids({int(m.group(1)) for m in _CITE_KEY_RE.finditer(escaped)})

    def _key(m: re.Match[str]) -> str:
        run_id, row_idx = int(m.group(1)), int(m.group(2))
        key = f"R{run_id}:{row_idx}"
        if key in invalid:
            return f'<span class="cite-invalid" title="citation not found in database">{key}</span>'
        if run_id in deleted:
            return (
                f'<a class="cite cite-deleted" href="/runs/{run_id}" '
                f'title="run {run_id} was deleted; this row no longer exists">{key}</a>'
            )
        href = f"/runs/{run_id}?row={row_idx}#row-{run_id}-{row_idx}"
        if key in unsupported:
            # Values come from the model's text: escape them for the attribute.
            title = escape(f"cited row doesn't support this: {unsupported[key]} not found in row")
            return f'<a class="cite cite-unsupported" href="{href}" title="{title}">{key}</a>'
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
    secs=lambda v: fmt_secs(v),
    row_url=lambda k: row_url(k),
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


def request_case_id(request: Request) -> int | None:
    """The active case: ``?case=<id>`` on the page, or (for HTMX fragment requests) on the page
    that made the request (HX-Current-URL). Membership is checked where it matters."""
    from urllib.parse import parse_qs, urlparse

    raw = request.query_params.get("case")
    if not raw and request.headers.get("HX-Current-URL"):
        raw = (parse_qs(urlparse(request.headers["HX-Current-URL"]).query).get("case") or [""])[0]
    return int(raw) if raw and raw.isdigit() else None


def render(request: Request, name: str, status_code: int = 200, **context: Any) -> HTMLResponse:
    # Case context travels in the URL (?case=<id>) so links keep it.
    case_id = context.setdefault("active_case_id", request_case_id(request))
    context.setdefault("case_q", f"?case={case_id}" if case_id else "")
    context.setdefault("case_amp", f"case={case_id}&" if case_id else "")
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


def form_values(spec: PluginSpec | None, args: dict[str, Any]) -> dict[str, Any]:
    """Inverse of parse_plugin_args: typed args -> values for the run form (Edit before run)."""
    values: dict[str, Any] = {}
    for a in spec.args if spec else ():
        if a.name not in args:
            continue
        value = args[a.name]
        if a.type == "int_list" and isinstance(value, list):
            values[a.name] = ", ".join(str(v) for v in value)
        elif a.type == "bool":
            values[a.name] = bool(value)
        else:
            values[a.name] = str(value)
    return values


def list_runs(session: Session, evidence_id: int) -> list[Run]:
    stmt = select(Run).where(Run.evidence_id == evidence_id).order_by(Run.id.desc())
    return list(session.scalars(stmt))


def list_scoped_notes(
    session: Session, evidence_id: int | None, case_id: int | None = None
) -> list[Note]:
    """Notes of one image, or of one case."""
    if case_id is not None:
        return [n for n in notes_svc.list_notes(session, case_id=case_id) if n.case_id == case_id]
    if evidence_id is None:
        return []
    notes = notes_svc.list_notes(session, evidence_id=evidence_id)
    return [n for n in notes if n.evidence_id == evidence_id]


def ai_history(session: Session, evidence_id: int) -> list[AIMessage]:
    getter = getattr(ai_svc, "get_messages", None)
    if getter is not None:
        return list(getter(session, evidence_id))
    stmt = select(AIMessage).where(AIMessage.evidence_id == evidence_id).order_by(AIMessage.id)
    return list(session.scalars(stmt))


def ai_panel_context(session: Session, evidence_id: int) -> dict[str, Any]:
    """Chat history plus AI agent tasks: a task's card replaces its goal message, and its
    answer is shown inside the card (not again in the history)."""
    from app.ai import agent

    messages = ai_history(session, evidence_id)
    try:
        tasks = agent.list_tasks(session, evidence_id)
    except Exception:  # e.g. a stubbed service in tests
        tasks = []
    by_id = {m.id: m for m in messages}
    return {
        "messages": messages,
        "task_by_msg": {t.user_message_id: agent.view(t) for t in tasks if t.user_message_id},
        "task_answers": {
            t.answer_message_id: by_id.get(t.answer_message_id)
            for t in tasks
            if t.answer_message_id
        },
    }


def fmt_secs(value: Any) -> str:
    """Seconds -> '1:05' (or '1:02:03')."""
    try:
        total = max(0, int(value))
    except (TypeError, ValueError):
        return "—"
    h, rem = divmod(total, 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"


def row_url(key: str) -> str:
    """'R12:3' -> the row's link (see CONTRACTS.md)."""
    m = _CITE_KEY_RE.fullmatch(key or "")
    if not m:
        return "#"
    run_id, row_idx = m.group(1), m.group(2)
    return f"/runs/{run_id}?row={row_idx}#row-{run_id}-{row_idx}"


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
    return render(
        request,
        "_evidence_list.html",
        evidence=evidence,
        run_counts=counts,
        evidence_cases=_evidence_cases(session),
        **extra,
    )


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


def notes_response(
    request: Request, session: Session, evidence_id: int | None, case_id: int | None = None
) -> HTMLResponse:
    notes = list_scoped_notes(session, evidence_id, case_id)
    return render(
        request, "_notes.html", notes=notes, evidence_id=evidence_id, note_case_id=case_id
    )


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
        **ai_panel_context(session, ev.id),
        "runs_panel": True,
        "values": {},
        "integrity_status": integrity_svc.status(ev),
        "integrity_problem": integrity_svc.describe_problem(ev),
        "integrity_checks": integrity_svc.list_checks(session, ev.id)[:20],
        "integrity_mode": get_settings().integrity_mode,
        "verify_on_run": get_settings().verify_on_run,
        "agent_defaults": {
            "max_steps": get_settings().agent_max_steps,
            "max_minutes": round(get_settings().agent_max_seconds / 60, 1),
        },
        "hashing": evidence_svc.is_hashing(ev.id),
        "cleanup": _cleanup_summary(session, ev.id),
        **recommendations_context(session, ev.id),
    }


def recommendations_context(
    session: Session, evidence_id: int, show_all: bool = False
) -> dict[str, Any]:
    """The "Recommended next" panel (app/services/recommendations.py). Never breaks the page."""
    from app.services import recommendations as recs_svc

    try:
        recs = recs_svc.recommend(session, evidence_id)
    except Exception:  # a broken guide must not take the image page down
        logger.exception("recommendations failed for evidence %s", evidence_id)
        recs = None
    runs = list_runs(session, evidence_id)
    return {
        "recs": recs,
        "recs_all": show_all,
        "recs_shown": recs_svc.DEFAULT_SHOWN,
        "recs_polling": any(r.status in ACTIVE_STATUSES for r in runs),
        **_ai_recommendation_context(session, evidence_id, runs),
    }


def _ai_recommendation_context(
    session: Session, evidence_id: int, runs: list[Run]
) -> dict[str, Any]:
    """Latest "what should I run next?" AI answer for the panel, and how many runs were
    queued after it (its advice may be out of date)."""
    latest = getattr(ai_svc, "latest_recommendation", lambda *_: None)(session, evidence_id)
    newer = 0
    if latest is not None and latest.created_at is not None:
        asked = latest.created_at.replace(tzinfo=None)
        newer = sum(
            1
            for r in runs
            if r.created_at is not None
            and r.created_at.replace(tzinfo=None) > asked
            and r.ai_message_id != latest.id
        )
    return {"ai_rec": latest, "ai_rec_newer_runs": newer}


def _cleanup_summary(session: Session, evidence_id: int) -> dict[str, Any]:
    """Failed / interrupted / cancelled runs that bulk clean-up would delete."""
    from app.services import run_deletion

    runs = run_deletion.cleanup_candidates(session, evidence_id)
    return {
        "count": len(runs),
        "bytes": sum(run_deletion.dir_bytes(run_deletion.run_dir(r.id)) for r in runs),
        "statuses": sorted({r.status.value for r in runs}),
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
    run_id: int,
    view: results_svc.RowView,
    fragment: bool = False,
    case: int | None = None,
    **overrides: Any,
) -> str:
    """URL of the run page (or the rows fragment) for a view, e.g. with another offset/sort."""
    params = view.to_params(**overrides)
    if case:
        params = {"case": case, **params}
    if params.get("limit") == PAGE_SIZE:
        params.pop("limit")
    base = f"/ui/runs/{run_id}/rows" if fragment else f"/runs/{run_id}"
    return f"{base}?{urlencode(params)}" if params else base


templates.env.globals.update(page_url=page_url)


def share_ctx(evidence_id: int | None, case_id: int | None) -> dict[str, Any]:
    """Sharing context for templates: the active case (if the image is in it), the cases a
    "Share" can go to, and which items of this image are already shared in the active case."""
    from app.db import SessionLocal
    from app.services import cases as cases_svc
    from app.services import sharing

    empty: dict[str, Any] = {"active": None, "label": "", "cases": [], "shared": {}}
    if not evidence_id:
        return empty
    try:
        with SessionLocal() as s:
            mine = [
                (c.id, c.name, label) for c, label in cases_svc.cases_for_evidence(s, evidence_id)
            ]
            active = next((m for m in mine if m[0] == case_id), None)
            return {
                "active": active,
                "label": active[2] if active else "",
                "cases": [active] if active else mine,
                "shared": sharing.shared_keys(s, active[0], evidence_id) if active else {},
            }
    except Exception:
        return empty


templates.env.globals.update(share_ctx=share_ctx)


def ioc_rows(case_id: int | None, run_id: int) -> dict[int, list[str]]:
    """{row_idx: [indicator, ...]} of the ACTIVE case's indicator hits on a run (other cases'
    watchlists are not shown, to keep investigations apart)."""
    if not case_id:
        return {}
    from app.db import SessionLocal
    from app.services import indicators

    try:
        with SessionLocal() as s:
            return indicators.row_hits(s, case_id, run_id)
    except Exception:
        return {}


templates.env.globals.update(ioc_rows=ioc_rows)


def suggestion_runs(evidence_id: int | None) -> dict[str, dict[str, Any]]:
    """{step key: {"id", "status"}} of the newest run per plugin + args on an image, so AI
    suggestions can show "queued / ran (run N)". Keys: recommendations.step_key."""
    from app.db import SessionLocal
    from app.services.recommendations import step_key

    if not evidence_id:
        return {}
    try:
        with SessionLocal() as s:
            runs = s.scalars(
                select(Run)
                .where(Run.evidence_id == evidence_id, Run.deleted_at.is_(None))
                .order_by(Run.id)
            )
            return {
                step_key(r.tool, r.plugin, r.args or {}): {"id": r.id, "status": r.status.value}
                for r in runs
            }
    except Exception:
        return {}


def suggestion_key(s: dict[str, Any]) -> str:
    from app.services.recommendations import step_key

    args = s.get("normalized_args", s.get("args")) or {}
    return step_key(s.get("tool") or "volatility3", str(s.get("plugin")), args)


templates.env.globals.update(suggestion_runs=suggestion_runs, suggestion_key=suggestion_key)
templates.env.globals.update(zip_password=lambda: get_settings().artifact_zip_password)


# --------------------------------------------------------------------------- pages


@router.get("/", response_class=HTMLResponse)
def index(request: Request, session: SessionDep) -> HTMLResponse:
    evidence = list(session.scalars(select(Evidence).order_by(Evidence.rel_path)))
    counts = dict(
        session.execute(select(Run.evidence_id, func.count(Run.id)).group_by(Run.evidence_id)).all()
    )
    from app.services import cases as cases_svc

    return render(
        request,
        "index.html",
        evidence=evidence,
        run_counts=counts,
        cases=cases_svc.list_cases(session),
        evidence_cases=_evidence_cases(session),
        evidence_id=None,
    )


def _evidence_cases(session: Session) -> dict[int, list[Any]]:
    """{evidence_id: [(case, label), ...]} for the evidence list's case chips."""
    from app.models import Case, CaseEvidence

    out: dict[int, list[Any]] = {}
    for ev_id, case, label in session.execute(
        select(CaseEvidence.evidence_id, Case, CaseEvidence.label)
        .join(Case, Case.id == CaseEvidence.case_id)
        .order_by(Case.name)
    ):
        out.setdefault(ev_id, []).append((case, label))
    return out


@router.get("/evidence/{evidence_id}", response_class=HTMLResponse)
def evidence_page(
    request: Request,
    session: SessionDep,
    evidence_id: int,
    plugin: str | None = None,
    case: int | None = None,
    args: str | None = None,
) -> HTMLResponse:
    ev = get_evidence_or_404(session, evidence_id)
    ctx = {**evidence_context(session, ev, plugin), **case_context(session, ev, case)}
    if args and ctx["selected_plugin"]:  # "Edit" on a recommendation: prefill the run form
        try:
            parsed = json.loads(args)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            ctx["values"] = form_values(ctx["selected_plugin"], parsed)
    return render(request, "evidence.html", **ctx)


def case_context(session: Session, ev: Evidence, case_id: int | None) -> dict[str, Any]:
    """Case panel of an image page: its cases, and (with an active case) what OTHER images
    shared in it plus what this image shared."""
    from app.services import cases as cases_svc
    from app.services import sharing

    image_cases = cases_svc.cases_for_evidence(session, ev.id)
    active = next(((c, label) for c, label in image_cases if c.id == case_id), None)
    ctx: dict[str, Any] = {
        "image_cases": image_cases,
        "active_case": active[0] if active else None,
        "active_label": active[1] if active else "",
        "case_warning": None,
        "shared_in_case": [],
        "shared_from_here": [],
        "indicator_hits": [],
    }
    if case_id and active is None:
        ctx["case_warning"] = f"This image is not in case {case_id}; showing it without a case."
        ctx["active_case_id"] = None
        ctx["case_q"] = ""
        ctx["case_amp"] = ""
        return ctx
    if active:
        ctx["shared_in_case"] = sharing.resolved_for_case(
            session, case_id, exclude_evidence_id=ev.id
        )
        ctx["shared_from_here"] = [
            sharing.resolve(session, i, case_id)
            for i in sharing.list_items(session, case_id, only_evidence_id=ev.id)
        ]
        ctx["case_labels"] = cases_svc.labels(session, case_id)
        from app.services import indicators

        ctx["indicator_hits"] = indicators.hits(session, case_id, evidence_id=ev.id)
    return ctx


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


def _active_case(session: Session, request: Request, evidence_id: int) -> Any:
    """The active case object if the request names one this image belongs to."""
    from app.services import cases as cases_svc

    case_id = request_case_id(request)
    if case_id and cases_svc.membership(session, case_id, evidence_id):
        return session.get(cases_svc.Case, case_id)
    return None


def _delete_preview(session: Session, run: Run) -> Any:
    from app.services import run_deletion

    if run.deleted_at is not None or run.status in ACTIVE_STATUSES:
        return None
    return run_deletion.preview(session, run.id)


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
        stderr_tail=stderr_tail(run)
        if run.status in (RunStatus.FAILED, RunStatus.INTERRUPTED)
        else None,
        can_rerun=run.status in RERUNNABLE_STATUSES,
        delete_preview=_delete_preview(session, run),
        summary=summary,
        evidence_id=run.evidence_id,
        hook_specs=hooks_mod.hooks_for(run.tool, run.plugin),
        hook_errors=[h for h in run.hook_results or [] if h.get("status") != "ok"],
        follow_ups=follow_ups,
        message=message,
        zip_password=get_settings().artifact_zip_password,
        active_case=_active_case(session, request, run.evidence_id),
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
def ui_notes(
    request: Request,
    session: SessionDep,
    evidence_id: int | None = None,
    case_id: int | None = None,
) -> HTMLResponse:
    return notes_response(request, session, evidence_id, case_id)


def _notes_done(
    request: Request, session: Session, evidence_id: int | None, case_id: int | None = None
) -> Response:
    session.commit()
    if not is_htmx(request):
        if case_id:
            return redirect(f"/cases/{case_id}#notes")
        return redirect(f"/evidence/{evidence_id}#notes" if evidence_id else "/")
    return notes_response(request, session, evidence_id, case_id)


@router.post("/ui/notes", dependencies=[Depends(same_origin_post)])
def ui_note_create(
    request: Request,
    form: FormDep,
    session: SessionDep,
) -> Response:
    raw_ev = (form.get("evidence_id") or "").strip()
    evidence_id = int(raw_ev) if raw_ev.isdigit() else None
    raw_case = (form.get("case_id") or "").strip()
    case_id = int(raw_case) if raw_case.isdigit() and evidence_id is None else None
    if evidence_id is not None:
        get_evidence_or_404(session, evidence_id)
    if evidence_id is None and case_id is None:
        raise HTTPException(422, "a note belongs to an image or a case")
    body = (form.get("body") or "").strip()
    if body:
        try:
            notes_svc.create_note(session, body, evidence_id=evidence_id, case_id=case_id)
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc
    return _notes_done(request, session, evidence_id, case_id)


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
    evidence_id, case_id = note.evidence_id, note.case_id
    body = (form.get("body") or "").strip()
    if body:
        notes_svc.update_note(session, note_id, body)
    return _notes_done(request, session, evidence_id, case_id)


@router.post("/ui/notes/{note_id}/delete", dependencies=[Depends(same_origin_post)])
def ui_note_delete(request: Request, note_id: int, session: SessionDep) -> Response:
    note = session.get(Note, note_id)
    if note is None:
        raise HTTPException(404, "note not found")
    evidence_id, case_id = note.evidence_id, note.case_id
    notes_svc.delete_note(session, note_id)
    return _notes_done(request, session, evidence_id, case_id)


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
        raw_msg_id = (form.get("ai_message_id") or "").strip()
        ai_message_id = int(raw_msg_id) if raw_msg_id and origin == RunOrigin.AI_SUGGESTED else None
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
            **({"ai_message_id": ai_message_id} if ai_message_id is not None else {}),
        )
        session.commit()
    except (ValueError, KeyError) as exc:  # ArgValidationError and JSON errors are ValueErrors
        session.rollback()
        error = (
            str(exc)
            if isinstance(exc, ArgValidationError | integrity_svc.IntegrityError | DiskSpaceError)
            else f"invalid request: {exc}"
        )

    if is_htmx(request):
        if error:
            resp = render(request, "_run_error.html", error=error)
            resp.headers["HX-Retarget"] = "#run-form-errors"
            resp.headers["HX-Reswap"] = "innerHTML"
            return resp
        resp = runs_response(request, session, evidence_id, clear_errors=True)
        resp.headers["HX-Trigger"] = RECOMMENDATIONS_CHANGED
        return resp
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
    except (integrity_svc.IntegrityError, DiskSpaceError) as exc:
        session.rollback()
        if not is_htmx(request):
            anchor = "integrity" if isinstance(exc, integrity_svc.IntegrityError) else "runs"
            return redirect(f"/evidence/{evidence_id}#{anchor}")
        return runs_response(request, session, evidence_id, error=str(exc))
    session.commit()
    if not is_htmx(request):
        return redirect(f"/evidence/{evidence_id}#runs")
    resp = runs_response(
        request, session, evidence_id, message=f"Queued {len(runs)} auto-enumeration run(s)."
    )
    resp.headers["HX-Trigger"] = RECOMMENDATIONS_CHANGED
    return resp


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


@router.post("/ui/runs/{run_id}/rerun", dependencies=[Depends(same_origin_post)])
def ui_rerun(request: Request, run_id: int, session: SessionDep) -> Response:
    """Queue a copy of a finished run. From the runs table (HTMX) the table is refreshed; from
    the run page the browser goes to the new run."""
    run = get_run_or_404(session, run_id)
    try:
        new_run = runs_svc.rerun(session, run_id)
    except (ValueError, LookupError) as exc:  # integrity, disk space, allowlist, still active
        session.rollback()
        error = f"Re-run failed: {exc}"
        if is_htmx(request):
            return runs_response(request, session, run.evidence_id, error=error)
        return _render_run_page(request, session, run, message=error)
    if is_htmx(request):
        return runs_response(
            request,
            session,
            run.evidence_id,
            message=f"Queued run {new_run.id} (re-run of {run_id}).",
        )
    return redirect(f"/runs/{new_run.id}")


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
        **ai_panel_context(session, evidence_id),
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
    """Ask a question, or (mode=goal) give the AI agent a goal (app/ai/agent.py)."""
    from app.ai import agent

    get_evidence_or_404(session, evidence_id)
    question = (form.get("question") or "").strip()
    error = None
    if form.get("mode") == "goal":
        try:
            minutes = (form.get("max_minutes") or "").strip()
            agent.start_task(
                session,
                evidence_id,
                question,
                max_steps=form.get("max_steps") or None,
                max_seconds=int(float(minutes) * 60) if minutes else None,
            )
        except (agent.AgentError, ValueError) as exc:
            session.rollback()
            error = str(exc)
    elif question:
        ai_svc.ask(session, evidence_id, question, run_ids=_parse_int_list(form.get("run_ids")))
        session.commit()
    else:
        error = "Enter a question."
    if not is_htmx(request):
        return redirect(f"/evidence/{evidence_id}#ai")
    return render(
        request,
        "_ai_history.html",
        **ai_panel_context(session, evidence_id),
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


# --------------------------------------------------------------------------- case export


@router.get("/ui/export")
def ui_case_export(
    session: SessionDep,
    evidence_id: str | None = None,
    format: str = "md",  # noqa: A002
    include_dumped: bool = False,
    case_id: str | None = None,
) -> Response:
    """Target of the export dialogs on the home, case and evidence pages."""
    from app.api.export import export_response

    ev_id = _int_or_none(evidence_id)
    if ev_id is not None:
        get_evidence_or_404(session, ev_id)
    return export_response(
        session, ev_id, format, include_dumped and format == "zip", _int_or_none(case_id)
    )


# --------------------------------------------------------------------------- system / health


def _health_badge() -> tuple[str, str] | None:
    """(status, tooltip) for the top-bar System link; None if the checks cannot run."""
    from app.db import SessionLocal
    from app.services import health

    try:
        with SessionLocal() as s:
            return health.badge(s)
    except Exception:
        return None


templates.env.globals.update(health_badge=_health_badge)


@router.get("/system", response_class=HTMLResponse)
def system_page(request: Request, session: SessionDep) -> HTMLResponse:
    from app.services import health

    checks = health.quick_checks(session)
    health.clear_badge_cache()
    from app.services import backup, run_deletion

    return render(
        request,
        "system.html",
        checks=checks,
        overall=health.overall(checks),
        settings_rows=health.settings_summary(),
        backups=backup.list_backups()[:15],
        backup_state=backup.manual_state(),
        biggest_runs=run_deletion.biggest_runs(session),
    )


@router.post("/ui/system/test/{kind}", dependencies=[Depends(same_origin_post)])
def ui_system_test(request: Request, kind: str) -> Response:
    from app.services import health

    tests = {"volatility": health.run_volatility_test, "ai": health.run_ai_test}
    if kind not in tests:
        raise HTTPException(404, "unknown test")
    check = tests[kind]()
    if not is_htmx(request):
        return redirect("/system")
    return render(request, "_health_check.html", check=check)


# --------------------------------------------------------------------------- run deletion


@router.post("/ui/runs/{run_id}/delete", dependencies=[Depends(same_origin_post)])
def ui_delete_run(request: Request, run_id: int, form: FormDep, session: SessionDep) -> Response:
    from app.services import run_deletion

    run = get_run_or_404(session, run_id)
    try:
        result = run_deletion.delete_run(session, run_id, form.get("reason") or "")
    except ValueError as exc:
        session.rollback()
        return _render_run_page(request, session, run, message=f"Delete failed: {exc}")
    if not result.files_removed:
        session.refresh(run)
        return _render_run_page(
            request,
            session,
            run,
            message="Deleted, but some files could not be removed; see the log.",
        )
    return redirect(f"/runs/{run_id}")


@router.post("/ui/evidence/{evidence_id}/cleanup", dependencies=[Depends(same_origin_post)])
def ui_cleanup(request: Request, evidence_id: int, form: FormDep, session: SessionDep) -> Response:
    from app.services import run_deletion

    get_evidence_or_404(session, evidence_id)
    try:
        results = run_deletion.delete_runs(session, evidence_id, form.get("reason") or "")
    except ValueError as exc:
        session.rollback()
        return runs_response(request, session, evidence_id, error=f"Clean-up failed: {exc}")
    freed = sum(r.bytes_freed for r in results)
    message = f"Deleted the data of {len(results)} run(s), freeing {humansize(freed)}."
    if not is_htmx(request):
        return redirect(f"/evidence/{evidence_id}#runs")
    return runs_response(request, session, evidence_id, message=message)


@router.post("/ui/system/backup", dependencies=[Depends(same_origin_post)])
def ui_backup_now(request: Request) -> Response:
    from app.services import backup

    started = backup.start_manual_backup()
    if not is_htmx(request):
        return redirect("/system#backups")
    return render(
        request,
        "_backup_status.html",
        state=backup.manual_state() | ({} if started else {"busy": True}),
    )


@router.get("/ui/system/backup-status", response_class=HTMLResponse)
def ui_backup_status(request: Request) -> HTMLResponse:
    from app.services import backup

    return render(request, "_backup_status.html", state=backup.manual_state())


@router.post("/ui/system/backups/{name}/verify", dependencies=[Depends(same_origin_post)])
def ui_verify_backup(request: Request, name: str) -> Response:
    from app.services import backup

    try:
        backup.get_backup(name)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    report = backup.verify_backup(name)
    if not is_htmx(request):
        return redirect("/system#backups")
    return render(request, "_backup_verify.html", report=report)
