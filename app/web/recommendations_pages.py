"""UI for the investigation guide: the "Recommended next" panel on the image page and the
read-only /guide page (see app/services/recommendations.py and app/tools/volatility/guide.py)."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import HTMLResponse

from app.ai import service as ai_svc
from app.services import integrity as integrity_svc
from app.services import recommendations as recs_svc
from app.services.resources import DiskSpaceError
from app.tools import registry
from app.tools.base import ArgValidationError
from app.tools.guide import check_guide, describe_when
from app.web.pages import (
    RUNS_CHANGED,
    FormDep,
    SessionDep,
    get_evidence_or_404,
    is_htmx,
    recommendations_context,
    redirect,
    render,
    same_origin_post,
)

router = APIRouter(include_in_schema=False)

_RUN_ERRORS = (ArgValidationError, integrity_svc.IntegrityError, DiskSpaceError)


def _panel(
    request: Request,
    session: SessionDep,
    evidence_id: int,
    show_all: bool = False,
    trigger_runs: bool = False,
    **extra: Any,
) -> HTMLResponse:
    resp = render(
        request,
        "_recommendations.html",
        evidence_id=evidence_id,
        **recommendations_context(session, evidence_id, show_all),
        **extra,
    )
    if trigger_runs:
        resp.headers["HX-Trigger"] = RUNS_CHANGED
    return resp


def _step(form: dict[str, str]) -> tuple[str, dict[str, Any], str]:
    plugin = (form.get("plugin") or "").strip()
    tool = (form.get("tool") or "volatility3").strip() or "volatility3"
    try:
        args = json.loads(form.get("args_json") or "{}")
    except ValueError:
        raise ArgValidationError("args must be a JSON object") from None
    if not plugin or not isinstance(args, dict):
        raise ArgValidationError("plugin and args are required")
    return plugin, args, tool


def _done(request: Request, session: SessionDep, evidence_id: int, **extra: Any) -> Response:
    if not is_htmx(request):
        return redirect(f"/evidence/{evidence_id}#recommendations")
    show_all = request.headers.get("HX-Current-URL", "").find("all=1") >= 0
    return _panel(request, session, evidence_id, show_all, **extra)


@router.get("/ui/evidence/{evidence_id}/recommendations", response_class=HTMLResponse)
def ui_recommendations(
    request: Request, evidence_id: int, session: SessionDep, all: int = 0
) -> HTMLResponse:
    get_evidence_or_404(session, evidence_id)
    return _panel(request, session, evidence_id, show_all=bool(all))


@router.post(
    "/ui/evidence/{evidence_id}/recommendations/run", dependencies=[Depends(same_origin_post)]
)
def ui_run_recommendation(
    request: Request, evidence_id: int, form: FormDep, session: SessionDep
) -> Response:
    get_evidence_or_404(session, evidence_id)
    try:
        plugin, args, tool = _step(form)
        run = recs_svc.run_recommendation(session, evidence_id, plugin, args, tool)
    except _RUN_ERRORS as exc:
        session.rollback()
        return _done(request, session, evidence_id, error=str(exc))
    return _done(
        request, session, evidence_id, trigger_runs=True, message=f"Queued run {run.id}: {plugin}."
    )


@router.post(
    "/ui/evidence/{evidence_id}/recommendations/baseline", dependencies=[Depends(same_origin_post)]
)
def ui_run_baseline(request: Request, evidence_id: int, session: SessionDep) -> Response:
    get_evidence_or_404(session, evidence_id)
    try:
        created = recs_svc.run_baseline(session, evidence_id)
    except _RUN_ERRORS as exc:
        session.rollback()
        return _done(request, session, evidence_id, error=str(exc))
    return _done(
        request,
        session,
        evidence_id,
        trigger_runs=True,
        message=f"Queued {len(created)} baseline step(s).",
    )


@router.post(
    "/ui/evidence/{evidence_id}/recommendations/dismiss", dependencies=[Depends(same_origin_post)]
)
def ui_dismiss(request: Request, evidence_id: int, form: FormDep, session: SessionDep) -> Response:
    get_evidence_or_404(session, evidence_id)
    try:
        plugin, args, tool = _step(form)
        recs_svc.dismiss(session, evidence_id, plugin, args, tool)
    except ArgValidationError as exc:
        session.rollback()
        return _done(request, session, evidence_id, error=str(exc))
    return _done(request, session, evidence_id)


@router.post(
    "/ui/evidence/{evidence_id}/recommendations/restore", dependencies=[Depends(same_origin_post)]
)
def ui_restore(request: Request, evidence_id: int, form: FormDep, session: SessionDep) -> Response:
    get_evidence_or_404(session, evidence_id)
    try:
        plugin, args, tool = _step(form)
        recs_svc.restore(session, evidence_id, plugin, args, tool)
    except ArgValidationError as exc:
        session.rollback()
        return _done(request, session, evidence_id, error=str(exc))
    return _done(request, session, evidence_id)


AI_HISTORY_CHANGED = "ai-history-changed"  # the AI chat panel reloads


@router.post(
    "/ui/evidence/{evidence_id}/recommendations/ai", dependencies=[Depends(same_origin_post)]
)
def ui_ai_recommend(
    request: Request, evidence_id: int, form: FormDep, session: SessionDep
) -> Response:
    """Ask the AI what to run next (blocks on the provider; provider errors are stored on the
    answer, never raised). The answer goes to the AI chat; the panel shows its suggestions."""
    get_evidence_or_404(session, evidence_id)
    ai_svc.recommend_next(session, evidence_id, form.get("focus") or "")
    session.commit()
    resp = _done(request, session, evidence_id)
    if is_htmx(request):
        resp.headers["HX-Trigger"] = AI_HISTORY_CHANGED
    return resp


@router.get("/guide", response_class=HTMLResponse)
def guide_page(request: Request, tool: str = "volatility3") -> HTMLResponse:
    """Read-only view of the investigation guide, for analysts and developers."""
    runner = registry.get_runner(tool)
    guide, problems = check_guide(runner)
    specs = {p.name: p for p in runner.plugins()}
    return render(
        request,
        "guide.html",
        tool=tool,
        guide=guide,
        problems=problems,
        specs=specs,
        describe_when=describe_when,
    )
