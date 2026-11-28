"""UI for AI agent tasks ("give the AI a goal"; see app/ai/agent.py). Tasks are started from
the AI chat form (pages.ui_ai_ask, mode=goal); their cards live in the chat history."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse

from app.ai import agent
from app.models import AIMessage, AIRunRequest
from app.tools.base import ArgValidationError
from app.web.pages import (
    FormDep,
    SessionDep,
    find_plugin,
    form_values,
    is_htmx,
    parse_plugin_args,
    redirect,
    render,
    same_origin_post,
    templates,
)

router = APIRouter(include_in_schema=False)


def ai_run_request(run: Any) -> AIRunRequest | None:
    """The AI run request behind a run queued by an AI task (for the run page)."""
    from sqlalchemy import select

    from app.db import SessionLocal

    if not getattr(run, "ai_task_id", None):
        return None
    try:
        with SessionLocal() as s:
            req = s.scalars(select(AIRunRequest).where(AIRunRequest.run_id == run.id)).first()
            if req is not None:
                s.expunge(req)
            return req
    except Exception:
        return None


templates.env.globals.update(
    describe_call=agent.describe_call,
    plugin_spec=find_plugin,
    form_values=form_values,
    ai_run_request=ai_run_request,
)


def _card(
    request: Request, session: SessionDep, task_id: int, error: str | None = None
) -> HTMLResponse:
    try:
        task = agent.get_task(session, task_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    answer = session.get(AIMessage, task.answer_message_id) if task.answer_message_id else None
    return render(
        request,
        "_ai_task.html",
        tv=agent.view(task, session),
        answer=answer,
        evidence_id=task.evidence_id,
        runs_panel=True,
        task_error=error,
    )


@router.get("/ui/ai/tasks/{task_id}", response_class=HTMLResponse)
def ui_task(request: Request, task_id: int, session: SessionDep) -> Response:
    """The task's card (polled every 2 s while the task is queued or running)."""
    if not is_htmx(request):
        task = session.get(agent.AITask, task_id)
        return redirect(f"/evidence/{task.evidence_id}#ai-task-{task_id}" if task else "/")
    return _card(request, session, task_id)


@router.post("/ui/ai/tasks/{task_id}/cancel", dependencies=[Depends(same_origin_post)])
def ui_cancel_task(request: Request, task_id: int, session: SessionDep) -> Response:
    try:
        task = agent.cancel_task(session, task_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    if not is_htmx(request):
        return redirect(f"/evidence/{task.evidence_id}#ai-task-{task_id}")
    return _card(request, session, task_id)


@router.post("/ui/ai/run-requests/{request_id}/decide", dependencies=[Depends(same_origin_post)])
def ui_decide(request: Request, request_id: int, form: FormDep, session: SessionDep) -> Response:
    """Approve / edit options / deny (with note) one run request of an AI task."""
    req = session.get(AIRunRequest, request_id)
    if req is None:
        raise HTTPException(404, "run request not found")
    task_id = req.task_id
    action = form.get("action") or ""
    error = None
    try:
        args = None
        if action == "edit":
            spec = find_plugin(req.plugin, req.tool)
            if spec is None:
                raise agent.ApprovalError(f"plugin not allowed: {req.plugin!r}")
            args = parse_plugin_args(spec, form)
        agent.decide(session, request_id, action, args, form.get("note") or "")
    except (agent.ApprovalError, ArgValidationError) as exc:
        session.rollback()
        error = str(exc)
    if not is_htmx(request):
        return redirect(f"/evidence/{req.task.evidence_id}#ai-task-{task_id}")
    return _card(request, session, task_id, error=error)


@router.post("/ui/ai/tasks/{task_id}/approve-all", dependencies=[Depends(same_origin_post)])
def ui_approve_all(request: Request, task_id: int, session: SessionDep) -> Response:
    error = None
    try:
        task = agent.approve_all_remaining(session, task_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except agent.ApprovalError as exc:
        session.rollback()
        error = str(exc)
        task = agent.get_task(session, task_id)
    if not is_htmx(request):
        return redirect(f"/evidence/{task.evidence_id}#ai-task-{task_id}")
    return _card(request, session, task_id, error=error)
