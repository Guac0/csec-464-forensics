"""UI for AI agent tasks ("give the AI a goal"; see app/ai/agent.py). Tasks are started from
the AI chat form (pages.ui_ai_ask, mode=goal); their cards live in the chat history."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse

from app.ai import agent
from app.models import AIMessage
from app.web.pages import SessionDep, is_htmx, redirect, render, same_origin_post, templates

router = APIRouter(include_in_schema=False)
templates.env.globals.update(describe_call=agent.describe_call)


def _card(request: Request, session: SessionDep, task_id: int) -> HTMLResponse:
    try:
        task = agent.get_task(session, task_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    answer = session.get(AIMessage, task.answer_message_id) if task.answer_message_id else None
    return render(
        request,
        "_ai_task.html",
        tv=agent.view(task),
        answer=answer,
        evidence_id=task.evidence_id,
        runs_panel=True,
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
