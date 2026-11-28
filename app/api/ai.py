"""JSON API for the AI layer. Endpoints are plain `def` (run in the threadpool) because they
block on the external AI provider."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.ai import service
from app.ai.context import NotFoundError
from app.db import get_session
from app.models import AIMessage

router = APIRouter(prefix="/api/ai", tags=["ai"])


class AskRequest(BaseModel):
    evidence_id: int
    question: str = Field(min_length=1, max_length=20000)
    run_ids: list[int] | None = None
    row_refs: list[str] | None = None


class TaskRequest(BaseModel):
    evidence_id: int
    goal: str = Field(max_length=2000)
    max_steps: int | None = None
    max_seconds: int | None = None


class RecommendRequest(BaseModel):
    evidence_id: int
    focus: str = Field(default="", max_length=300)


class AIMessageOut(BaseModel):
    id: int
    evidence_id: int | None
    role: str
    content: str
    is_ai_output: bool
    model_requested: str | None
    model_returned: str | None
    provider_base_url: str | None
    params: dict[str, Any] | None
    request_messages: list[dict[str, Any]] | None
    context_refs: dict[str, Any] | None
    citations: list[dict[str, Any]] | None
    suggestions: list[dict[str, Any]] | None
    usage: dict[str, Any] | None
    error: str | None
    created_at: datetime


def message_out(msg: AIMessage) -> AIMessageOut:
    return AIMessageOut(
        id=msg.id,
        evidence_id=msg.evidence_id,
        role=msg.role,
        content=msg.content,
        is_ai_output=msg.role == "assistant",
        model_requested=msg.model_requested,
        model_returned=msg.model_returned,
        provider_base_url=msg.provider_base_url,
        params=msg.params,
        request_messages=msg.request_messages,
        context_refs=msg.context_refs,
        citations=msg.citations,
        suggestions=msg.suggestions,
        usage=msg.usage,
        error=msg.error,
        created_at=msg.created_at,
    )


@router.post("/ask", response_model=AIMessageOut)
def ask(body: AskRequest, session: Session = Depends(get_session)) -> AIMessageOut:  # noqa: B008
    try:
        msg = service.ask(
            session,
            body.evidence_id,
            body.question,
            run_ids=body.run_ids,
            row_refs=body.row_refs,
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return message_out(msg)


@router.post("/recommend", response_model=AIMessageOut)
def recommend(body: RecommendRequest, session: Session = Depends(get_session)) -> AIMessageOut:  # noqa: B008
    """ "What should I run next?": suggestions from the investigation state (runs, hook
    findings, flagged rows, the guide's static recommendations). Stored in the chat history."""
    try:
        msg = service.recommend_next(session, body.evidence_id, body.focus)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return message_out(msg)


@router.post("/summarize/{run_id}", response_model=AIMessageOut)
def summarize(run_id: int, session: Session = Depends(get_session)) -> AIMessageOut:  # noqa: B008
    try:
        msg = service.summarize_run(session, run_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return message_out(msg)


@router.get("/messages", response_model=list[AIMessageOut])
def messages(
    evidence_id: int,
    session: Session = Depends(get_session),  # noqa: B008
) -> list[AIMessageOut]:
    return [message_out(m) for m in service.get_messages(session, evidence_id)]


# --------------------------------------------------------------------------- AI agent tasks


@router.post("/tasks", status_code=201)
def start_task(body: TaskRequest, session: Session = Depends(get_session)) -> dict[str, Any]:  # noqa: B008
    """Give the AI agent a goal for one image (read-only tools; runs in the background).
    Poll GET /api/ai/tasks/{id} for status, steps and the answer message id."""
    from app.ai import agent

    try:
        task = agent.start_task(
            session, body.evidence_id, body.goal, body.max_steps, body.max_seconds
        )
    except agent.AgentError as exc:
        status = 404 if "not found" in str(exc) else 422
        raise HTTPException(status_code=status, detail=str(exc)) from exc
    session.refresh(task)
    return agent.view(task).as_dict()


@router.get("/tasks")
def list_tasks(evidence_id: int, session: Session = Depends(get_session)) -> list[dict[str, Any]]:  # noqa: B008
    from app.ai import agent

    return [agent.view(t).as_dict() for t in agent.list_tasks(session, evidence_id)]


@router.get("/tasks/{task_id}")
def get_task(task_id: int, session: Session = Depends(get_session)) -> dict[str, Any]:  # noqa: B008
    from app.ai import agent

    try:
        return agent.view(agent.get_task(session, task_id)).as_dict()
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/tasks/{task_id}/cancel")
def cancel_task(task_id: int, session: Session = Depends(get_session)) -> dict[str, Any]:  # noqa: B008
    from app.ai import agent

    try:
        return agent.view(agent.cancel_task(session, task_id)).as_dict()
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
