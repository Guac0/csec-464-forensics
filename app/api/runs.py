"""JSON API: runs and their parsed result rows."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.db import get_session
from app.models import Run, RunOrigin, RunStatus
from app.services import runs as runs_service
from app.tools.base import ArgValidationError, ToolRequest

SessionDep = Annotated[Session, Depends(get_session)]

router = APIRouter(prefix="/api/runs", tags=["runs"])


class RunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    evidence_id: int
    tool: str
    plugin: str
    args: dict[str, Any]
    argv: list[str] | None
    origin: RunOrigin
    status: RunStatus
    tool_version: str | None
    evidence_sha256: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    heartbeat_at: datetime | None
    returncode: int | None
    stdout_path: str | None
    stderr_path: str | None
    stdout_sha256: str | None
    row_count: int
    error: str | None
    hook_results: list[dict[str, Any]] | None
    findings: list[dict[str, Any]] | None
    parent_run_id: int | None
    triggered_by_hook: str | None
    chain_depth: int


class RunCreate(BaseModel):
    evidence_id: int
    plugin: str
    args: dict[str, Any] = Field(default_factory=dict)
    origin: RunOrigin = RunOrigin.MANUAL
    tool: str = "volatility3"


class RowOut(BaseModel):
    citation: str
    row_idx: int
    depth: int
    parent_idx: int | None
    data: dict[str, Any]
    annotations: list[dict[str, Any]] | None


class RowsPage(BaseModel):
    total: int
    offset: int
    limit: int
    rows: list[RowOut]


def _get_or_404(session: Session, run_id: int) -> Run:
    try:
        return runs_service.get_run(session, run_id)
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc


@router.get("", response_model=list[RunOut])
def list_runs(session: SessionDep, evidence_id: int | None = None) -> list[Run]:
    return runs_service.list_runs(session, evidence_id)


@router.post("", response_model=RunOut, status_code=201)
def create_run(body: RunCreate, session: SessionDep) -> Run:
    if body.origin == RunOrigin.HOOK:
        raise HTTPException(422, "origin 'hook' is reserved for runs queued by post-run hooks")
    try:
        return runs_service.create_run(
            session,
            body.evidence_id,
            ToolRequest(plugin=body.plugin, args=body.args),
            origin=body.origin,
            tool=body.tool,
        )
    except ArgValidationError as exc:
        raise HTTPException(422, str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc


@router.get("/{run_id}", response_model=RunOut)
def get_run(run_id: int, session: SessionDep) -> Run:
    return _get_or_404(session, run_id)


@router.post("/{run_id}/cancel", response_model=RunOut)
def cancel_run(run_id: int, session: SessionDep) -> Run:
    _get_or_404(session, run_id)
    return runs_service.cancel_run(session, run_id)


@router.get("/{run_id}/rows", response_model=RowsPage)
def get_rows(
    run_id: int,
    session: SessionDep,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    q: str | None = None,
    annotated: bool = False,
    tag: str | None = None,
) -> RowsPage:
    _get_or_404(session, run_id)
    rows, total = runs_service.get_rows(
        session, run_id, offset=offset, limit=limit, q=q, annotated=annotated, tag=tag
    )
    return RowsPage(
        total=total,
        offset=offset,
        limit=limit,
        rows=[
            RowOut(
                citation=r.citation,
                row_idx=r.row_idx,
                depth=r.depth,
                parent_idx=r.parent_idx,
                data=r.data,
                annotations=r.annotations,
            )
            for r in rows
        ],
    )


@router.post("/{run_id}/hooks/rerun", response_model=RunOut)
def rerun_hooks(run_id: int, session: SessionDep) -> Run:
    """Run the post-run hooks again (e.g. after changing hook code) without re-running the tool.
    Previous annotations, findings and hook results of this run are replaced."""
    from app.tools import hooks

    run = _get_or_404(session, run_id)
    try:
        hooks.run_hooks(session, run_id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    session.refresh(run)
    return run
