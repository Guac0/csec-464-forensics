"""JSON API: runs and their parsed result rows."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import SessionLocal, get_session
from app.models import Run, RunOrigin, RunStatus
from app.services import audit, results
from app.services import runs as runs_service
from app.tools.base import ArgValidationError, ToolRequest
from app.tools.executor import sha256_file

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
    evidence_size_bytes: int | None
    evidence_mtime: float | None
    integrity_warning: str | None
    phase: str | None
    artifact_count: int = 0
    columns: list[dict[str, Any]] | None = None
    search_indexed: bool = False
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
    rerun_of_id: int | None = None
    deleted_at: datetime | None = None
    delete_reason: str | None = None
    chain_depth: int
    ai_message_id: int | None = None
    ai_task_id: int | None = None


class RunCreate(BaseModel):
    evidence_id: int
    plugin: str
    args: dict[str, Any] = Field(default_factory=dict)
    origin: RunOrigin = RunOrigin.MANUAL
    tool: str = "volatility3"
    # The AI answer whose suggestion this is (origin "ai" only).
    ai_message_id: int | None = None


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
    if body.origin == RunOrigin.AI_AGENT:
        raise HTTPException(422, "origin 'agent' is reserved for runs queued by AI agent tasks")
    try:
        return runs_service.create_run(
            session,
            body.evidence_id,
            ToolRequest(plugin=body.plugin, args=body.args),
            origin=body.origin,
            tool=body.tool,
            ai_message_id=body.ai_message_id,
        )
    except ArgValidationError as exc:
        raise HTTPException(422, str(exc)) from exc
    except runs_service.IntegrityError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except runs_service.DiskSpaceError as exc:
        raise HTTPException(status.HTTP_507_INSUFFICIENT_STORAGE, str(exc)) from exc
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
    request: Request,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    q: str | None = None,
    annotated: bool = False,
    tag: str | None = None,
    sort: str | None = None,
    desc: bool = False,
) -> RowsPage:
    """Rows of a run. Search ``q``; hook annotations ``annotated``/``tag``; sort by a column
    (``sort``, ``desc``); per-column filters as ``f.<column>=<expression>`` where the expression
    is text (contains) or starts with =, !=, >, >=, <, <= (numbers compare numerically)."""
    run = _get_or_404(session, run_id)
    view = results.RowView.from_params(request.query_params)
    try:
        rows, total = results.query_rows(session, run, view, offset=offset, limit=limit)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
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


@router.post("/{run_id}/rerun", response_model=RunOut, status_code=201)
def rerun(run_id: int, session: SessionDep) -> Run:
    """Queue a new run with the same plugin and args (e.g. after it was interrupted)."""
    _get_or_404(session, run_id)
    try:
        return runs_service.rerun(session, run_id)
    except runs_service.IntegrityError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except runs_service.DiskSpaceError as exc:
        raise HTTPException(status.HTTP_507_INSUFFICIENT_STORAGE, str(exc)) from exc
    except ArgValidationError as exc:
        raise HTTPException(422, f"cannot re-run: {exc}") from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc


class DeleteIn(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)


@router.get("/{run_id}/delete-preview")
def delete_preview(run_id: int, session: SessionDep) -> dict[str, Any]:
    """What deleting this run would remove (rows, bytes, dumped files) and what cites it."""
    from dataclasses import asdict

    from app.services import run_deletion

    _get_or_404(session, run_id)
    return asdict(run_deletion.preview(session, run_id))


@router.post("/{run_id}/delete", response_model=RunOut)
def delete_run(run_id: int, body: DeleteIn, session: SessionDep) -> Run:
    """Delete the run's rows, raw output and dumped files, keeping a tombstone record (with its
    hashes) and the audit history. Not possible while queued or running."""
    from app.services import run_deletion

    run = _get_or_404(session, run_id)
    try:
        run_deletion.delete_run(session, run_id, body.reason)
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    session.refresh(run)
    return run


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


EXPORT_MEDIA = {"csv": "text/csv; charset=utf-8", "jsonl": "application/x-ndjson"}


@router.get("/{run_id}/export")
def export_run(
    run_id: int,
    session: SessionDep,
    request: Request,
    format: Literal["csv", "jsonl", "raw"] = "csv",  # noqa: A002
) -> Response:
    """Download a run: ``csv`` / ``jsonl`` = all rows of the current view (same q/tag/sort/f.*
    parameters as /rows), ``raw`` = the tool's original output file. Audited (key_read)."""
    run = _get_or_404(session, run_id)
    return export_response(session, run, request.query_params, format)


def export_response(session: Session, run: Run, params: Any, fmt: str) -> Response:
    view = results.RowView.from_params(params)
    base = f"run-{run.id}-{run.plugin.rsplit('.', 1)[-1].lower()}"
    if run.deleted_at is not None:
        raise HTTPException(status.HTTP_410_GONE, f"run {run.id} was deleted: {run.delete_reason}")
    if fmt == "raw":
        path = (get_settings().data_dir / run.stdout_path) if run.stdout_path else None
        if path is None or not path.is_file():
            raise HTTPException(status.HTTP_404_NOT_FOUND, "this run has no stored tool output")
        if run.stdout_sha256 and sha256_file(path) != run.stdout_sha256:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "the stored tool output no longer matches the SHA-256 recorded for this run",
            )
        _audit_export(session, run, "raw", None)
        return FileResponse(
            path,
            media_type="application/octet-stream",
            filename=f"{base}-raw-output.jsonl",
            headers={"X-Content-Type-Options": "nosniff"},
        )
    if fmt not in EXPORT_MEDIA:
        raise HTTPException(422, "format must be csv, jsonl or raw")
    _audit_export(session, run, fmt, view)
    run_id = run.id

    def stream() -> Iterator[str]:
        # Own session: the request's session may be closed before streaming finishes.
        with SessionLocal() as s:
            run_ = s.get(Run, run_id)
            yield from results.export_rows(s, run_, view, fmt)

    suffix = "-filtered" if view.active else ""
    return StreamingResponse(
        stream(),
        media_type=EXPORT_MEDIA[fmt],
        headers={
            "Content-Disposition": f'attachment; filename="{base}{suffix}.{fmt}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


def _audit_export(session: Session, run: Run, fmt: str, view: Any) -> None:
    audit.record(
        session,
        "run.export",
        category=audit.KEY_READ,
        object_type="run",
        object_id=run.id,
        evidence_id=run.evidence_id,
        summary=f"Exported run {run.id} ({fmt}"
        + (", current view" if view is not None and view.active else "")
        + ")",
        details={"format": fmt, "view": view.describe() if view is not None else None},
    )
    session.commit()


@router.post("/{run_id}/search-index", response_model=RunOut)
def build_search_index(run_id: int, session: SessionDep) -> Run:
    """Add an existing run's rows to the full-text search index (see FT_SEARCH_INDEX)."""
    run = _get_or_404(session, run_id)
    results.index_run(session, run_id)
    session.refresh(run)
    return run
