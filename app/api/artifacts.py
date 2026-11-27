"""JSON API: files written by tools during runs (derived artifacts) and their downloads."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session
from starlette.background import BackgroundTask

from app.db import get_session
from app.services import artifacts as artifacts_service
from app.services import runs as runs_service

SessionDep = Annotated[Session, Depends(get_session)]

router = APIRouter(prefix="/api", tags=["artifacts"])

# Served as an opaque download, never rendered: the content may be malware.
DOWNLOAD_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "sandbox",
    "Cache-Control": "no-store",
}


class ArtifactOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    run_id: int
    evidence_id: int
    filename: str
    size_bytes: int
    sha256: str
    md5: str
    sha1: str
    file_type: str
    source_row_idx: int | None
    created_at: datetime


@router.get("/runs/{run_id}/artifacts", response_model=list[ArtifactOut])
def list_run_artifacts(run_id: int, session: SessionDep) -> list:
    try:
        runs_service.get_run(session, run_id)
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    return artifacts_service.list_for_run(session, run_id)


@router.get("/artifacts/{artifact_id}", response_model=ArtifactOut)
def get_artifact(artifact_id: int, session: SessionDep):  # noqa: ANN201
    try:
        return artifacts_service.get_artifact(session, artifact_id)
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc


@router.get("/artifacts/{artifact_id}/download")
def download_artifact(
    artifact_id: int,
    session: SessionDep,
    format: Literal["zip", "raw"] = "zip",  # noqa: A002
) -> FileResponse:
    """``format=zip`` (default): AES-encrypted zip, password FT_ARTIFACT_ZIP_PASSWORD
    ("infected"). ``format=raw``: the file itself - handle as live malware. Audited."""
    return file_download(session, artifact_id, format)


def file_download(session: Session, artifact_id: int, fmt: str) -> FileResponse:
    try:
        path, filename, temporary = artifacts_service.prepare_download(session, artifact_id, fmt)
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except artifacts_service.ArtifactIntegrityError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename=filename,
        headers=DOWNLOAD_HEADERS,
        background=BackgroundTask(Path(path).unlink, missing_ok=True) if temporary else None,
    )
