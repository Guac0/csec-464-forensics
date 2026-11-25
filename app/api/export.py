"""JSON API: export an evidence item or the whole investigation (Markdown report or ZIP bundle)."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from starlette.background import BackgroundTask

from app.db import get_session
from app.services import export as export_service

SessionDep = Annotated[Session, Depends(get_session)]

router = APIRouter(prefix="/api", tags=["export"])


@router.get("/export")
def export_case(
    session: SessionDep,
    evidence_id: int | None = None,
    format: Literal["md", "zip"] = "md",  # noqa: A002
    include_dumped: bool = False,
) -> Response:
    """``evidence_id`` set: that evidence item; omitted: everything. ``format=md``: report only;
    ``format=zip``: report + per-run CSV and raw output + manifest.json (SHA-256 of every file).
    ``include_dumped`` (zip only) adds dumped files and AES-encrypts the ZIP with
    FT_ARTIFACT_ZIP_PASSWORD. Every export is recorded in the audit log."""
    return export_response(session, evidence_id, format, include_dumped)


def export_response(
    session: Session, evidence_id: int | None, fmt: str, include_dumped: bool
) -> Response:
    if fmt not in ("md", "zip"):
        raise HTTPException(422, "format must be md or zip")
    now = datetime.now(UTC)
    try:
        if fmt == "md":
            report = export_service.build_report(session, evidence_id, generated_at=now)
            body = report.encode("utf-8")
            scope = export_service.get_scope(session, evidence_id)
            export_service.record_export(
                session, evidence_id, "md", report_sha256=hashlib.sha256(body).hexdigest()
            )
            stamp = now.strftime("%Y%m%dT%H%M%SZ")
            return Response(
                body,
                media_type="text/markdown; charset=utf-8",
                headers={
                    "Content-Disposition": f'attachment; filename="{scope.slug}-{stamp}.md"',
                    "X-Content-Type-Options": "nosniff",
                },
            )
        bundle = export_service.build_bundle(
            session, evidence_id, include_dumped=include_dumped, generated_at=now
        )
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    export_service.record_export(
        session,
        evidence_id,
        "zip",
        include_dumped=include_dumped,
        report_sha256=bundle.report_sha256,
        files=len(bundle.files),
    )
    return FileResponse(
        bundle.path,
        media_type="application/zip",
        filename=bundle.filename,
        headers={"X-Content-Type-Options": "nosniff"},
        background=BackgroundTask(Path(bundle.path).unlink, missing_ok=True),
    )
