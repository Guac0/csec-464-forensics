"""JSON API: read and verify the audit log (it cannot be modified through the API)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.db import get_session
from app.services import audit

SessionDep = Annotated[Session, Depends(get_session)]

router = APIRouter(prefix="/api/audit", tags=["audit"])


class AuditEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    seq: int
    ts: str
    actor: str
    origin: str
    category: str
    action: str
    object_type: str | None
    object_id: int | None
    evidence_id: int | None
    summary: str
    details: dict[str, Any] | None
    request_id: str | None
    prev_hash: str
    hash: str


class AuditPage(BaseModel):
    total: int
    offset: int
    limit: int
    events: list[AuditEventOut]


@router.get("", response_model=AuditPage)
def list_events(
    session: SessionDep,
    category: str | None = None,
    action: str | None = None,
    evidence_id: int | None = None,
    object_type: str | None = None,
    object_id: int | None = None,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> AuditPage:
    """Events, newest first. ``action`` ending in "." is a prefix match (e.g. ``note.``)."""
    events, total = audit.list_events(
        session,
        category=category,
        action=action,
        evidence_id=evidence_id,
        object_type=object_type,
        object_id=object_id,
        offset=offset,
        limit=limit,
    )
    return AuditPage(
        total=total,
        offset=offset,
        limit=limit,
        events=[AuditEventOut.model_validate(e) for e in events],
    )


@router.get("/verify")
def verify(session: SessionDep) -> dict[str, Any]:
    """Recompute the hash chain. The check itself is recorded (category key_read)."""
    return audit.verify_and_record(session).as_dict()
