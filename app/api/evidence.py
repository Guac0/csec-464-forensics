"""JSON API: evidence discovery, hashing, description, auto-enumeration."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.api.runs import RunOut
from app.db import get_session
from app.services import evidence as evidence_service
from app.services import runs as runs_service
from app.tools.base import ArgValidationError

SessionDep = Annotated[Session, Depends(get_session)]

router = APIRouter(prefix="/api/evidence", tags=["evidence"])


class EvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rel_path: str
    size_bytes: int
    mtime: float
    sha256: str | None
    hashed_at: datetime | None
    os_info: dict[str, Any] | None
    description: str
    created_at: datetime
    hashing: bool = False


class EvidenceUpdate(BaseModel):
    description: str


def _out(ev: Any) -> EvidenceOut:
    out = EvidenceOut.model_validate(ev)
    out.hashing = evidence_service.is_hashing(ev.id)
    return out


def _get_or_404(session: Session, evidence_id: int) -> Any:
    try:
        return evidence_service.get_evidence(session, evidence_id)
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc


@router.get("", response_model=list[EvidenceOut])
def list_evidence(session: SessionDep) -> list[EvidenceOut]:
    return [_out(e) for e in evidence_service.list_evidence(session)]


@router.post("/scan", response_model=list[EvidenceOut])
def scan(session: SessionDep) -> list[EvidenceOut]:
    return [_out(e) for e in evidence_service.scan_evidence(session)]


@router.get("/{evidence_id}", response_model=EvidenceOut)
def get_evidence(evidence_id: int, session: SessionDep) -> EvidenceOut:
    return _out(_get_or_404(session, evidence_id))


@router.patch("/{evidence_id}", response_model=EvidenceOut)
def update_evidence(evidence_id: int, body: EvidenceUpdate, session: SessionDep) -> EvidenceOut:
    _get_or_404(session, evidence_id)
    return _out(evidence_service.update_description(session, evidence_id, body.description))


@router.post("/{evidence_id}/hash", response_model=EvidenceOut, status_code=202)
def hash_evidence(evidence_id: int, session: SessionDep) -> EvidenceOut:
    """Start hashing in the background; poll GET /api/evidence/{id} for the result."""
    ev = _get_or_404(session, evidence_id)
    evidence_service.start_hash_in_background(evidence_id)
    return _out(ev)


@router.post("/{evidence_id}/auto", response_model=list[RunOut], status_code=201)
def auto_enumerate(evidence_id: int, session: SessionDep) -> list[RunOut]:
    _get_or_404(session, evidence_id)
    try:
        runs = runs_service.enqueue_auto(session, evidence_id)
    except ArgValidationError as exc:
        raise HTTPException(422, str(exc)) from exc
    return [RunOut.model_validate(r) for r in runs]
