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
from app.services import integrity
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
    md5: str | None
    sha1: str | None
    hashed_at: datetime | None
    expected_sha256: str | None
    expected_md5: str | None
    expected_sha1: str | None
    mismatch_ack_at: datetime | None
    mismatch_ack_reason: str | None
    changed_detected_at: datetime | None
    integrity_status: str = ""
    integrity_problem: str | None = None
    os_info: dict[str, Any] | None
    description: str
    created_at: datetime
    hashing: bool = False


class EvidenceUpdate(BaseModel):
    """Fields left out are unchanged. Expected hashes: hex string, or "" to clear."""

    description: str | None = None
    expected_sha256: str | None = None
    expected_md5: str | None = None
    expected_sha1: str | None = None


class AcknowledgeMismatch(BaseModel):
    reason: str


class IntegrityCheckOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    run_id: int | None
    kind: str
    result: str
    sha256: str | None
    md5: str | None
    sha1: str | None
    size_bytes: int | None
    mtime: float | None
    seconds: float | None
    detail: str
    created_at: datetime


def _out(ev: Any) -> EvidenceOut:
    out = EvidenceOut.model_validate(ev)
    out.hashing = evidence_service.is_hashing(ev.id)
    out.integrity_status = integrity.status(ev)
    out.integrity_problem = integrity.describe_problem(ev)
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
    ev = _get_or_404(session, evidence_id)
    if body.description is not None:
        evidence_service.update_description(session, evidence_id, body.description)
    expected = body.model_dump(include={"expected_sha256", "expected_md5", "expected_sha1"})
    if any(v is not None for v in expected.values()):
        current = {f"expected_{a}": getattr(ev, f"expected_{a}") for a in integrity.ALGORITHMS}
        merged = {k: (v if v is not None else current[k]) for k, v in expected.items()}
        try:
            integrity.set_expected_hashes(
                session,
                evidence_id,
                sha256=merged["expected_sha256"],
                md5=merged["expected_md5"],
                sha1=merged["expected_sha1"],
            )
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
    return _out(_get_or_404(session, evidence_id))


@router.post("/{evidence_id}/hash", response_model=EvidenceOut, status_code=202)
@router.post("/{evidence_id}/verify", response_model=EvidenceOut, status_code=202)
def verify_evidence(evidence_id: int, session: SessionDep) -> EvidenceOut:
    """Hash / re-verify the image in the background (SHA-256 + MD5 + SHA-1); poll
    GET /api/evidence/{id}. The current content becomes the baseline (recorded)."""
    ev = _get_or_404(session, evidence_id)
    evidence_service.start_hash_in_background(evidence_id)
    return _out(ev)


@router.post("/{evidence_id}/acknowledge-mismatch", response_model=EvidenceOut)
def acknowledge_mismatch(
    evidence_id: int, body: AcknowledgeMismatch, session: SessionDep
) -> EvidenceOut:
    """Allow runs despite a mismatch with the expected hashes (reason is required, audited)."""
    _get_or_404(session, evidence_id)
    try:
        return _out(integrity.acknowledge_mismatch(session, evidence_id, body.reason))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/{evidence_id}/integrity", response_model=list[IntegrityCheckOut])
def integrity_checks(evidence_id: int, session: SessionDep) -> list:
    """Every hash computation / verification of this image, newest first."""
    _get_or_404(session, evidence_id)
    return integrity.list_checks(session, evidence_id)


@router.post("/{evidence_id}/auto", response_model=list[RunOut], status_code=201)
def auto_enumerate(evidence_id: int, session: SessionDep) -> list[RunOut]:
    _get_or_404(session, evidence_id)
    try:
        runs = runs_service.enqueue_auto(session, evidence_id)
    except ArgValidationError as exc:
        raise HTTPException(422, str(exc)) from exc
    except integrity.IntegrityError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except runs_service.DiskSpaceError as exc:
        raise HTTPException(status.HTTP_507_INSUFFICIENT_STORAGE, str(exc)) from exc
    return [RunOut.model_validate(r) for r in runs]
