"""JSON API: analyst notes CRUD."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.db import get_session
from app.models import Note
from app.services import notes as notes_service

SessionDep = Annotated[Session, Depends(get_session)]

router = APIRouter(prefix="/api/notes", tags=["notes"])


class NoteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    evidence_id: int | None
    case_id: int | None = None
    body: str
    created_at: datetime
    updated_at: datetime


class NoteCreate(BaseModel):
    body: str
    # Exactly one of these.
    evidence_id: int | None = None
    case_id: int | None = None


class NoteUpdate(BaseModel):
    body: str


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, LookupError):
        return HTTPException(status.HTTP_404_NOT_FOUND, str(exc))
    return HTTPException(422, str(exc))


@router.get("", response_model=list[NoteOut])
def list_notes(
    session: SessionDep, evidence_id: int | None = None, case_id: int | None = None
) -> list[Note]:
    return notes_service.list_notes(session, evidence_id, case_id)


@router.post("", response_model=NoteOut, status_code=201)
def create_note(body: NoteCreate, session: SessionDep) -> Note:
    try:
        return notes_service.create_note(session, body.body, body.evidence_id, body.case_id)
    except (LookupError, ValueError) as exc:
        raise _http_error(exc) from exc


@router.get("/{note_id}", response_model=NoteOut)
def get_note(note_id: int, session: SessionDep) -> Note:
    try:
        return notes_service.get_note(session, note_id)
    except LookupError as exc:
        raise _http_error(exc) from exc


@router.patch("/{note_id}", response_model=NoteOut)
def update_note(note_id: int, body: NoteUpdate, session: SessionDep) -> Note:
    try:
        return notes_service.update_note(session, note_id, body.body)
    except (LookupError, ValueError) as exc:
        raise _http_error(exc) from exc


@router.delete("/{note_id}", status_code=204)
def delete_note(note_id: int, session: SessionDep) -> Response:
    try:
        notes_service.delete_note(session, note_id)
    except LookupError as exc:
        raise _http_error(exc) from exc
    return Response(status_code=204)


class NoteVersionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    note_id: int
    version: int
    action: str
    body: str
    evidence_id: int | None
    case_id: int | None = None
    actor: str
    created_at: datetime


@router.get("/{note_id}/versions", response_model=list[NoteVersionOut])
def note_versions(note_id: int, session: SessionDep) -> list:
    """Full edit history of a note (still available after the note is deleted)."""
    versions = notes_service.list_versions(session, note_id)
    if not versions:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"no history for note {note_id}")
    return versions
