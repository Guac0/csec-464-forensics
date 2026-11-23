"""Analyst notes CRUD."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Note, utcnow
from app.services.evidence import get_evidence


def _clean_body(body: str) -> str:
    body = body.strip()
    if not body:
        raise ValueError("note body must not be empty")
    return body


def get_note(session: Session, note_id: int) -> Note:
    """Return the Note or raise LookupError."""
    note = session.get(Note, note_id)
    if note is None:
        raise LookupError(f"note {note_id} not found")
    return note


def list_notes(session: Session, evidence_id: int | None = None) -> list[Note]:
    """All notes (oldest first), or only those attached to ``evidence_id`` when given."""
    stmt = select(Note).order_by(Note.created_at, Note.id)
    if evidence_id is not None:
        stmt = stmt.where(Note.evidence_id == evidence_id)
    return list(session.scalars(stmt))


def create_note(session: Session, body: str, evidence_id: int | None = None) -> Note:
    if evidence_id is not None:
        get_evidence(session, evidence_id)
    note = Note(body=_clean_body(body), evidence_id=evidence_id)
    session.add(note)
    session.commit()
    return note


def update_note(session: Session, note_id: int, body: str) -> Note:
    note = get_note(session, note_id)
    note.body = _clean_body(body)
    note.updated_at = utcnow()
    session.commit()
    return note


def delete_note(session: Session, note_id: int) -> None:
    note = get_note(session, note_id)
    session.delete(note)
    session.commit()
