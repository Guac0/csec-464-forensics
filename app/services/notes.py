"""Analyst notes CRUD."""

from __future__ import annotations

import hashlib

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Note, NoteVersion, utcnow
from app.services import audit
from app.services.evidence import get_evidence

_PAST = {"create": "created", "edit": "edited", "delete": "deleted"}


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


def list_notes(
    session: Session, evidence_id: int | None = None, case_id: int | None = None
) -> list[Note]:
    """All notes (oldest first), or only those of ``evidence_id`` / ``case_id`` when given."""
    stmt = select(Note).order_by(Note.created_at, Note.id)
    if evidence_id is not None:
        stmt = stmt.where(Note.evidence_id == evidence_id)
    if case_id is not None:
        stmt = stmt.where(Note.case_id == case_id)
    return list(session.scalars(stmt))


def list_versions(session: Session, note_id: int) -> list[NoteVersion]:
    """Full history of a note, oldest first (also works after the note was deleted)."""
    return list(
        session.scalars(
            select(NoteVersion).where(NoteVersion.note_id == note_id).order_by(NoteVersion.version)
        )
    )


def _add_version(session: Session, note: Note, action: str, body: str) -> NoteVersion:
    """Append a NoteVersion and the matching audit event (same transaction as the change)."""
    latest = session.scalar(
        select(func.max(NoteVersion.version)).where(NoteVersion.note_id == note.id)
    )
    version = NoteVersion(
        note_id=note.id,
        version=(latest or 0) + 1,
        action=action,
        body=body,
        evidence_id=note.evidence_id,
        case_id=note.case_id,
        actor=audit.current_context().actor,
    )
    session.add(version)
    session.flush()
    previous = (
        session.scalar(
            select(NoteVersion.body).where(
                NoteVersion.note_id == note.id, NoteVersion.version == version.version - 1
            )
        )
        if version.version > 1
        else None
    )
    audit.record(
        session,
        f"note.{action}",
        object_type="note",
        object_id=note.id,
        evidence_id=note.evidence_id,
        summary=f"Note {note.id} {_PAST[action]} (version {version.version})",
        details={
            "version": version.version,
            "note_version_id": version.id,
            # Hashes tie the (separately stored) note text into the tamper-evident chain.
            "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
            "previous_body_sha256": hashlib.sha256(previous.encode("utf-8")).hexdigest()
            if previous is not None
            else None,
            "chars": len(body),
            "case_id": note.case_id,
        },
    )
    return version


def create_note(
    session: Session, body: str, evidence_id: int | None = None, case_id: int | None = None
) -> Note:
    """A note on exactly one image (``evidence_id``) or one case (``case_id``)."""
    if (evidence_id is None) == (case_id is None):
        raise ValueError("a note belongs to exactly one image or one case")
    if evidence_id is not None:
        get_evidence(session, evidence_id)
    else:
        from app.services.cases import get_case

        get_case(session, case_id)  # type: ignore[arg-type]
    note = Note(body=_clean_body(body), evidence_id=evidence_id, case_id=case_id)
    session.add(note)
    session.flush()
    _add_version(session, note, "create", note.body)
    session.commit()
    return note


def update_note(session: Session, note_id: int, body: str) -> Note:
    note = get_note(session, note_id)
    note.body = _clean_body(body)
    note.updated_at = utcnow()
    _add_version(session, note, "edit", note.body)
    session.commit()
    return note


def delete_note(session: Session, note_id: int) -> None:
    """Delete the note. Its history (note_versions) is kept, ending in a "delete" version."""
    note = get_note(session, note_id)
    _add_version(session, note, "delete", note.body)
    session.delete(note)
    session.commit()
