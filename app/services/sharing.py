"""Sharing items from one image with the other images of a case ("promoting").

An analyst shares a specific result row, hook finding, evidence note or AI answer from image A
to a case A belongs to. The other images of that case then show it in a separate, labelled
"Shared in this case" panel, and per-image reports list it under "Leads from linked evidence".

A shared item is a POINTER to its source, never a copy: it is resolved to the source's LATEST
state every time it is shown (``resolve``), flagged when the source changed since it was shared
(content hash at share time) and shown as gone when the source was deleted. Shared items never
enter another image's runs, rows, hook input or AI context.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AIMessage, Evidence, Note, ResultRow, Run, SharedItem, SharedKind
from app.services import audit
from app.services.cases import get_case, membership

MAX_COMMENT = 2000
PREVIEW_CHARS = 300

KIND_LABELS = {
    SharedKind.ROW: "Result row",
    SharedKind.FINDING: "Hook finding",
    SharedKind.NOTE: "Note",
    SharedKind.AI_ANSWER: "AI answer (lead, not evidence)",
}


@dataclass
class Resolved:
    """A shared item as it is NOW."""

    item: SharedItem
    status: str  # "ok" | "changed" (since shared) | "gone" (source deleted / missing)
    status_text: str
    kind_label: str
    title: str
    text: str  # current content (preview) or "" when gone
    link: str | None
    source: Evidence | None


def _sha(value: Any) -> str:
    raw = value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _preview(text: str, limit: int = PREVIEW_CHARS) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _row_text(data: dict[str, Any]) -> str:
    return _preview(
        ", ".join(
            f"{k}={v}" for k, v in data.items() if k != "__children" and v not in (None, "", [])
        )
    )


def _finding_key(f: dict[str, Any]) -> str:
    return f"{f.get('hook', '')}/{f.get('title', '')}"


# --------------------------------------------------------------------------------- source


@dataclass
class _Source:
    evidence_id: int
    key: str
    title: str
    content: Any  # what is hashed
    fields: dict[str, Any]


def _source(
    session: Session,
    kind: SharedKind,
    *,
    run_id: int | None = None,
    row_idx: int | None = None,
    finding_index: int | None = None,
    note_id: int | None = None,
    ai_message_id: int | None = None,
) -> _Source:
    if kind in (SharedKind.ROW, SharedKind.FINDING):
        run = session.get(Run, run_id) if run_id is not None else None
        if run is None:
            raise LookupError(f"run {run_id} not found")
        if run.deleted_at is not None:
            raise ValueError(f"run {run.id} was deleted")
        if kind == SharedKind.ROW:
            row = session.scalar(
                select(ResultRow).where(ResultRow.run_id == run.id, ResultRow.row_idx == row_idx)
            )
            if row is None:
                raise LookupError(f"row R{run.id}:{row_idx} not found")
            return _Source(
                run.evidence_id,
                f"R{run.id}:{row.row_idx}",
                f"{run.plugin} row R{run.id}:{row.row_idx}",
                row.data,
                {"run_id": run.id, "row_idx": row.row_idx},
            )
        findings = run.findings or []
        if finding_index is None or not 0 <= finding_index < len(findings):
            raise LookupError(f"finding {finding_index} not found on run {run.id}")
        f = findings[finding_index]
        return _Source(
            run.evidence_id,
            f"F{run.id}:{_finding_key(f)}",
            f"{run.plugin} finding: {f.get('title', '')}",
            f,
            {"run_id": run.id},
        )
    if kind == SharedKind.NOTE:
        note = session.get(Note, note_id) if note_id is not None else None
        if note is None:
            raise LookupError(f"note {note_id} not found")
        if note.evidence_id is None:
            raise ValueError("only notes on an image can be shared (case notes already are)")
        return _Source(
            note.evidence_id, f"N{note.id}", f"Note {note.id}", note.body, {"note_id": note.id}
        )
    if kind == SharedKind.AI_ANSWER:
        msg = session.get(AIMessage, ai_message_id) if ai_message_id is not None else None
        if msg is None or msg.role != "assistant" or msg.evidence_id is None:
            raise LookupError(f"AI answer {ai_message_id} not found")
        if msg.error or not msg.content:
            raise ValueError("this AI answer has no content to share")
        return _Source(
            msg.evidence_id,
            f"A{msg.id}",
            f"AI answer {msg.id}",
            msg.content,
            {"ai_message_id": msg.id},
        )
    raise ValueError(f"unknown kind {kind!r}")


# --------------------------------------------------------------------------------- actions


def share(
    session: Session,
    case_id: int,
    kind: SharedKind | str,
    *,
    comment: str = "",
    run_id: int | None = None,
    row_idx: int | None = None,
    finding_index: int | None = None,
    note_id: int | None = None,
    ai_message_id: int | None = None,
) -> SharedItem:
    """Share an item from an image to a case the image belongs to. Raises LookupError for a
    missing source/case and ValueError if not allowed (image not in the case, already shared)."""
    kind = SharedKind(kind)
    case = get_case(session, case_id)
    src = _source(
        session,
        kind,
        run_id=run_id,
        row_idx=row_idx,
        finding_index=finding_index,
        note_id=note_id,
        ai_message_id=ai_message_id,
    )
    if membership(session, case_id, src.evidence_id) is None:
        raise ValueError(f"the image this comes from is not in case {case.name!r}")
    existing = session.scalar(
        select(SharedItem).where(
            SharedItem.case_id == case_id,
            SharedItem.kind == kind,
            SharedItem.source_key == src.key,
        )
    )
    if existing is not None:
        raise ValueError(f"already shared in case {case.name!r}")
    comment = (comment or "").strip()[:MAX_COMMENT]
    item = SharedItem(
        case_id=case_id,
        kind=kind,
        source_evidence_id=src.evidence_id,
        source_key=src.key,
        title=src.title,
        comment=comment,
        source_sha256=_sha(src.content),
        shared_by=audit.current_context().actor,
        **src.fields,
    )
    session.add(item)
    session.flush()
    audit.record(
        session,
        "share.create",
        object_type="shared_item",
        object_id=item.id,
        evidence_id=src.evidence_id,
        summary=f"Shared {KIND_LABELS[kind].lower()} {src.key} to case {case.name}",
        details={
            "case_id": case_id,
            "kind": kind.value,
            "source_key": src.key,
            "source_sha256": item.source_sha256,
            "comment": comment,
        },
    )
    session.commit()
    return item


def unshare_in_tx(session: Session, item: SharedItem, reason: str = "") -> None:
    """Remove a shared item inside the caller's transaction (no commit)."""
    audit.record(
        session,
        "share.remove",
        object_type="shared_item",
        object_id=item.id,
        evidence_id=item.source_evidence_id,
        summary=f"Un-shared {item.source_key} from case {item.case_id}",
        details={"case_id": item.case_id, "kind": item.kind.value, "reason": reason},
    )
    session.delete(item)


def unshare(session: Session, item_id: int, reason: str = "") -> int:
    """Remove a shared item; returns its case id. The source itself is untouched."""
    item = session.get(SharedItem, item_id)
    if item is None:
        raise LookupError(f"shared item {item_id} not found")
    case_id = item.case_id
    unshare_in_tx(session, item, reason)
    session.commit()
    return case_id


# --------------------------------------------------------------------------------- reading


def list_items(
    session: Session,
    case_id: int,
    *,
    exclude_evidence_id: int | None = None,
    only_evidence_id: int | None = None,
) -> list[SharedItem]:
    stmt = select(SharedItem).where(SharedItem.case_id == case_id)
    if exclude_evidence_id is not None:
        stmt = stmt.where(SharedItem.source_evidence_id != exclude_evidence_id)
    if only_evidence_id is not None:
        stmt = stmt.where(SharedItem.source_evidence_id == only_evidence_id)
    return list(session.scalars(stmt.order_by(SharedItem.shared_at, SharedItem.id)))


def shared_keys(session: Session, case_id: int, evidence_id: int) -> dict[str, int]:
    """{source_key: shared item id} for items shared from ``evidence_id`` in ``case_id`` (to
    mark them as already shared and offer un-share)."""
    return {
        key: item_id
        for key, item_id in session.execute(
            select(SharedItem.source_key, SharedItem.id).where(
                SharedItem.case_id == case_id, SharedItem.source_evidence_id == evidence_id
            )
        )
    }


def _status(item: SharedItem, content: Any) -> tuple[str, str]:
    if _sha(content) != item.source_sha256:
        return "changed", "changed since it was shared"
    return "ok", ""


def resolve(session: Session, item: SharedItem, case_id: int | None = None) -> Resolved:
    """The item as its source is NOW (latest state)."""
    src_ev = session.get(Evidence, item.source_evidence_id)
    q = f"case={case_id}&" if case_id else ""
    label = KIND_LABELS[item.kind]

    def gone(why: str, link: str | None = None) -> Resolved:
        return Resolved(item, "gone", why, label, item.title, "", link, src_ev)

    if item.kind in (SharedKind.ROW, SharedKind.FINDING):
        run = session.get(Run, item.run_id)
        if run is None:
            return gone("the run no longer exists")
        run_link = f"/runs/{run.id}?{q}".rstrip("?&")
        if run.deleted_at is not None:
            return gone(f"the run was deleted: {run.delete_reason}", run_link)
        if item.kind == SharedKind.ROW:
            row = session.scalar(
                select(ResultRow).where(
                    ResultRow.run_id == run.id, ResultRow.row_idx == item.row_idx
                )
            )
            if row is None:
                return gone("the row no longer exists", run_link)
            status, text = _status(item, row.data)
            link = f"/runs/{run.id}?{q}row={row.row_idx}#row-{run.id}-{row.row_idx}"
            return Resolved(
                item, status, text, label, item.title, _row_text(row.data), link, src_ev
            )
        wanted = item.source_key.split(":", 1)[1]
        f = next((f for f in run.findings or [] if _finding_key(f) == wanted), None)
        if f is None:
            return gone("the finding is no longer on the run (hooks re-run?)", run_link)
        status, text = _status(item, f)
        body = _preview(f"{f.get('title', '')}: {f.get('detail', '')}")
        return Resolved(
            item, status, text, label, item.title, body, run_link + "#post-processing", src_ev
        )
    if item.kind == SharedKind.NOTE:
        note = session.get(Note, item.note_id)
        if note is None:
            return gone("the note was deleted", f"/notes/{item.note_id}/history")
        status, text = _status(item, note.body)
        return Resolved(
            item, status, text, label, item.title, _preview(note.body, 1000),
            f"/notes/{note.id}/history", src_ev,
        )  # fmt: skip
    msg = session.get(AIMessage, item.ai_message_id)
    ev_link = (
        f"/evidence/{item.source_evidence_id}?{q}".rstrip("?&") + f"#ai-msg-{item.ai_message_id}"
    )
    if msg is None:
        return gone("the AI answer no longer exists")
    status, text = _status(item, msg.content)
    return Resolved(
        item, status, text, label, item.title, _preview(msg.content, 1000), ev_link, src_ev
    )


def resolved_for_case(
    session: Session, case_id: int, exclude_evidence_id: int | None = None
) -> list[Resolved]:
    return [
        resolve(session, i, case_id)
        for i in list_items(session, case_id, exclude_evidence_id=exclude_evidence_id)
    ]
