"""Audit log: an append-only, hash-chained record of what happened.

Writing events
--------------
Call :func:`record` from the service layer **inside the same transaction** as the change it
describes (before ``session.commit()``), so an action and its audit entry are saved together or
not at all::

    audit.record(session, "note.edit", object_type="note", object_id=note.id,
                 evidence_id=note.evidence_id, summary="Edited note", details={...})

Who/where comes from the current :class:`AuditContext` (a context variable): the HTTP middleware
sets ``origin="ui"|"api"`` and a request id, the worker sets ``origin="worker"``. ``actor`` is
``"local"`` until the app has logins.

Categories and levels (``FT_AUDIT_LEVEL``)
------------------------------------------
- ``change``   - anything that changes data (always recorded)
- ``key_read`` - sensitive reads: audit verification, and later exports/downloads
- ``request``  - every HTTP request (page views, API reads, HTMX polling), written by
  :func:`audit_requests_middleware`; only recorded at level ``all``

Tamper evidence
---------------
- SQLite triggers (migration 0003) reject UPDATE/DELETE on ``audit_events`` - stops app bugs.
- Each event's ``hash`` = SHA-256 over its fields including ``prev_hash`` (the previous event's
  hash) and a gap-free ``seq``. ``audit_head`` stores the latest hash/seq. :func:`verify_chain`
  recomputes everything, so edits, deletions, re-ordering or truncation made directly to the
  database file are detected. (Someone with write access to the file could rebuild the whole
  chain; anchoring the head hash outside the DB is a possible future step.)
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import time
import uuid
from collections.abc import Awaitable, Callable, Iterator
from contextvars import ContextVar
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import insert, select, update
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import AuditEvent, AuditHead

logger = logging.getLogger(__name__)

CHANGE = "change"
KEY_READ = "key_read"
REQUEST = "request"
CATEGORIES = (CHANGE, KEY_READ, REQUEST)
_LEVEL_INCLUDES: dict[str, frozenset[str]] = {
    "changes": frozenset({CHANGE}),
    "key_reads": frozenset({CHANGE, KEY_READ}),
    "all": frozenset({CHANGE, KEY_READ, REQUEST}),
}
GENESIS_HASH = "0" * 64
# Request paths never logged even at level "all": static assets and the Docker healthcheck
# (every 30s) would drown out everything else.
REQUEST_LOG_EXCLUDED_PREFIXES = ("/static/", "/health")

# Fields covered by the hash, in a fixed order (changing this invalidates existing chains).
HASHED_FIELDS = (
    "seq",
    "ts",
    "actor",
    "origin",
    "category",
    "action",
    "object_type",
    "object_id",
    "evidence_id",
    "summary",
    "details",
    "request_id",
    "prev_hash",
)


# --------------------------------------------------------------------------------- context


@dataclass(frozen=True)
class AuditContext:
    actor: str = "local"
    origin: str = "system"
    request_id: str | None = None


_context: ContextVar[AuditContext] = ContextVar("audit_context", default=AuditContext())  # noqa: B039


def current_context() -> AuditContext:
    return _context.get()


@contextlib.contextmanager
def audit_context(**changes: Any) -> Iterator[AuditContext]:
    """Temporarily override actor/origin/request_id: ``with audit_context(origin="worker")``."""
    ctx = replace(_context.get(), **changes)
    token = _context.set(ctx)
    try:
        yield ctx
    finally:
        _context.reset(token)


# --------------------------------------------------------------------------------- writing


def enabled(category: str) -> bool:
    """Whether events of this category are recorded at the configured FT_AUDIT_LEVEL."""
    return category in _LEVEL_INCLUDES[get_settings().audit_level]


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def compute_hash(fields: dict[str, Any]) -> str:
    canonical = json.dumps(
        {k: fields.get(k) for k in HASHED_FIELDS},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _normalise(details: dict[str, Any] | None) -> dict[str, Any] | None:
    """Round-trip through JSON so what we hash is exactly what is stored and read back."""
    if details is None:
        return None
    return json.loads(json.dumps(details, default=str))


def record(
    session: Session,
    action: str,
    *,
    category: str = CHANGE,
    summary: str = "",
    object_type: str | None = None,
    object_id: int | None = None,
    evidence_id: int | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Append an event in the session's current transaction. Returns the stored fields, or None
    if the category is below FT_AUDIT_LEVEL. The caller commits (together with its change)."""
    if category not in CATEGORIES:
        raise ValueError(f"unknown audit category {category!r}")
    if not enabled(category):
        return None
    ctx = current_context()
    # Bump the head first: this takes SQLite's write lock, so no other connection can append
    # between reading the head and writing it (appends are serialised, the chain cannot fork).
    res = session.execute(update(AuditHead).where(AuditHead.id == 1).values(seq=AuditHead.seq + 1))
    if res.rowcount != 1:  # type: ignore[attr-defined]
        raise RuntimeError("audit_head row missing; run database migrations")
    seq, prev_hash = session.execute(
        select(AuditHead.seq, AuditHead.last_hash).where(AuditHead.id == 1)
    ).one()
    fields: dict[str, Any] = {
        "seq": seq,
        "ts": _now(),
        "actor": ctx.actor,
        "origin": ctx.origin,
        "category": category,
        "action": action,
        "object_type": object_type,
        "object_id": object_id,
        "evidence_id": evidence_id,
        "summary": summary,
        "details": _normalise(details),
        "request_id": ctx.request_id,
        "prev_hash": prev_hash,
    }
    fields["hash"] = compute_hash(fields)
    session.execute(insert(AuditEvent).values(**fields))
    session.execute(update(AuditHead).where(AuditHead.id == 1).values(last_hash=fields["hash"]))
    return fields


def record_now(action: str, **kwargs: Any) -> None:
    """Record an event in its own short transaction (for code with no session of its own).
    Never raises: failures are logged."""
    from app.db import SessionLocal, get_engine

    try:
        get_engine()
        with SessionLocal() as s:
            record(s, action, **kwargs)
            s.commit()
    except Exception:
        logger.exception("could not write audit event %s", action)


# --------------------------------------------------------------------------------- reading


def list_events(
    session: Session,
    *,
    category: str | None = None,
    action: str | None = None,
    evidence_id: int | None = None,
    object_type: str | None = None,
    object_id: int | None = None,
    offset: int = 0,
    limit: int = 100,
) -> tuple[list[AuditEvent], int]:
    """Newest first. ``action`` matches exactly or as a prefix ending in '.', e.g. 'note.'."""
    from sqlalchemy import func

    where = []
    if category:
        where.append(AuditEvent.category == category)
    if action:
        where.append(
            AuditEvent.action.startswith(action, autoescape=True)
            if action.endswith(".")
            else AuditEvent.action == action
        )
    if evidence_id is not None:
        where.append(AuditEvent.evidence_id == evidence_id)
    if object_type:
        where.append(AuditEvent.object_type == object_type)
    if object_id is not None:
        where.append(AuditEvent.object_id == object_id)
    total = session.scalar(select(func.count()).select_from(AuditEvent).where(*where)) or 0
    rows = session.scalars(
        select(AuditEvent)
        .where(*where)
        .order_by(AuditEvent.seq.desc())
        .offset(max(0, offset))
        .limit(max(1, limit))
    )
    return list(rows), total


@dataclass
class ChainReport:
    ok: bool
    events: int
    head_seq: int
    head_hash: str
    error: str | None = None
    bad_seq: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "events": self.events,
            "head_seq": self.head_seq,
            "head_hash": self.head_hash,
            "error": self.error,
            "bad_seq": self.bad_seq,
        }


def verify_chain(session: Session, batch: int = 2000) -> ChainReport:
    """Recompute the whole chain. Detects edited, deleted, inserted or re-ordered events and a
    truncated tail (head mismatch)."""
    head = session.get(AuditHead, 1)
    if head is None:
        return ChainReport(False, 0, 0, "", "audit_head row is missing")
    session.refresh(head)
    prev, expected_seq, count, last_seq = GENESIS_HASH, 1, 0, 0
    while True:
        events = (
            session.execute(
                select(AuditEvent)
                .where(AuditEvent.seq > last_seq)
                .order_by(AuditEvent.seq)
                .limit(batch)
            )
            .scalars()
            .all()
        )
        if not events:
            break
        for ev in events:
            fields = {k: getattr(ev, k) for k in HASHED_FIELDS}
            if ev.seq != expected_seq:
                return _bad(head, count, ev.seq, f"sequence gap: expected {expected_seq}")
            if ev.prev_hash != prev:
                return _bad(head, count, ev.seq, "prev_hash does not match the previous event")
            if compute_hash(fields) != ev.hash:
                return _bad(head, count, ev.seq, "event content does not match its hash")
            prev, expected_seq, count, last_seq = ev.hash, ev.seq + 1, count + 1, ev.seq
        session.expunge_all()  # keep memory flat on long logs
        head = session.get(AuditHead, 1) or head
    if head.seq != count or head.last_hash != prev:
        return _bad(head, count, None, "chain head does not match the last event (truncated?)")
    return ChainReport(True, count, head.seq, head.last_hash)


def verify_and_record(session: Session) -> ChainReport:
    """Verify the chain and record that a verification happened (category key_read)."""
    report = verify_chain(session)
    record(
        session,
        "audit.verify",
        category=KEY_READ,
        summary="Audit chain verified: OK" if report.ok else f"Audit chain BROKEN: {report.error}",
        details=report.as_dict(),
    )
    session.commit()
    return report


def _bad(head: AuditHead, count: int, seq: int | None, error: str) -> ChainReport:
    return ChainReport(False, count, head.seq, head.last_hash, error, seq)


# --------------------------------------------------------------------------------- HTTP


async def audit_requests_middleware(
    request: Any, call_next: Callable[[Any], Awaitable[Any]]
) -> Any:
    """Set the audit context for the request and, at FT_AUDIT_LEVEL=all, log the request itself.

    Mutating endpoints record their own semantic events (category "change"); this adds one
    "http.request" event per request so page views and API reads are covered too.
    """
    from starlette.concurrency import run_in_threadpool

    path = request.url.path
    origin = "api" if path.startswith("/api") else "ui"
    request_id = uuid.uuid4().hex[:16]
    token = _context.set(AuditContext(actor="local", origin=origin, request_id=request_id))
    started = time.perf_counter()
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        _context.reset(token)
        if enabled(REQUEST) and not path.startswith(REQUEST_LOG_EXCLUDED_PREFIXES):
            details = {
                "method": request.method,
                "path": path,
                "query": request.url.query or None,
                "status": status_code,
                "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                "client": request.client.host if request.client else None,
                "htmx": request.headers.get("hx-request") == "true",
            }
            with audit_context(origin=origin, request_id=request_id):
                await run_in_threadpool(
                    record_now,
                    "http.request",
                    category=REQUEST,
                    summary=f"{request.method} {path} -> {status_code}",
                    details=details,
                )
