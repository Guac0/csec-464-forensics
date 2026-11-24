"""ORM models. This file is a shared contract: change it deliberately and tell the team."""

from __future__ import annotations

import enum
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class Evidence(Base):
    """A RAM image found in the read-only evidence directory."""

    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Path relative to settings.evidence_dir (never absolute, never containing "..").
    rel_path: Mapped[str] = mapped_column(String, unique=True)
    size_bytes: Mapped[int] = mapped_column(Integer)
    mtime: Mapped[float] = mapped_column()
    # Computed hashes (one pass over the file); None until hashed. See app/services/integrity.py.
    sha256: Mapped[str | None] = mapped_column(String(64), default=None)
    md5: Mapped[str | None] = mapped_column(String(32), default=None)
    sha1: Mapped[str | None] = mapped_column(String(40), default=None)
    hashed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    # Hashes the analyst expects (e.g. from the acquisition report). A difference = mismatch.
    expected_sha256: Mapped[str | None] = mapped_column(String(64), default=None)
    expected_md5: Mapped[str | None] = mapped_column(String(32), default=None)
    expected_sha1: Mapped[str | None] = mapped_column(String(40), default=None)
    # Analyst's explicit decision to run despite a mismatch (cleared when hashes change).
    mismatch_ack_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    mismatch_ack_reason: Mapped[str | None] = mapped_column(Text, default=None)
    # Set when the file's size/mtime no longer match what was hashed; cleared by re-hashing.
    changed_detected_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    # Filled by humans' windows.info handling (e.g. {"os": "windows", "build": "19041"}).
    os_info: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    runs: Mapped[list[Run]] = relationship(back_populates="evidence")


class RunStatus(enum.StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RunOrigin(enum.StrEnum):
    MANUAL = "manual"  # user picked plugin + args
    PRESET = "preset"  # user clicked a hardcoded suggested query
    AUTO = "auto"  # queued by auto-enumeration
    AI_SUGGESTED = "ai"  # user clicked a validated AI suggestion
    HOOK = "hook"  # queued by a post-run hook as a follow-up (see app/tools/hooks.py)


class Run(Base):
    """One invocation of a tool plugin against one evidence item."""

    __tablename__ = "runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    evidence_id: Mapped[int] = mapped_column(ForeignKey("evidence.id"))
    tool: Mapped[str] = mapped_column(String, default="volatility3")
    plugin: Mapped[str] = mapped_column(String)  # e.g. "windows.pslist.PsList"
    args: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # validated arg values
    argv: Mapped[list[str] | None] = mapped_column(JSON, default=None)  # exact argv executed
    origin: Mapped[RunOrigin] = mapped_column(Enum(RunOrigin), default=RunOrigin.MANUAL)
    status: Mapped[RunStatus] = mapped_column(Enum(RunStatus), default=RunStatus.QUEUED)
    tool_version: Mapped[str | None] = mapped_column(String, default=None)
    # Snapshot of the evidence the tool actually ran against (checked just before execution).
    evidence_sha256: Mapped[str | None] = mapped_column(String(64), default=None)
    evidence_size_bytes: Mapped[int | None] = mapped_column(Integer, default=None)
    evidence_mtime: Mapped[float | None] = mapped_column(default=None)
    # Set when FT_INTEGRITY_MODE=warn let the run go ahead despite an integrity problem.
    integrity_warning: Mapped[str | None] = mapped_column(Text, default=None)
    # What a RUNNING run is doing: "hashing" | "verifying" | "running" | "post-processing".
    phase: Mapped[str | None] = mapped_column(String, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    returncode: Mapped[int | None] = mapped_column(Integer, default=None)
    # Paths relative to settings.data_dir.
    stdout_path: Mapped[str | None] = mapped_column(String, default=None)
    stderr_path: Mapped[str | None] = mapped_column(String, default=None)
    stdout_sha256: Mapped[str | None] = mapped_column(String(64), default=None)
    row_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    # Post-run hooks (app/tools/hooks.py). One entry per hook executed on the last hook pass:
    # {"hook", "version", "status": "ok"|"error", "duration_ms", "error", "at", ...counts}.
    hook_results: Mapped[list[dict[str, Any]] | None] = mapped_column(
        JSON(none_as_null=True), default=None
    )
    # Run-level findings from hooks: {"hook", "title", "detail", "severity", "rows": [row_idx]}.
    findings: Mapped[list[dict[str, Any]] | None] = mapped_column(
        JSON(none_as_null=True), default=None
    )
    # Follow-up provenance: set when a hook queued this run.
    parent_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("runs.id", ondelete="SET NULL", name="fk_runs_parent_run_id"),
        default=None,
        index=True,
    )
    triggered_by_hook: Mapped[str | None] = mapped_column(String, default=None)
    # 0 for user/auto runs; parent's depth + 1 for hook follow-ups (loop guard).
    chain_depth: Mapped[int] = mapped_column(Integer, default=0, server_default="0")

    evidence: Mapped[Evidence] = relationship(back_populates="runs")
    rows: Mapped[list[ResultRow]] = relationship(
        back_populates="run", cascade="all, delete-orphan", order_by="ResultRow.row_idx"
    )


class ResultRow(Base):
    """One parsed output row. (run_id, row_idx) is the stable citation key "R{run_id}:{row_idx}"."""

    __tablename__ = "result_rows"
    __table_args__ = (UniqueConstraint("run_id", "row_idx"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"), index=True)
    row_idx: Mapped[int] = mapped_column(Integer)
    # Tree depth for tree-style plugins (e.g. pstree); 0 for flat output.
    depth: Mapped[int] = mapped_column(Integer, default=0)
    parent_idx: Mapped[int | None] = mapped_column(Integer, default=None)
    data: Mapped[dict[str, Any]] = mapped_column(JSON)
    # Hook annotations: [{"hook", "tag", "severity", "note"}]; None when not annotated.
    annotations: Mapped[list[dict[str, Any]] | None] = mapped_column(
        JSON(none_as_null=True), default=None
    )

    run: Mapped[Run] = relationship(back_populates="rows")

    @property
    def citation(self) -> str:
        return f"R{self.run_id}:{self.row_idx}"


class Note(Base):
    """Free-form analyst notes. evidence_id None = global/investigation-level note."""

    __tablename__ = "notes"

    id: Mapped[int] = mapped_column(primary_key=True)
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id"), default=None)
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AIMessage(Base):
    """A user question or AI answer, with full provenance for every AI output."""

    __tablename__ = "ai_messages"

    id: Mapped[int] = mapped_column(primary_key=True)
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id"), default=None)
    role: Mapped[str] = mapped_column(String)  # "user" | "assistant"
    content: Mapped[str] = mapped_column(Text)
    # Provenance (assistant messages):
    model_requested: Mapped[str | None] = mapped_column(String, default=None)
    model_returned: Mapped[str | None] = mapped_column(String, default=None)
    provider_base_url: Mapped[str | None] = mapped_column(String, default=None)
    params: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)
    request_messages: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, default=None)
    context_refs: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)  # run/row ids
    citations: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, default=None)
    suggestions: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, default=None)
    usage: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class NoteVersion(Base):
    """Append-only history of a note: one row per create/edit/delete (DB triggers block changes).

    ``note_id`` is deliberately not a foreign key, so history survives the note being deleted.
    """

    __tablename__ = "note_versions"
    __table_args__ = (UniqueConstraint("note_id", "version"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    note_id: Mapped[int] = mapped_column(Integer, index=True)
    version: Mapped[int] = mapped_column(Integer)  # 1, 2, 3... per note
    action: Mapped[str] = mapped_column(String)  # "create" | "edit" | "delete"
    body: Mapped[str] = mapped_column(Text)  # text after the action (last text for "delete")
    evidence_id: Mapped[int | None] = mapped_column(Integer, default=None)
    actor: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    """One audit log entry. Append-only (DB triggers) and hash-chained (see app/services/audit.py).

    ``ts`` is stored as an ISO-8601 UTC string (not DateTime) so the value that was hashed is
    byte-for-byte the value read back during verification.
    """

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    seq: Mapped[int] = mapped_column(Integer, unique=True)  # 1, 2, 3... gaps = deleted rows
    ts: Mapped[str] = mapped_column(String, index=True)
    actor: Mapped[str] = mapped_column(String)  # "local" until there is login
    origin: Mapped[str] = mapped_column(String)  # ui | api | worker | system
    category: Mapped[str] = mapped_column(String, index=True)  # change | key_read | request
    action: Mapped[str] = mapped_column(String, index=True)  # e.g. "note.edit", "run.create"
    object_type: Mapped[str | None] = mapped_column(String, default=None)
    object_id: Mapped[int | None] = mapped_column(Integer, default=None)
    evidence_id: Mapped[int | None] = mapped_column(Integer, default=None, index=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON(none_as_null=True), default=None)
    request_id: Mapped[str | None] = mapped_column(String, default=None)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class AuditHead(Base):
    """Single row (id=1) holding the latest chain hash and sequence number. Updating it first in
    every audit write takes SQLite's write lock, so chain appends are serialised."""

    __tablename__ = "audit_head"

    id: Mapped[int] = mapped_column(primary_key=True)
    seq: Mapped[int] = mapped_column(Integer, default=0)
    last_hash: Mapped[str] = mapped_column(String(64))


class IntegrityCheck(Base):
    """Append-only record of every hash computation / verification of an evidence file."""

    __tablename__ = "integrity_checks"

    id: Mapped[int] = mapped_column(primary_key=True)
    evidence_id: Mapped[int] = mapped_column(Integer, index=True)
    run_id: Mapped[int | None] = mapped_column(Integer, default=None)  # set for pre-run checks
    # "initial" (first hash) | "verify" (manual) | "pre_run" (FT_VERIFY_ON_RUN) | "rehash"
    kind: Mapped[str] = mapped_column(String)
    # "ok" | "changed" (content differs from the last hash) | "mismatch" (differs from the
    # expected hashes) | "error"
    result: Mapped[str] = mapped_column(String)
    sha256: Mapped[str | None] = mapped_column(String(64), default=None)
    md5: Mapped[str | None] = mapped_column(String(32), default=None)
    sha1: Mapped[str | None] = mapped_column(String(40), default=None)
    size_bytes: Mapped[int | None] = mapped_column(Integer, default=None)
    mtime: Mapped[float | None] = mapped_column(default=None)
    seconds: Mapped[float | None] = mapped_column(default=None)
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
