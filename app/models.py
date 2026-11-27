"""ORM models. This file is a shared contract: change it deliberately and tell the team."""

from __future__ import annotations

import enum
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
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
    # The app stopped (crash, restart, shutdown) while the run was in progress.
    INTERRUPTED = "interrupted"


class RunOrigin(enum.StrEnum):
    MANUAL = "manual"  # user picked plugin + args
    PRESET = "preset"  # user clicked a hardcoded suggested query
    AUTO = "auto"  # queued by auto-enumeration
    AI_SUGGESTED = "ai"  # user clicked a validated AI suggestion
    HOOK = "hook"  # queued by a post-run hook as a follow-up (see app/tools/hooks.py)
    RECOMMENDED = "recommended"  # user clicked a recommendation from the investigation guide


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
    # Output columns in first-seen order with an inferred type, computed at ingest:
    # [{"name": "PID", "type": "int"}, ...]; type is int|float|bool|str|json|null|mixed.
    columns: Mapped[list[dict[str, Any]] | None] = mapped_column(
        JSON(none_as_null=True), default=None
    )
    # True when this run's rows are in the full-text search index (FT_SEARCH_INDEX).
    search_indexed: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
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
    # Set when the run was created with "Re-run" from another run.
    rerun_of_id: Mapped[int | None] = mapped_column(
        ForeignKey("runs.id", ondelete="SET NULL", name="fk_runs_rerun_of_id"), default=None
    )
    # OS process id of the tool while it runs (used to stop an orphaned process after a crash).
    pid: Mapped[int | None] = mapped_column(Integer, default=None)
    # Tombstone: set when the run's rows, raw output and dumped files were deleted (the record,
    # its hashes and its audit history stay). Status keeps the value it had before deletion.
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    delete_reason: Mapped[str | None] = mapped_column(Text, default=None)

    evidence: Mapped[Evidence] = relationship(back_populates="runs")
    artifacts: Mapped[list[DerivedArtifact]] = relationship(
        viewonly=True, order_by="DerivedArtifact.filename"
    )
    rows: Mapped[list[ResultRow]] = relationship(
        back_populates="run", cascade="all, delete-orphan", order_by="ResultRow.row_idx"
    )

    @property
    def artifact_count(self) -> int:
        return len(self.artifacts)


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
    """Free-form analyst notes, attached to exactly one evidence item OR one case."""

    __tablename__ = "notes"

    id: Mapped[int] = mapped_column(primary_key=True)
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id"), default=None)
    case_id: Mapped[int | None] = mapped_column(
        ForeignKey("cases.id", name="fk_notes_case_id"), default=None, index=True
    )
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
    case_id: Mapped[int | None] = mapped_column(Integer, default=None)
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


class DerivedArtifact(Base):
    """A file a tool wrote during a run (e.g. a process dumped with --dump).

    Stored under ``<data_dir>/runs/<run_id>/output/``. Hashed when registered; downloads re-check
    the SHA-256. Treat the content as potentially malicious.
    """

    __tablename__ = "derived_artifacts"
    __table_args__ = (UniqueConstraint("run_id", "rel_path"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), index=True)
    evidence_id: Mapped[int] = mapped_column(Integer, index=True)
    rel_path: Mapped[str] = mapped_column(String)  # relative to settings.data_dir
    filename: Mapped[str] = mapped_column(String)  # path relative to the run's output dir
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    md5: Mapped[str] = mapped_column(String(32))
    sha1: Mapped[str] = mapped_column(String(40))
    file_type: Mapped[str] = mapped_column(String, default="data")  # guessed from magic bytes
    # Result row that names this file (e.g. pslist's "File output" column), if any.
    source_row_idx: Mapped[int | None] = mapped_column(Integer, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Case(Base):
    """A group of evidence items investigated together (e.g. before/after snapshots of one
    machine, or several machines hit by the same actor). Membership is the only link between
    images: things are shared between images only by explicitly sharing them to a case."""

    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String, unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    members: Mapped[list[CaseEvidence]] = relationship(
        back_populates="case", cascade="all, delete-orphan", order_by="CaseEvidence.added_at"
    )


class CaseEvidence(Base):
    """An evidence item in a case. An image can be in several cases."""

    __tablename__ = "case_evidence"

    case_id: Mapped[int] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), primary_key=True
    )
    evidence_id: Mapped[int] = mapped_column(
        ForeignKey("evidence.id"), primary_key=True, index=True
    )
    # Optional role of the image in this case, e.g. "before", "after", "laptop-2".
    label: Mapped[str] = mapped_column(String, default="")
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    case: Mapped[Case] = relationship(back_populates="members")
    evidence: Mapped[Evidence] = relationship()


class SharedKind(enum.StrEnum):
    ROW = "row"  # a result row (run_id, row_idx)
    FINDING = "finding"  # a hook finding on a run (run_id, finding title + hook)
    NOTE = "note"  # an evidence note (note_id)
    AI_ANSWER = "ai_answer"  # an AI answer (ai_message_id), shared as an AI lead


class SharedItem(Base):
    """Something from one image deliberately shared with the other images of a case.

    It is a pointer: the UI and reports show the source's LATEST state (app/services/sharing.py),
    plus whether it changed since it was shared (``source_sha256``) or no longer exists. It is
    never copied into the other images' runs, rows, hooks or AI context.
    """

    __tablename__ = "shared_items"
    __table_args__ = (UniqueConstraint("case_id", "kind", "source_key"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    kind: Mapped[SharedKind] = mapped_column(Enum(SharedKind))
    # The image it came from (must be a member of the case when shared).
    source_evidence_id: Mapped[int] = mapped_column(ForeignKey("evidence.id"), index=True)
    # Stable identity of the source within its kind, e.g. "R12:34", "F12:hook/title", "N7", "A9".
    source_key: Mapped[str] = mapped_column(String)
    run_id: Mapped[int | None] = mapped_column(Integer, default=None)
    row_idx: Mapped[int | None] = mapped_column(Integer, default=None)
    note_id: Mapped[int | None] = mapped_column(Integer, default=None)
    ai_message_id: Mapped[int | None] = mapped_column(Integer, default=None)
    # Short description of the source when shared (shown if the source is gone).
    title: Mapped[str] = mapped_column(Text, default="")
    comment: Mapped[str] = mapped_column(Text, default="")
    # SHA-256 of the source's content when shared, to flag "changed since shared".
    source_sha256: Mapped[str] = mapped_column(String(64))
    shared_by: Mapped[str] = mapped_column(String, default="")
    shared_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IndicatorType(enum.StrEnum):
    PROCESS = (
        "process"  # process / executable name, e.g. updater.exe (also matches a path ending in it)
    )
    PATH = "path"  # file path (case-insensitive, / and \\ treated alike)
    IP = "ip"  # IPv4 / IPv6 address
    DOMAIN = "domain"  # host or domain name
    HASH = "hash"  # MD5 / SHA-1 / SHA-256 (hex)
    REGISTRY = "registry"  # registry key or value path
    TEXT = "text"  # anything else (mutex, service name, user name...), case-insensitive


class MatchMode(enum.StrEnum):
    EXACT = "exact"  # whole cell equals the indicator (after normalising for its type)
    CONTAINS = "contains"  # indicator appears anywhere in the cell (slower, more false positives)


class Indicator(Base):
    """An indicator on a case's watchlist, checked against the rows of the case's images."""

    __tablename__ = "indicators"
    __table_args__ = (UniqueConstraint("case_id", "type", "normalized", "match_mode", "column"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    type: Mapped[IndicatorType] = mapped_column(Enum(IndicatorType))
    value: Mapped[str] = mapped_column(Text)  # as entered
    normalized: Mapped[str] = mapped_column(Text)  # what is compared
    match_mode: Mapped[MatchMode] = mapped_column(Enum(MatchMode), default=MatchMode.EXACT)
    # Only look in this result column ("" = any column).
    column: Mapped[str] = mapped_column(String, default="")
    comment: Mapped[str] = mapped_column(Text, default="")
    # Where it was taken from, if made from a result row ("R12:3"), else "".
    source_key: Mapped[str] = mapped_column(String, default="")
    created_by: Mapped[str] = mapped_column(String, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # Last time every run of the case's images was checked for it (None = only new runs so far).
    checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)


class IndicatorHit(Base):
    """A result row (of one image's run) that matches an indicator."""

    __tablename__ = "indicator_hits"
    __table_args__ = (UniqueConstraint("indicator_id", "run_id", "row_idx", "column"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    indicator_id: Mapped[int] = mapped_column(
        ForeignKey("indicators.id", ondelete="CASCADE"), index=True
    )
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"), index=True)
    evidence_id: Mapped[int] = mapped_column(Integer, index=True)
    row_idx: Mapped[int] = mapped_column(Integer)
    column: Mapped[str] = mapped_column(String)
    cell: Mapped[str] = mapped_column(Text)  # the matching cell value (truncated)
    found_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SavedComparison(Base):
    """A before/after comparison saved to a case. Stores the settings and the counts when it was
    saved; opening it recomputes the diff from the (pinned) runs' current rows."""

    __tablename__ = "saved_comparisons"

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String)
    plugin: Mapped[str] = mapped_column(String)
    evidence_a_id: Mapped[int] = mapped_column(Integer)
    evidence_b_id: Mapped[int] = mapped_column(Integer)
    run_a_id: Mapped[int] = mapped_column(Integer)
    run_b_id: Mapped[int] = mapped_column(Integer)
    keys: Mapped[list[str]] = mapped_column(JSON)
    ignore: Mapped[list[str]] = mapped_column(JSON)
    # {"only_a": n, "only_b": n, "changed": n, "same": n} when saved.
    counts: Mapped[dict[str, int]] = mapped_column(JSON)
    comment: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DismissedRecommendation(Base):
    """A guide recommendation the analyst hid for one image ("not relevant here").

    ``key`` identifies the recommendation: tool, plugin and normalised args (see
    app/services/recommendations.py ``step_key``).
    """

    __tablename__ = "dismissed_recommendations"
    __table_args__ = (UniqueConstraint("evidence_id", "key"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    evidence_id: Mapped[int] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), index=True
    )
    key: Mapped[str] = mapped_column(String)
    tool: Mapped[str] = mapped_column(String)
    plugin: Mapped[str] = mapped_column(String)
    args: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_by: Mapped[str] = mapped_column(String, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
