"""Initial schema (all earlier migrations 0001-0017 squashed for the team handoff).

Everything Alembic cannot autogenerate is at the end of upgrade(): the audit chain's genesis row,
append-only triggers (audit log, note history, integrity checks) and the FTS5 search table.
Databases from before the squash are not upgraded: recreate them (see docs/DEVELOPMENT.md).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Must match app/services/audit.py.
GENESIS_HASH = "0" * 64
APPEND_ONLY_TABLES = ("audit_events", "note_versions", "integrity_checks")

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "app_settings",
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("value", sa.JSON(), nullable=False),
        sa.Column("updated_by", sa.String(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("ts", sa.String(), nullable=False),
        sa.Column("actor", sa.String(), nullable=False),
        sa.Column("origin", sa.String(), nullable=False),
        sa.Column("category", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("object_type", sa.String(), nullable=True),
        sa.Column("object_id", sa.Integer(), nullable=True),
        sa.Column("evidence_id", sa.Integer(), nullable=True),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("details", sa.JSON(none_as_null=True), nullable=True),
        sa.Column("request_id", sa.String(), nullable=True),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("hash", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("seq"),
    )
    with op.batch_alter_table("audit_events", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_audit_events_action"), ["action"], unique=False)
        batch_op.create_index(batch_op.f("ix_audit_events_category"), ["category"], unique=False)
        batch_op.create_index(
            batch_op.f("ix_audit_events_evidence_id"), ["evidence_id"], unique=False
        )
        batch_op.create_index(batch_op.f("ix_audit_events_ts"), ["ts"], unique=False)

    op.create_table(
        "audit_head",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("last_hash", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "cases",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "evidence",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("rel_path", sa.String(), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("mtime", sa.Double(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("md5", sa.String(length=32), nullable=True),
        sa.Column("sha1", sa.String(length=40), nullable=True),
        sa.Column("hashed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expected_sha256", sa.String(length=64), nullable=True),
        sa.Column("expected_md5", sa.String(length=32), nullable=True),
        sa.Column("expected_sha1", sa.String(length=40), nullable=True),
        sa.Column("mismatch_ack_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("mismatch_ack_reason", sa.Text(), nullable=True),
        sa.Column("changed_detected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("os_info", sa.JSON(), nullable=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("rel_path"),
    )
    op.create_table(
        "integrity_checks",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.Integer(), nullable=True),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("result", sa.String(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("md5", sa.String(length=32), nullable=True),
        sa.Column("sha1", sa.String(length=40), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("mtime", sa.Double(), nullable=True),
        sa.Column("seconds", sa.Double(), nullable=True),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("integrity_checks", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_integrity_checks_evidence_id"), ["evidence_id"], unique=False
        )

    op.create_table(
        "note_versions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("note_id", sa.Integer(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=True),
        sa.Column("case_id", sa.Integer(), nullable=True),
        sa.Column("actor", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("note_id", "version"),
    )
    with op.batch_alter_table("note_versions", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_note_versions_note_id"), ["note_id"], unique=False)

    op.create_table(
        "ai_messages",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=True),
        sa.Column("role", sa.String(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("model_requested", sa.String(), nullable=True),
        sa.Column("model_returned", sa.String(), nullable=True),
        sa.Column("provider_base_url", sa.String(), nullable=True),
        sa.Column("params", sa.JSON(), nullable=True),
        sa.Column("request_messages", sa.JSON(), nullable=True),
        sa.Column("context_refs", sa.JSON(), nullable=True),
        sa.Column("citations", sa.JSON(), nullable=True),
        sa.Column("suggestions", sa.JSON(), nullable=True),
        sa.Column("usage", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("reasoning", sa.Text(), nullable=True),
        sa.Column("finish_reason", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "case_evidence",
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=False),
        sa.Column("label", sa.String(), nullable=False),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
        ),
        sa.PrimaryKeyConstraint("case_id", "evidence_id"),
    )
    with op.batch_alter_table("case_evidence", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_case_evidence_evidence_id"), ["evidence_id"], unique=False
        )

    op.create_table(
        "dismissed_recommendations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=False),
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("tool", sa.String(), nullable=False),
        sa.Column("plugin", sa.String(), nullable=False),
        sa.Column("args", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("evidence_id", "key"),
    )
    with op.batch_alter_table("dismissed_recommendations", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_dismissed_recommendations_evidence_id"), ["evidence_id"], unique=False
        )

    op.create_table(
        "indicators",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column(
            "type",
            sa.Enum(
                "PROCESS", "PATH", "IP", "DOMAIN", "HASH", "REGISTRY", "TEXT", name="indicatortype"
            ),
            nullable=False,
        ),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("normalized", sa.Text(), nullable=False),
        sa.Column("match_mode", sa.Enum("EXACT", "CONTAINS", name="matchmode"), nullable=False),
        sa.Column("column", sa.String(), nullable=False),
        sa.Column("comment", sa.Text(), nullable=False),
        sa.Column("source_key", sa.String(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_id", "type", "normalized", "match_mode", "column"),
    )
    with op.batch_alter_table("indicators", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_indicators_case_id"), ["case_id"], unique=False)

    op.create_table(
        "notes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=True),
        sa.Column("case_id", sa.Integer(), nullable=True),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], name="fk_notes_case_id"),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("notes", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_notes_case_id"), ["case_id"], unique=False)

    op.create_table(
        "saved_comparisons",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("plugin", sa.String(), nullable=False),
        sa.Column("evidence_a_id", sa.Integer(), nullable=False),
        sa.Column("evidence_b_id", sa.Integer(), nullable=False),
        sa.Column("run_a_id", sa.Integer(), nullable=False),
        sa.Column("run_b_id", sa.Integer(), nullable=False),
        sa.Column("keys", sa.JSON(), nullable=False),
        sa.Column("ignore", sa.JSON(), nullable=False),
        sa.Column("counts", sa.JSON(), nullable=False),
        sa.Column("comment", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("saved_comparisons", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_saved_comparisons_case_id"), ["case_id"], unique=False)

    op.create_table(
        "shared_items",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column(
            "kind",
            sa.Enum("ROW", "FINDING", "NOTE", "AI_ANSWER", name="sharedkind"),
            nullable=False,
        ),
        sa.Column("source_evidence_id", sa.Integer(), nullable=False),
        sa.Column("source_key", sa.String(), nullable=False),
        sa.Column("run_id", sa.Integer(), nullable=True),
        sa.Column("row_idx", sa.Integer(), nullable=True),
        sa.Column("note_id", sa.Integer(), nullable=True),
        sa.Column("ai_message_id", sa.Integer(), nullable=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("comment", sa.Text(), nullable=False),
        sa.Column("source_sha256", sa.String(length=64), nullable=False),
        sa.Column("shared_by", sa.String(), nullable=False),
        sa.Column("shared_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["source_evidence_id"],
            ["evidence.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_id", "kind", "source_key"),
    )
    with op.batch_alter_table("shared_items", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_shared_items_case_id"), ["case_id"], unique=False)
        batch_op.create_index(
            batch_op.f("ix_shared_items_source_evidence_id"), ["source_evidence_id"], unique=False
        )

    op.create_table(
        "ai_tasks",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=False),
        sa.Column("goal", sa.Text(), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "QUEUED",
                "RUNNING",
                "AWAITING_APPROVAL",
                "WAITING_FOR_RUNS",
                "DONE",
                "FAILED",
                "CANCELLED",
                "INTERRUPTED",
                name="aitaskstatus",
            ),
            nullable=False,
        ),
        sa.Column("limits", sa.JSON(), nullable=False),
        sa.Column("approve_all", sa.Boolean(), server_default="0", nullable=False),
        sa.Column("paused_seconds", sa.Integer(), server_default="0", nullable=False),
        sa.Column("state", sa.JSON(), nullable=True),
        sa.Column("resumed_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("tool_mode", sa.String(), nullable=True),
        sa.Column("steps_used", sa.Integer(), nullable=False),
        sa.Column("current_action", sa.String(), nullable=True),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("usage", sa.JSON(), nullable=True),
        sa.Column("user_message_id", sa.Integer(), nullable=True),
        sa.Column("answer_message_id", sa.Integer(), nullable=True),
        sa.Column("created_by", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["answer_message_id"], ["ai_messages.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
        ),
        sa.ForeignKeyConstraint(["user_message_id"], ["ai_messages.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("ai_tasks", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_ai_tasks_evidence_id"), ["evidence_id"], unique=False)

    op.create_table(
        "ai_task_steps",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("task_id", sa.Integer(), nullable=False),
        sa.Column("idx", sa.Integer(), nullable=False),
        sa.Column("turn", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("tool", sa.String(), nullable=True),
        sa.Column("args", sa.JSON(), nullable=True),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("row_keys", sa.JSON(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["task_id"], ["ai_tasks.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("ai_task_steps", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_ai_task_steps_task_id"), ["task_id"], unique=False)

    op.create_table(
        "runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=False),
        sa.Column("tool", sa.String(), nullable=False),
        sa.Column("plugin", sa.String(), nullable=False),
        sa.Column("args", sa.JSON(), nullable=False),
        sa.Column("argv", sa.JSON(), nullable=True),
        sa.Column(
            "origin",
            sa.Enum(
                "MANUAL",
                "PRESET",
                "AUTO",
                "AI_SUGGESTED",
                "HOOK",
                "RECOMMENDED",
                "AI_AGENT",
                name="runorigin",
            ),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum(
                "QUEUED",
                "RUNNING",
                "SUCCEEDED",
                "FAILED",
                "CANCELLED",
                "INTERRUPTED",
                name="runstatus",
            ),
            nullable=False,
        ),
        sa.Column("tool_version", sa.String(), nullable=True),
        sa.Column("evidence_sha256", sa.String(length=64), nullable=True),
        sa.Column("evidence_size_bytes", sa.Integer(), nullable=True),
        sa.Column("evidence_mtime", sa.Double(), nullable=True),
        sa.Column("integrity_warning", sa.Text(), nullable=True),
        sa.Column("phase", sa.String(), nullable=True),
        sa.Column("columns", sa.JSON(none_as_null=True), nullable=True),
        sa.Column("search_indexed", sa.Boolean(), server_default="0", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("returncode", sa.Integer(), nullable=True),
        sa.Column("stdout_path", sa.String(), nullable=True),
        sa.Column("stderr_path", sa.String(), nullable=True),
        sa.Column("stdout_sha256", sa.String(length=64), nullable=True),
        sa.Column("row_count", sa.Integer(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("hook_results", sa.JSON(none_as_null=True), nullable=True),
        sa.Column("findings", sa.JSON(none_as_null=True), nullable=True),
        sa.Column("parent_run_id", sa.Integer(), nullable=True),
        sa.Column("triggered_by_hook", sa.String(), nullable=True),
        sa.Column("ai_task_id", sa.Integer(), nullable=True),
        sa.Column("ai_message_id", sa.Integer(), nullable=True),
        sa.Column("chain_depth", sa.Integer(), server_default="0", nullable=False),
        sa.Column("rerun_of_id", sa.Integer(), nullable=True),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("delete_reason", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["ai_message_id"], ["ai_messages.id"], name="fk_runs_ai_message_id", ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["ai_task_id"], ["ai_tasks.id"], name="fk_runs_ai_task_id", ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
        ),
        sa.ForeignKeyConstraint(
            ["parent_run_id"], ["runs.id"], name="fk_runs_parent_run_id", ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["rerun_of_id"], ["runs.id"], name="fk_runs_rerun_of_id", ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("runs", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_runs_ai_message_id"), ["ai_message_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_runs_ai_task_id"), ["ai_task_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_runs_parent_run_id"), ["parent_run_id"], unique=False)

    op.create_table(
        "ai_run_requests",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("task_id", sa.Integer(), nullable=False),
        sa.Column("tool", sa.String(), nullable=False),
        sa.Column("plugin", sa.String(), nullable=False),
        sa.Column("args", sa.JSON(), nullable=False),
        sa.Column("final_args", sa.JSON(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("decided_by", sa.String(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("run_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["task_id"], ["ai_tasks.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("ai_run_requests", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_ai_run_requests_run_id"), ["run_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_ai_run_requests_task_id"), ["task_id"], unique=False)

    op.create_table(
        "derived_artifacts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.Integer(), nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=False),
        sa.Column("rel_path", sa.String(), nullable=False),
        sa.Column("filename", sa.String(), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("md5", sa.String(length=32), nullable=False),
        sa.Column("sha1", sa.String(length=40), nullable=False),
        sa.Column("file_type", sa.String(), nullable=False),
        sa.Column("source_row_idx", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["runs.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "rel_path"),
    )
    with op.batch_alter_table("derived_artifacts", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_derived_artifacts_evidence_id"), ["evidence_id"], unique=False
        )
        batch_op.create_index(batch_op.f("ix_derived_artifacts_run_id"), ["run_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_derived_artifacts_sha256"), ["sha256"], unique=False)

    op.create_table(
        "indicator_hits",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("indicator_id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.Integer(), nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=False),
        sa.Column("row_idx", sa.Integer(), nullable=False),
        sa.Column("column", sa.String(), nullable=False),
        sa.Column("cell", sa.Text(), nullable=False),
        sa.Column("found_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["indicator_id"], ["indicators.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("indicator_id", "run_id", "row_idx", "column"),
    )
    with op.batch_alter_table("indicator_hits", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_indicator_hits_evidence_id"), ["evidence_id"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_indicator_hits_indicator_id"), ["indicator_id"], unique=False
        )
        batch_op.create_index(batch_op.f("ix_indicator_hits_run_id"), ["run_id"], unique=False)

    op.create_table(
        "result_rows",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.Integer(), nullable=False),
        sa.Column("row_idx", sa.Integer(), nullable=False),
        sa.Column("depth", sa.Integer(), nullable=False),
        sa.Column("parent_idx", sa.Integer(), nullable=True),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("annotations", sa.JSON(none_as_null=True), nullable=True),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "row_idx"),
    )
    with op.batch_alter_table("result_rows", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_result_rows_run_id"), ["run_id"], unique=False)

    op.execute(
        sa.text("INSERT INTO audit_head (id, seq, last_hash) VALUES (1, 0, :h)").bindparams(
            h=GENESIS_HASH
        )
    )
    for table in APPEND_ONLY_TABLES:
        for verb in ("UPDATE", "DELETE"):
            op.execute(
                f"CREATE TRIGGER {table}_no_{verb.lower()} BEFORE {verb} ON {table} "
                f"BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END"
            )
    op.execute(
        "CREATE TRIGGER audit_head_no_delete BEFORE DELETE ON audit_head "
        "BEGIN SELECT RAISE(ABORT, 'audit_head must not be deleted'); END"
    )
    # Optional full-text search over result rows; rowid = result_rows.id (app/services/results.py).
    op.execute(
        "CREATE VIRTUAL TABLE IF NOT EXISTS result_rows_fts USING fts5(text, tokenize='trigram')"
    )


def downgrade() -> None:
    # Development only: this destroys everything, including the audit log.
    op.execute("DROP TABLE IF EXISTS result_rows_fts")
    op.execute("DROP TRIGGER IF EXISTS audit_head_no_delete")
    for table in APPEND_ONLY_TABLES:
        for verb in ("update", "delete"):
            op.execute(f"DROP TRIGGER IF EXISTS {table}_no_{verb}")
    with op.batch_alter_table("result_rows", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_result_rows_run_id"))

    op.drop_table("result_rows")
    with op.batch_alter_table("indicator_hits", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_indicator_hits_run_id"))
        batch_op.drop_index(batch_op.f("ix_indicator_hits_indicator_id"))
        batch_op.drop_index(batch_op.f("ix_indicator_hits_evidence_id"))

    op.drop_table("indicator_hits")
    with op.batch_alter_table("derived_artifacts", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_derived_artifacts_sha256"))
        batch_op.drop_index(batch_op.f("ix_derived_artifacts_run_id"))
        batch_op.drop_index(batch_op.f("ix_derived_artifacts_evidence_id"))

    op.drop_table("derived_artifacts")
    with op.batch_alter_table("ai_run_requests", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_ai_run_requests_task_id"))
        batch_op.drop_index(batch_op.f("ix_ai_run_requests_run_id"))

    op.drop_table("ai_run_requests")
    with op.batch_alter_table("runs", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_runs_parent_run_id"))
        batch_op.drop_index(batch_op.f("ix_runs_ai_task_id"))
        batch_op.drop_index(batch_op.f("ix_runs_ai_message_id"))

    op.drop_table("runs")
    with op.batch_alter_table("ai_task_steps", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_ai_task_steps_task_id"))

    op.drop_table("ai_task_steps")
    with op.batch_alter_table("ai_tasks", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_ai_tasks_evidence_id"))

    op.drop_table("ai_tasks")
    with op.batch_alter_table("shared_items", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_shared_items_source_evidence_id"))
        batch_op.drop_index(batch_op.f("ix_shared_items_case_id"))

    op.drop_table("shared_items")
    with op.batch_alter_table("saved_comparisons", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_saved_comparisons_case_id"))

    op.drop_table("saved_comparisons")
    with op.batch_alter_table("notes", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_notes_case_id"))

    op.drop_table("notes")
    with op.batch_alter_table("indicators", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_indicators_case_id"))

    op.drop_table("indicators")
    with op.batch_alter_table("dismissed_recommendations", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_dismissed_recommendations_evidence_id"))

    op.drop_table("dismissed_recommendations")
    with op.batch_alter_table("case_evidence", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_case_evidence_evidence_id"))

    op.drop_table("case_evidence")
    op.drop_table("ai_messages")
    with op.batch_alter_table("note_versions", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_note_versions_note_id"))

    op.drop_table("note_versions")
    with op.batch_alter_table("integrity_checks", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_integrity_checks_evidence_id"))

    op.drop_table("integrity_checks")
    op.drop_table("evidence")
    op.drop_table("cases")
    op.drop_table("audit_head")
    with op.batch_alter_table("audit_events", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_audit_events_ts"))
        batch_op.drop_index(batch_op.f("ix_audit_events_evidence_id"))
        batch_op.drop_index(batch_op.f("ix_audit_events_category"))
        batch_op.drop_index(batch_op.f("ix_audit_events_action"))

    op.drop_table("audit_events")
    op.drop_table("app_settings")
