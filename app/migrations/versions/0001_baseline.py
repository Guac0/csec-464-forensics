"""Baseline schema: the tables the PoC created with create_all() before Alembic was added.

Databases created before Alembic are stamped at this revision by app.db.migrate().

Revision ID: 0001_baseline
Revises:
Create Date: 2026-11-24 13:19:54.950248
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_baseline"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "evidence",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("rel_path", sa.String(), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("mtime", sa.Double(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("hashed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("os_info", sa.JSON(), nullable=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("rel_path"),
    )
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
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "notes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=True),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
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
            sa.Enum("MANUAL", "PRESET", "AUTO", "AI_SUGGESTED", name="runorigin"),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum("QUEUED", "RUNNING", "SUCCEEDED", "FAILED", "CANCELLED", name="runstatus"),
            nullable=False,
        ),
        sa.Column("tool_version", sa.String(), nullable=True),
        sa.Column("evidence_sha256", sa.String(length=64), nullable=True),
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
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "result_rows",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.Integer(), nullable=False),
        sa.Column("row_idx", sa.Integer(), nullable=False),
        sa.Column("depth", sa.Integer(), nullable=False),
        sa.Column("parent_idx", sa.Integer(), nullable=True),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "row_idx"),
    )
    with op.batch_alter_table("result_rows", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_result_rows_run_id"), ["run_id"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("result_rows", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_result_rows_run_id"))

    op.drop_table("result_rows")
    op.drop_table("runs")
    op.drop_table("notes")
    op.drop_table("ai_messages")
    op.drop_table("evidence")
