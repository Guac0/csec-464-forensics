"""AI agent tasks ("give the AI a goal") and their steps.

Revision ID: 0014_ai_tasks
Revises: 0013_run_ai_message
Create Date: 2026-12-02 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014_ai_tasks"
down_revision: str | None = "0013_run_ai_message"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

STATUSES = ("QUEUED", "RUNNING", "DONE", "FAILED", "CANCELLED", "INTERRUPTED")


def upgrade() -> None:
    op.create_table(
        "ai_tasks",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=False),
        sa.Column("goal", sa.Text(), nullable=False),
        sa.Column("status", sa.Enum(*STATUSES, name="aitaskstatus"), nullable=False),
        sa.Column("limits", sa.JSON(), nullable=False),
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
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence.id"]),
        sa.ForeignKeyConstraint(["user_message_id"], ["ai_messages.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["answer_message_id"], ["ai_messages.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_ai_tasks_evidence_id", "ai_tasks", ["evidence_id"])
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
    op.create_index("ix_ai_task_steps_task_id", "ai_task_steps", ["task_id"])


def downgrade() -> None:
    op.drop_index("ix_ai_task_steps_task_id", "ai_task_steps")
    op.drop_table("ai_task_steps")
    op.drop_index("ix_ai_tasks_evidence_id", "ai_tasks")
    op.drop_table("ai_tasks")
