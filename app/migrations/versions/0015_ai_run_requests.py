"""AI agent run requests (approvals), runs queued by AI tasks, saved model reasoning.

Revision ID: 0015_ai_run_requests
Revises: 0014_ai_tasks
Create Date: 2026-12-03 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015_ai_run_requests"
down_revision: str | None = "0014_ai_tasks"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_STATUSES = ("QUEUED", "RUNNING", "DONE", "FAILED", "CANCELLED", "INTERRUPTED")
STATUSES = (
    "QUEUED", "RUNNING", "AWAITING_APPROVAL", "WAITING_FOR_RUNS", "DONE", "FAILED", "CANCELLED",
    "INTERRUPTED",
)  # fmt: skip


def upgrade() -> None:
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
        sa.ForeignKeyConstraint(["task_id"], ["ai_tasks.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_ai_run_requests_task_id", "ai_run_requests", ["task_id"])
    op.create_index("ix_ai_run_requests_run_id", "ai_run_requests", ["run_id"])
    with op.batch_alter_table("ai_tasks", schema=None) as batch_op:
        batch_op.alter_column(
            "status",
            existing_type=sa.Enum(*OLD_STATUSES, name="aitaskstatus"),
            type_=sa.Enum(*STATUSES, name="aitaskstatus"),
            existing_nullable=False,
        )
        batch_op.add_column(
            sa.Column("approve_all", sa.Boolean(), nullable=False, server_default="0")
        )
        batch_op.add_column(
            sa.Column("paused_seconds", sa.Integer(), nullable=False, server_default="0")
        )
    with op.batch_alter_table("runs", schema=None) as batch_op:
        batch_op.add_column(sa.Column("ai_task_id", sa.Integer(), nullable=True))
        batch_op.create_index("ix_runs_ai_task_id", ["ai_task_id"])
        batch_op.create_foreign_key(
            "fk_runs_ai_task_id", "ai_tasks", ["ai_task_id"], ["id"], ondelete="SET NULL"
        )
    with op.batch_alter_table("ai_messages", schema=None) as batch_op:
        batch_op.add_column(sa.Column("reasoning", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("ai_messages", schema=None) as batch_op:
        batch_op.drop_column("reasoning")
    with op.batch_alter_table("runs", schema=None) as batch_op:
        batch_op.drop_constraint("fk_runs_ai_task_id", type_="foreignkey")
        batch_op.drop_index("ix_runs_ai_task_id")
        batch_op.drop_column("ai_task_id")
    with op.batch_alter_table("ai_tasks", schema=None) as batch_op:
        batch_op.drop_column("paused_seconds")
        batch_op.drop_column("approve_all")
        batch_op.alter_column(
            "status",
            existing_type=sa.Enum(*STATUSES, name="aitaskstatus"),
            type_=sa.Enum(*OLD_STATUSES, name="aitaskstatus"),
            existing_nullable=False,
        )
    op.drop_index("ix_ai_run_requests_run_id", "ai_run_requests")
    op.drop_index("ix_ai_run_requests_task_id", "ai_run_requests")
    op.drop_table("ai_run_requests")
