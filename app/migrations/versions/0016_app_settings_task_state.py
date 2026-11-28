"""Settings changed in the app; AI task checkpoints for resuming after a restart.

Revision ID: 0016_app_settings_task_state
Revises: 0015_ai_run_requests
Create Date: 2026-12-04 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0016_app_settings_task_state"
down_revision: str | None = "0015_ai_run_requests"
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
    with op.batch_alter_table("ai_tasks", schema=None) as batch_op:
        batch_op.add_column(sa.Column("state", sa.JSON(), nullable=True))
        batch_op.add_column(
            sa.Column("resumed_count", sa.Integer(), nullable=False, server_default="0")
        )


def downgrade() -> None:
    with op.batch_alter_table("ai_tasks", schema=None) as batch_op:
        batch_op.drop_column("resumed_count")
        batch_op.drop_column("state")
    op.drop_table("app_settings")
