"""Run deletion tombstones: when a run's rows, raw output and dumped files were deleted, and why.

Revision ID: 0008_run_deletion
Revises: 0007_run_recovery
Create Date: 2026-11-27 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008_run_deletion"
down_revision: str | None = "0007_run_recovery"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("runs", schema=None) as batch_op:
        batch_op.add_column(sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("delete_reason", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("runs", schema=None) as batch_op:
        batch_op.drop_column("delete_reason")
        batch_op.drop_column("deleted_at")
