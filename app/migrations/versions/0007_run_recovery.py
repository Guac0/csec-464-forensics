"""Run recovery: an "interrupted" run status, the tool's process id while it runs (to stop an
orphaned process after a crash) and "re-run of" provenance.

Existing runs that were marked failed with "interrupted by restart" become interrupted.

Revision ID: 0007_run_recovery
Revises: 0006_results
Create Date: 2026-11-25 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007_run_recovery"
down_revision: str | None = "0006_results"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD = ("QUEUED", "RUNNING", "SUCCEEDED", "FAILED", "CANCELLED")
NEW = (*OLD, "INTERRUPTED")


def upgrade() -> None:
    with op.batch_alter_table("runs", schema=None) as batch_op:
        batch_op.alter_column(
            "status",
            existing_type=sa.Enum(*OLD, name="runstatus"),
            type_=sa.Enum(*NEW, name="runstatus"),
            existing_nullable=False,
        )
        batch_op.add_column(sa.Column("rerun_of_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("pid", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_runs_rerun_of_id", "runs", ["rerun_of_id"], ["id"], ondelete="SET NULL"
        )
    op.execute(
        "UPDATE runs SET status = 'INTERRUPTED' "
        "WHERE status = 'FAILED' AND error = 'interrupted by restart'"
    )


def downgrade() -> None:
    op.execute("UPDATE runs SET status = 'FAILED' WHERE status = 'INTERRUPTED'")
    with op.batch_alter_table("runs", schema=None) as batch_op:
        batch_op.drop_constraint("fk_runs_rerun_of_id", type_="foreignkey")
        batch_op.drop_column("pid")
        batch_op.drop_column("rerun_of_id")
        batch_op.alter_column(
            "status",
            existing_type=sa.Enum(*NEW, name="runstatus"),
            type_=sa.Enum(*OLD, name="runstatus"),
            existing_nullable=False,
        )
