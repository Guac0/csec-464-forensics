"""Post-run hooks: run findings/hook results, follow-up provenance, row annotations.

Adding the parent_run_id foreign key makes SQLite rebuild the runs table (batch mode).
app.db.migrate() turns foreign keys off during migrations so the rebuild cannot cascade-delete
result rows.

Revision ID: 0002_hooks
Revises: 0001_baseline
Create Date: 2026-11-24 13:34:11.530269
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_hooks"
down_revision: str | None = "0001_baseline"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("result_rows", schema=None) as batch_op:
        batch_op.add_column(sa.Column("annotations", sa.JSON(), nullable=True))

    with op.batch_alter_table("runs", schema=None) as batch_op:
        batch_op.add_column(sa.Column("hook_results", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("findings", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("parent_run_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("triggered_by_hook", sa.String(), nullable=True))
        batch_op.add_column(
            sa.Column("chain_depth", sa.Integer(), server_default="0", nullable=False)
        )
        batch_op.create_index(batch_op.f("ix_runs_parent_run_id"), ["parent_run_id"], unique=False)
        batch_op.create_foreign_key(
            "fk_runs_parent_run_id", "runs", ["parent_run_id"], ["id"], ondelete="SET NULL"
        )


def downgrade() -> None:
    with op.batch_alter_table("runs", schema=None) as batch_op:
        batch_op.drop_constraint("fk_runs_parent_run_id", type_="foreignkey")
        batch_op.drop_index(batch_op.f("ix_runs_parent_run_id"))
        batch_op.drop_column("chain_depth")
        batch_op.drop_column("triggered_by_hook")
        batch_op.drop_column("parent_run_id")
        batch_op.drop_column("findings")
        batch_op.drop_column("hook_results")

    with op.batch_alter_table("result_rows", schema=None) as batch_op:
        batch_op.drop_column("annotations")
