"""Saved before/after comparisons on a case.

Revision ID: 0011_comparisons
Revises: 0010_indicators
Create Date: 2026-11-29 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011_comparisons"
down_revision: str | None = "0010_indicators"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
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
    op.create_index("ix_saved_comparisons_case_id", "saved_comparisons", ["case_id"])


def downgrade() -> None:
    op.drop_index("ix_saved_comparisons_case_id", table_name="saved_comparisons")
    op.drop_table("saved_comparisons")
