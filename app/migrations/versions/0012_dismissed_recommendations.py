"""Guide recommendations dismissed per image.

Revision ID: 0012_dismissed_recommendations
Revises: 0011_comparisons
Create Date: 2026-11-30 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012_dismissed_recommendations"
down_revision: str | None = "0011_comparisons"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
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
    op.create_index(
        "ix_dismissed_recommendations_evidence_id", "dismissed_recommendations", ["evidence_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_dismissed_recommendations_evidence_id", "dismissed_recommendations")
    op.drop_table("dismissed_recommendations")
