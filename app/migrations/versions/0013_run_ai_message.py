"""Link runs to the AI answer whose suggestion started them.

Revision ID: 0013_run_ai_message
Revises: 0012_dismissed_recommendations
Create Date: 2026-12-01 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013_run_ai_message"
down_revision: str | None = "0012_dismissed_recommendations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("runs", schema=None) as batch_op:
        batch_op.add_column(sa.Column("ai_message_id", sa.Integer(), nullable=True))
        batch_op.create_index("ix_runs_ai_message_id", ["ai_message_id"])
        batch_op.create_foreign_key(
            "fk_runs_ai_message_id", "ai_messages", ["ai_message_id"], ["id"], ondelete="SET NULL"
        )


def downgrade() -> None:
    with op.batch_alter_table("runs", schema=None) as batch_op:
        batch_op.drop_constraint("fk_runs_ai_message_id", type_="foreignkey")
        batch_op.drop_index("ix_runs_ai_message_id")
        batch_op.drop_column("ai_message_id")
