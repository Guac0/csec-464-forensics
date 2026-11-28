"""Why the model stopped answering (detects answers cut off by the token limit).

Revision ID: 0017_ai_message_finish_reason
Revises: 0016_app_settings_task_state
Create Date: 2026-12-05 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017_ai_message_finish_reason"
down_revision: str | None = "0016_app_settings_task_state"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("ai_messages", schema=None) as batch_op:
        batch_op.add_column(sa.Column("finish_reason", sa.String(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("ai_messages", schema=None) as batch_op:
        batch_op.drop_column("finish_reason")
