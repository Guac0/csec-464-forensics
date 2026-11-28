"""Indicators: a per-case watchlist (process names, paths, IPs, hashes...) and the result rows
of the case's images that match them.

Revision ID: 0010_indicators
Revises: 0009_cases
Create Date: 2026-11-28 18:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010_indicators"
down_revision: str | None = "0009_cases"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TYPES = ("PROCESS", "PATH", "IP", "DOMAIN", "HASH", "REGISTRY", "TEXT")


def upgrade() -> None:
    op.create_table(
        "indicators",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column("type", sa.Enum(*TYPES, name="indicatortype"), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("normalized", sa.Text(), nullable=False),
        sa.Column("match_mode", sa.Enum("EXACT", "CONTAINS", name="matchmode"), nullable=False),
        sa.Column("column", sa.String(), nullable=False),
        sa.Column("comment", sa.Text(), nullable=False),
        sa.Column("source_key", sa.String(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_id", "type", "normalized", "match_mode", "column"),
    )
    op.create_index("ix_indicators_case_id", "indicators", ["case_id"])
    op.create_table(
        "indicator_hits",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("indicator_id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.Integer(), nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=False),
        sa.Column("row_idx", sa.Integer(), nullable=False),
        sa.Column("column", sa.String(), nullable=False),
        sa.Column("cell", sa.Text(), nullable=False),
        sa.Column("found_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["indicator_id"], ["indicators.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("indicator_id", "run_id", "row_idx", "column"),
    )
    op.create_index("ix_indicator_hits_indicator_id", "indicator_hits", ["indicator_id"])
    op.create_index("ix_indicator_hits_run_id", "indicator_hits", ["run_id"])
    op.create_index("ix_indicator_hits_evidence_id", "indicator_hits", ["evidence_id"])


def downgrade() -> None:
    op.drop_index("ix_indicator_hits_evidence_id", table_name="indicator_hits")
    op.drop_index("ix_indicator_hits_run_id", table_name="indicator_hits")
    op.drop_index("ix_indicator_hits_indicator_id", table_name="indicator_hits")
    op.drop_table("indicator_hits")
    op.drop_index("ix_indicators_case_id", table_name="indicators")
    op.drop_table("indicators")
