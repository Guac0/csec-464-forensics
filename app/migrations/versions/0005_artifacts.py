"""Derived artifacts: files written by tools during a run (e.g. --dump output).

Revision ID: 0005_artifacts
Revises: 0004_integrity
Create Date: 2026-11-24 14:20:26.083405
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_artifacts"
down_revision: str | None = "0004_integrity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "derived_artifacts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.Integer(), nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=False),
        sa.Column("rel_path", sa.String(), nullable=False),
        sa.Column("filename", sa.String(), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("md5", sa.String(length=32), nullable=False),
        sa.Column("sha1", sa.String(length=40), nullable=False),
        sa.Column("file_type", sa.String(), nullable=False),
        sa.Column("source_row_idx", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["runs.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "rel_path"),
    )
    with op.batch_alter_table("derived_artifacts", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_derived_artifacts_evidence_id"), ["evidence_id"], unique=False
        )
        batch_op.create_index(batch_op.f("ix_derived_artifacts_run_id"), ["run_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_derived_artifacts_sha256"), ["sha256"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("derived_artifacts", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_derived_artifacts_sha256"))
        batch_op.drop_index(batch_op.f("ix_derived_artifacts_run_id"))
        batch_op.drop_index(batch_op.f("ix_derived_artifacts_evidence_id"))

    op.drop_table("derived_artifacts")
