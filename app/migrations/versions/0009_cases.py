"""Cases: groups of evidence items, case notes and items shared between a case's images.

Global ("investigation") notes are replaced by case notes: if any exist, a "General" case is
created with every existing image as a member and those notes are moved into it (their version
history stays attached by note id).

Revision ID: 0009_cases
Revises: 0008_run_deletion
Create Date: 2026-11-28 12:00:00.000000
"""

from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision: str = "0009_cases"
down_revision: str | None = "0008_run_deletion"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

GENERAL = "General"


def upgrade() -> None:
    op.create_table(
        "cases",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "case_evidence",
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=False),
        sa.Column("label", sa.String(), nullable=False),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence.id"]),
        sa.PrimaryKeyConstraint("case_id", "evidence_id"),
    )
    op.create_index("ix_case_evidence_evidence_id", "case_evidence", ["evidence_id"])
    op.create_table(
        "shared_items",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column(
            "kind",
            sa.Enum("ROW", "FINDING", "NOTE", "AI_ANSWER", name="sharedkind"),
            nullable=False,
        ),
        sa.Column("source_evidence_id", sa.Integer(), nullable=False),
        sa.Column("source_key", sa.String(), nullable=False),
        sa.Column("run_id", sa.Integer(), nullable=True),
        sa.Column("row_idx", sa.Integer(), nullable=True),
        sa.Column("note_id", sa.Integer(), nullable=True),
        sa.Column("ai_message_id", sa.Integer(), nullable=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("comment", sa.Text(), nullable=False),
        sa.Column("source_sha256", sa.String(length=64), nullable=False),
        sa.Column("shared_by", sa.String(), nullable=False),
        sa.Column("shared_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["source_evidence_id"], ["evidence.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_id", "kind", "source_key"),
    )
    op.create_index("ix_shared_items_case_id", "shared_items", ["case_id"])
    op.create_index("ix_shared_items_source_evidence_id", "shared_items", ["source_evidence_id"])

    with op.batch_alter_table("notes", schema=None) as batch_op:
        batch_op.add_column(sa.Column("case_id", sa.Integer(), nullable=True))
        batch_op.create_index("ix_notes_case_id", ["case_id"])
        batch_op.create_foreign_key("fk_notes_case_id", "cases", ["case_id"], ["id"])
    # note_versions is append-only (triggers block UPDATE/DELETE); ADD COLUMN is still allowed.
    op.add_column("note_versions", sa.Column("case_id", sa.Integer(), nullable=True))

    bind = op.get_bind()
    has_global = bind.execute(
        sa.text("SELECT count(*) FROM notes WHERE evidence_id IS NULL")
    ).scalar()
    if has_global:
        now = datetime.now(UTC).isoformat(sep=" ")
        bind.execute(
            sa.text("INSERT INTO cases (name, description, created_at) VALUES (:n, :d, :t)"),
            {
                "n": GENERAL,
                "d": "Created when global investigation notes were replaced by case notes.",
                "t": now,
            },
        )
        case_id = bind.execute(
            sa.text("SELECT id FROM cases WHERE name = :n"), {"n": GENERAL}
        ).scalar()
        bind.execute(
            sa.text(
                "INSERT INTO case_evidence (case_id, evidence_id, label, added_at) "
                "SELECT :c, id, '', :t FROM evidence"
            ),
            {"c": case_id, "t": now},
        )
        bind.execute(
            sa.text("UPDATE notes SET case_id = :c WHERE evidence_id IS NULL"), {"c": case_id}
        )


def downgrade() -> None:
    op.execute("UPDATE notes SET case_id = NULL")
    op.drop_column("note_versions", "case_id")
    with op.batch_alter_table("notes", schema=None) as batch_op:
        batch_op.drop_constraint("fk_notes_case_id", type_="foreignkey")
        batch_op.drop_index("ix_notes_case_id")
        batch_op.drop_column("case_id")
    op.drop_index("ix_shared_items_source_evidence_id", table_name="shared_items")
    op.drop_index("ix_shared_items_case_id", table_name="shared_items")
    op.drop_table("shared_items")
    op.drop_index("ix_case_evidence_evidence_id", table_name="case_evidence")
    op.drop_table("case_evidence")
    op.drop_table("cases")
