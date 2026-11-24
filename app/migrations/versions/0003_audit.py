"""Audit log (append-only, hash-chained) and note version history.

- audit_events / note_versions: SQLite triggers reject every UPDATE and DELETE.
- audit_head: one row holding the chain's latest hash and sequence number (genesis = 64 zeros).
- Existing notes get a version-1 "create" entry so their history starts somewhere.

NOTE: if a later migration rebuilds audit_events or note_versions (batch mode), it must recreate
these triggers; tests/test_audit.py checks they exist at head.

Revision ID: 0003_audit
Revises: 0002_hooks
Create Date: 2026-11-24 13:53:59.436307
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_audit"
down_revision: str | None = "0002_hooks"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

GENESIS_HASH = "0" * 64
APPEND_ONLY_TABLES = ("audit_events", "note_versions")


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("ts", sa.String(), nullable=False),
        sa.Column("actor", sa.String(), nullable=False),
        sa.Column("origin", sa.String(), nullable=False),
        sa.Column("category", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("object_type", sa.String(), nullable=True),
        sa.Column("object_id", sa.Integer(), nullable=True),
        sa.Column("evidence_id", sa.Integer(), nullable=True),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("details", sa.JSON(none_as_null=True), nullable=True),
        sa.Column("request_id", sa.String(), nullable=True),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("hash", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("seq"),
    )
    with op.batch_alter_table("audit_events", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_audit_events_action"), ["action"], unique=False)
        batch_op.create_index(batch_op.f("ix_audit_events_category"), ["category"], unique=False)
        batch_op.create_index(
            batch_op.f("ix_audit_events_evidence_id"), ["evidence_id"], unique=False
        )
        batch_op.create_index(batch_op.f("ix_audit_events_ts"), ["ts"], unique=False)

    op.create_table(
        "audit_head",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("last_hash", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "note_versions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("note_id", sa.Integer(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=True),
        sa.Column("actor", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("note_id", "version"),
    )
    with op.batch_alter_table("note_versions", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_note_versions_note_id"), ["note_id"], unique=False)

    op.execute(
        sa.text("INSERT INTO audit_head (id, seq, last_hash) VALUES (1, 0, :h)").bindparams(
            h=GENESIS_HASH
        )
    )
    op.execute(
        "INSERT INTO note_versions "
        "(note_id, version, action, body, evidence_id, actor, created_at) "
        "SELECT id, 1, 'create', body, evidence_id, 'migration', created_at FROM notes"
    )
    for table in APPEND_ONLY_TABLES:
        for verb in ("UPDATE", "DELETE"):
            op.execute(
                f"CREATE TRIGGER {table}_no_{verb.lower()} BEFORE {verb} ON {table} "
                f"BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END"
            )
    op.execute(
        "CREATE TRIGGER audit_head_no_delete BEFORE DELETE ON audit_head "
        "BEGIN SELECT RAISE(ABORT, 'audit_head must not be deleted'); END"
    )


def downgrade() -> None:
    # Development only: this destroys the audit log.
    for table in APPEND_ONLY_TABLES:
        for verb in ("update", "delete"):
            op.execute(f"DROP TRIGGER IF EXISTS {table}_no_{verb}")
    op.execute("DROP TRIGGER IF EXISTS audit_head_no_delete")
    with op.batch_alter_table("note_versions", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_note_versions_note_id"))

    op.drop_table("note_versions")
    op.drop_table("audit_head")
    with op.batch_alter_table("audit_events", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_audit_events_ts"))
        batch_op.drop_index(batch_op.f("ix_audit_events_evidence_id"))
        batch_op.drop_index(batch_op.f("ix_audit_events_category"))
        batch_op.drop_index(batch_op.f("ix_audit_events_action"))

    op.drop_table("audit_events")
