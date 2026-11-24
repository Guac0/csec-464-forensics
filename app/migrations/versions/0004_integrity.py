"""Evidence integrity: MD5/SHA-1 alongside SHA-256, expected hashes + mismatch acknowledgement,
change detection, per-run evidence snapshot and phase, append-only integrity_checks history.

Images hashed before this migration keep their SHA-256; their MD5/SHA-1 are filled the next time
they are hashed (the worker re-hashes automatically before the next run).

Revision ID: 0004_integrity
Revises: 0003_audit
Create Date: 2026-11-24 14:07:48.367230
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_integrity"
down_revision: str | None = "0003_audit"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "integrity_checks",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.Integer(), nullable=True),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("result", sa.String(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("md5", sa.String(length=32), nullable=True),
        sa.Column("sha1", sa.String(length=40), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("mtime", sa.Double(), nullable=True),
        sa.Column("seconds", sa.Double(), nullable=True),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("integrity_checks", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_integrity_checks_evidence_id"), ["evidence_id"], unique=False
        )

    with op.batch_alter_table("evidence", schema=None) as batch_op:
        batch_op.add_column(sa.Column("md5", sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column("sha1", sa.String(length=40), nullable=True))
        batch_op.add_column(sa.Column("expected_sha256", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("expected_md5", sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column("expected_sha1", sa.String(length=40), nullable=True))
        batch_op.add_column(sa.Column("mismatch_ack_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("mismatch_ack_reason", sa.Text(), nullable=True))
        batch_op.add_column(
            sa.Column("changed_detected_at", sa.DateTime(timezone=True), nullable=True)
        )

    with op.batch_alter_table("runs", schema=None) as batch_op:
        batch_op.add_column(sa.Column("evidence_size_bytes", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("evidence_mtime", sa.Double(), nullable=True))
        batch_op.add_column(sa.Column("integrity_warning", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("phase", sa.String(), nullable=True))

    # Keep a record of hashes computed before this migration.
    op.execute(
        "INSERT INTO integrity_checks (evidence_id, kind, result, sha256, size_bytes, mtime, "
        "detail, created_at) SELECT id, 'initial', 'ok', sha256, size_bytes, mtime, "
        "'hash recorded before integrity checks existed', COALESCE(hashed_at, created_at) "
        "FROM evidence WHERE sha256 IS NOT NULL"
    )
    for verb in ("UPDATE", "DELETE"):
        op.execute(
            f"CREATE TRIGGER integrity_checks_no_{verb.lower()} BEFORE {verb} ON integrity_checks "
            "BEGIN SELECT RAISE(ABORT, 'integrity_checks is append-only'); END"
        )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS integrity_checks_no_update")
    op.execute("DROP TRIGGER IF EXISTS integrity_checks_no_delete")
    with op.batch_alter_table("runs", schema=None) as batch_op:
        batch_op.drop_column("phase")
        batch_op.drop_column("integrity_warning")
        batch_op.drop_column("evidence_mtime")
        batch_op.drop_column("evidence_size_bytes")

    with op.batch_alter_table("evidence", schema=None) as batch_op:
        batch_op.drop_column("changed_detected_at")
        batch_op.drop_column("mismatch_ack_reason")
        batch_op.drop_column("mismatch_ack_at")
        batch_op.drop_column("expected_sha1")
        batch_op.drop_column("expected_md5")
        batch_op.drop_column("expected_sha256")
        batch_op.drop_column("sha1")
        batch_op.drop_column("md5")

    with op.batch_alter_table("integrity_checks", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_integrity_checks_evidence_id"))

    op.drop_table("integrity_checks")
