"""Large results: per-run column list (stable table columns, typed sort/filter) and an optional
FTS5 trigram search index (``result_rows_fts``; filled only for runs stored with
FT_SEARCH_INDEX=true).

Existing runs get their ``columns`` computed from their rows here (a one-off scan).

Revision ID: 0006_results
Revises: 0005_artifacts
Create Date: 2026-11-25 01:12:23.229489
"""

import json
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_results"
down_revision: str | None = "0005_artifacts"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("runs", schema=None) as batch_op:
        batch_op.add_column(sa.Column("columns", sa.JSON(none_as_null=True), nullable=True))
        batch_op.add_column(
            sa.Column("search_indexed", sa.Boolean(), server_default="0", nullable=False)
        )

    # rowid = result_rows.id. Contains a copy of each indexed row's values as text.
    op.execute(
        "CREATE VIRTUAL TABLE IF NOT EXISTS result_rows_fts USING fts5(text, tokenize='trigram')"
    )

    # Backfill the column list of existing runs (same rules as app/services/results.py).
    bind = op.get_bind()
    run_ids = [r[0] for r in bind.execute(sa.text("SELECT id FROM runs WHERE row_count > 0"))]
    for run_id in run_ids:
        order: dict[str, set[str]] = {}
        rows = bind.execute(
            sa.text("SELECT data FROM result_rows WHERE run_id = :r ORDER BY row_idx"),
            {"r": run_id},
        )
        for (data,) in rows:
            for key, value in (json.loads(data) if isinstance(data, str) else data or {}).items():
                order.setdefault(key, set()).add(_type_name(value))
        columns = [{"name": k, "type": _merge(v)} for k, v in order.items()]
        bind.execute(
            sa.text("UPDATE runs SET columns = :c WHERE id = :r"),
            {"c": json.dumps(columns), "r": run_id},
        )


def _type_name(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    return "json"


def _merge(types: set[str]) -> str:
    types = types - {"null"}
    if not types:
        return "null"
    if types <= {"int", "float"}:
        return "float" if "float" in types else "int"
    return types.pop() if len(types) == 1 else "mixed"


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS result_rows_fts")
    with op.batch_alter_table("runs", schema=None) as batch_op:
        batch_op.drop_column("search_indexed")
        batch_op.drop_column("columns")
