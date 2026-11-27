"""Database migration checks. These catch the common team mistakes early:

- changing app/models.py without adding a migration (models and migrations drift apart),
- two PRs each adding a migration on the same parent (multiple Alembic heads),
- migrations that cannot be downgraded/re-applied,
- breaking existing databases created before Alembic was introduced.
"""

from __future__ import annotations

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text

from app import db
from app.config import Settings


def _engine(settings: Settings, name: str = "mig.db"):
    return create_engine(f"sqlite:///{settings.data_dir / name}")


def _current_revision(engine) -> str | None:
    with engine.connect() as conn:
        return MigrationContext.configure(conn).get_current_revision()


def _head() -> str:
    heads = ScriptDirectory.from_config(db.alembic_config()).get_heads()
    assert len(heads) == 1
    return heads[0]


def test_single_head() -> None:
    heads = ScriptDirectory.from_config(db.alembic_config()).get_heads()
    assert len(heads) == 1, (
        f"multiple Alembic heads {heads}: two branches added migrations with the same parent. "
        "Rebase and set down_revision of the newer migration to the other head "
        "(or run `alembic merge heads`)."
    )


def test_migrations_match_models(settings: Settings) -> None:
    engine = _engine(settings)
    db.migrate(engine)
    with engine.connect() as conn:
        unmanaged = ("result_rows_fts",)  # see app/migrations/env.py
        mc = MigrationContext.configure(
            conn,
            opts={
                "compare_type": True,
                "include_object": lambda o, name, type_, *a: (
                    not (type_ == "table" and name and name.startswith(unmanaged))
                ),
            },
        )
        diff = compare_metadata(mc, db.Base.metadata)
    assert diff == [], (
        "app/models.py and the migrations differ. Create a migration with "
        "`alembic revision --autogenerate -m '...'` and review it. Differences: "
        f"{diff}"
    )


def test_migrate_is_idempotent(settings: Settings) -> None:
    engine = _engine(settings)
    db.migrate(engine)
    db.migrate(engine)
    assert _current_revision(engine) == _head()


def test_downgrade_to_base_and_upgrade_again(settings: Settings) -> None:
    engine = _engine(settings)
    db.migrate(engine)
    cfg = db.alembic_config()
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.downgrade(cfg, "base")
    assert set(inspect(engine).get_table_names()) <= {"alembic_version"}
    db.migrate(engine)
    assert _current_revision(engine) == _head()


def test_pre_alembic_database_is_stamped_and_keeps_data(settings: Settings) -> None:
    """A DB made by the old create_all() (no alembic_version table) must be adopted in place."""
    engine = _engine(settings)
    # Recreate what the PoC built before Alembic: the baseline schema without alembic_version.
    # (Base.metadata.create_all would build today's models, which are newer than the baseline.)
    cfg = db.alembic_config()
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, db.BASELINE_REVISION)
        conn.execute(text("DROP TABLE alembic_version"))
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO evidence (rel_path, size_bytes, mtime, description, created_at) "
                "VALUES ('old.raw', 1, 0, '', '2026-01-01 00:00:00')"
            )
        )
    db.migrate(engine)
    assert _current_revision(engine) == _head()
    with engine.connect() as conn:
        assert conn.execute(text("SELECT rel_path FROM evidence")).scalar_one() == "old.raw"


def test_table_rebuilds_do_not_cascade_delete_rows(settings: Settings) -> None:
    """Upgrading from the baseline rebuilds the runs table (SQLite batch mode). With foreign keys
    on, dropping the old table would cascade-delete every result row; migrate() must prevent it."""
    engine = _engine(settings)
    cfg = db.alembic_config()
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, db.BASELINE_REVISION)
        conn.execute(
            text(
                "INSERT INTO evidence (id, rel_path, size_bytes, mtime, description, created_at) "
                "VALUES (1, 'a.raw', 1, 0, '', '2026-01-01 00:00:00')"
            )
        )
        conn.execute(
            text(
                "INSERT INTO runs (id, evidence_id, tool, plugin, args, origin, status, "
                "created_at, row_count) VALUES (1, 1, 'volatility3', 'p', '{}', 'MANUAL', "
                "'SUCCEEDED', '2026-01-01 00:00:00', 2)"
            )
        )
        conn.execute(
            text(
                "INSERT INTO result_rows (run_id, row_idx, depth, data) "
                "VALUES (1, 0, 0, '{}'), (1, 1, 0, '{}')"
            )
        )
    db.migrate(engine)
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM result_rows")).scalar_one() == 2
        assert conn.execute(text("SELECT chain_depth FROM runs")).scalar_one() == 0
        # Foreign keys are switched back on for normal operation.
    with engine.connect() as conn:
        assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
