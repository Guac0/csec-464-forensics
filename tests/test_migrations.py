"""Database migration checks. These catch the common team mistakes early:

- changing app/models.py without adding a migration (models and migrations drift apart),
- two PRs each adding a migration on the same parent (multiple Alembic heads),
- migrations that cannot be downgraded/re-applied,
- migrate() must refuse databases it cannot upgrade and keep foreign keys off while migrating.
"""

from __future__ import annotations

import pytest
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


@pytest.mark.parametrize("version", [None, "0017_ai_message_finish_reason"])
def test_database_from_before_the_squash_is_refused(settings: Settings, version) -> None:
    """Old databases (no alembic_version, or a revision squashed away) get a clear error."""
    engine = _engine(settings)
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE evidence (id INTEGER PRIMARY KEY)"))
        if version:
            conn.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32))"))
            conn.execute(text("INSERT INTO alembic_version VALUES (:v)"), {"v": version})
    with pytest.raises(RuntimeError, match="before the migration squash"):
        db.migrate(engine)


def test_foreign_keys_are_off_while_migrating(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SQLite batch mode rebuilds tables (copy, DROP, rename); with foreign keys on, the DROP
    would cascade-delete child rows. Future migrations rely on migrate() switching them off."""
    from alembic import command

    engine = _engine(settings)
    seen: list[int] = []
    real_upgrade = command.upgrade

    def spy(cfg, rev):
        seen.append(cfg.attributes["connection"].exec_driver_sql("PRAGMA foreign_keys").scalar())
        real_upgrade(cfg, rev)

    monkeypatch.setattr(command, "upgrade", spy)
    db.migrate(engine)
    assert seen == [0]
    with engine.connect() as conn:
        assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
