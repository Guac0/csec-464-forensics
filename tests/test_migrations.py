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
        mc = MigrationContext.configure(conn, opts={"compare_type": True})
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
    from app import models  # noqa: F401

    engine = _engine(settings)
    db.Base.metadata.create_all(engine)  # what the PoC did before Alembic
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
