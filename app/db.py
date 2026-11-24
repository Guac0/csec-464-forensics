"""Database engine/session setup (SQLite on the /data volume)."""

import logging
from collections.abc import Iterator
from pathlib import Path

from alembic.config import Config
from sqlalchemy import create_engine, event, inspect
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


_engine: Engine | None = None
SessionLocal = sessionmaker(autoflush=False, expire_on_commit=False)


def init_engine(url: str | None = None) -> Engine:
    """Create (or recreate) the engine and bind SessionLocal. Called at startup and by tests."""
    global _engine
    settings = get_settings()
    if url is None:
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        url = settings.database_url
    _engine = create_engine(url, connect_args={"check_same_thread": False})

    @event.listens_for(_engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _record):  # noqa: ANN001
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    SessionLocal.configure(bind=_engine)
    return _engine


def get_engine() -> Engine:
    if _engine is None:
        init_engine()
    assert _engine is not None
    return _engine


MIGRATIONS_DIR = Path(__file__).parent / "migrations"
# The first migration, equal to the schema the PoC created with create_all() before Alembic.
BASELINE_REVISION = "0001_baseline"


def alembic_config() -> Config:
    """Alembic config built in code, so no alembic.ini is needed at runtime (or in the image)."""
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    return cfg


def migrate(engine: Engine | None = None) -> None:
    """Bring the database schema up to date by running Alembic migrations to ``head``.

    Databases created before Alembic was introduced (tables present, no ``alembic_version``) are
    stamped at the baseline revision first, so existing work is kept and later migrations apply.
    """
    from alembic import command

    from app import models  # noqa: F401  (register models on Base.metadata for env.py)

    engine = engine or get_engine()
    cfg = alembic_config()
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        tables = set(inspect(conn).get_table_names())
        if "alembic_version" not in tables and "evidence" in tables:
            logger.info("pre-Alembic database detected; stamping %s", BASELINE_REVISION)
            command.stamp(cfg, BASELINE_REVISION)
        command.upgrade(cfg, "head")


def get_session() -> Iterator[Session]:
    """FastAPI dependency."""
    get_engine()
    with SessionLocal() as session:
        yield session
