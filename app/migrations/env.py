"""Alembic environment.

Two ways in:
- At app startup, ``app.db.migrate()`` passes an open connection via ``config.attributes``.
- From the CLI (``alembic upgrade head`` / ``alembic revision --autogenerate``, using the
  repo-root ``alembic.ini``), the database URL comes from the app settings (``FT_DATA_DIR``).

SQLite cannot ALTER most things in place, so ``render_as_batch=True`` makes Alembic rebuild
tables ("batch mode") when a migration changes columns or constraints.
"""

from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine

from app import models  # noqa: F401  (registers all tables on Base.metadata)
from app.config import get_settings
from app.db import Base

config = context.config
target_metadata = Base.metadata


def _configure(connection) -> None:  # noqa: ANN001
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_offline() -> None:
    """``alembic upgrade head --sql``: emit SQL instead of executing it."""
    context.configure(
        url=get_settings().database_url,
        target_metadata=target_metadata,
        render_as_batch=True,
        literal_binds=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        _configure(connection)
        return
    settings = get_settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    engine = create_engine(settings.database_url)
    with engine.begin() as conn:
        _configure(conn)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
