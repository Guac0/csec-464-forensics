"""Shared test fixtures. Shared contract: all test modules rely on these fixture names."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app import db
from app.config import Settings, get_settings

FIXTURES = Path(__file__).parent / "fixtures"
TEST_CONTENT_ROOT = "tests.content"


@pytest.fixture(autouse=True, scope="session")
def _test_content() -> Iterator[None]:
    """Infrastructure tests run against the frozen copy in tests/content/, not forensics/, so the
    forensics team can change their content without breaking these tests. Tests change the
    catalog/guide by monkeypatching attributes of ``content.current()``."""
    from app.tools import content

    content.use_root(TEST_CONTENT_ROOT)
    yield


def symlinks_supported(tmp_path: Path) -> bool:
    """Creating symlinks on Windows needs admin rights or Developer Mode; tests that need them
    skip (or drop the symlink part) when they are not available."""
    target, link = tmp_path / ".symlink-probe-target", tmp_path / ".symlink-probe"
    target.write_text("x")
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        return False
    finally:
        target.unlink(missing_ok=True)
    link.unlink()
    return True


@pytest.fixture
def settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Settings]:
    """Settings pointing at temp dirs. evidence_dir contains one small fake image."""
    evidence = tmp_path / "evidence"
    data = tmp_path / "data"
    symbols = tmp_path / "symbols"
    monkeypatch.setenv("FT_BACKUP_DIR", str(tmp_path / "backups"))
    for d in (evidence, data, symbols):
        d.mkdir()
    (evidence / "sample.raw").write_bytes(b"\x00" * 4096)
    monkeypatch.setenv("FT_EVIDENCE_DIR", str(evidence))
    monkeypatch.setenv("FT_DATA_DIR", str(data))
    monkeypatch.setenv("FT_SYMBOLS_DIR", str(symbols))
    monkeypatch.setenv("FT_AI_BASE_URL", "http://ai.test/v1")
    monkeypatch.setenv("FT_AI_API_KEY", "test-key")
    monkeypatch.setenv("FT_AI_MODEL", "test-model")
    # Disk-space guards off by default so tests don't depend on the machine's free space
    # (tests/test_resources.py turns them on).
    monkeypatch.setenv("FT_MIN_FREE_DISK_BYTES", "0")
    monkeypatch.setenv("FT_HARD_MIN_FREE_DISK_BYTES", "0")
    get_settings.cache_clear()
    yield get_settings()
    get_settings.cache_clear()


@pytest.fixture
def session(settings: Settings) -> Iterator[Session]:
    """A session on a fresh SQLite DB in settings.data_dir with all tables created."""
    db.init_engine()
    db.migrate()
    with db.SessionLocal() as s:
        yield s


@pytest.fixture
def client(session: Session):
    """FastAPI TestClient with the background worker disabled."""
    from fastapi.testclient import TestClient

    from app.main import create_app

    app = create_app(start_worker=False)
    with TestClient(app) as c:
        yield c
