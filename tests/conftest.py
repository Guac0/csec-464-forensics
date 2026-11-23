"""Shared test fixtures. Shared contract: all test modules rely on these fixture names."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app import db
from app.config import Settings, get_settings

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Settings]:
    """Settings pointing at temp dirs. evidence_dir contains one small fake image."""
    evidence = tmp_path / "evidence"
    data = tmp_path / "data"
    symbols = tmp_path / "symbols"
    for d in (evidence, data, symbols):
        d.mkdir()
    (evidence / "sample.raw").write_bytes(b"\x00" * 4096)
    monkeypatch.setenv("FT_EVIDENCE_DIR", str(evidence))
    monkeypatch.setenv("FT_DATA_DIR", str(data))
    monkeypatch.setenv("FT_SYMBOLS_DIR", str(symbols))
    monkeypatch.setenv("FT_AI_BASE_URL", "http://ai.test/v1")
    monkeypatch.setenv("FT_AI_API_KEY", "test-key")
    monkeypatch.setenv("FT_AI_MODEL", "test-model")
    get_settings.cache_clear()
    yield get_settings()
    get_settings.cache_clear()


@pytest.fixture
def session(settings: Settings) -> Iterator[Session]:
    """A session on a fresh SQLite DB in settings.data_dir with all tables created."""
    db.init_engine()
    db.create_all()
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
