"""System page and health checks."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.services import health
from tests.test_ai_helpers import mock_transport, respond_with


def _set(monkeypatch: pytest.MonkeyPatch, **env: str) -> Settings:
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    get_settings.cache_clear()
    return get_settings()


def _by_key(checks: list[health.Check]) -> dict[str, health.Check]:
    return {c.key: c for c in checks}


def test_quick_checks_on_a_fresh_install(session: Session, settings: Settings) -> None:
    checks = _by_key(health.quick_checks(session))
    assert set(checks) == {
        "disk", "folders", "symbols", "worker", "database", "audit", "hooks", "ai_config",
        "catalog", "guide", "backups",
    }  # fmt: skip
    assert checks["catalog"].status == "ok"
    assert checks["backups"].status == "warn" and "No backup yet" in checks["backups"].summary
    assert checks["disk"].status == "ok"
    assert checks["folders"].status == "ok"
    assert checks["database"].status == "ok" and "up to date" in checks["database"].summary
    assert checks["audit"].status in ("ok", "info") and "Chain verified" in checks["audit"].summary
    assert checks["worker"].status == "fail"  # not started in tests
    assert checks["hooks"].status == "ok"
    assert health.overall(list(checks.values())) == "fail"


def test_disk_check_levels(session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _set(monkeypatch, FT_MIN_FREE_DISK_BYTES=str(1024**5))
    check = health.check_disk(settings)
    assert check.status == "fail" and "New runs are blocked" in check.summary


def test_folder_and_symbol_problems(
    session: Session, settings: Settings, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    settings = _set(monkeypatch, FT_EVIDENCE_DIR=str(tmp_path / "missing"), FT_VOL_OFFLINE="true")
    folders = health.check_folders(session, settings)
    assert folders.status == "fail" and "is the volume mounted" in folders.summary
    symbols = health.check_symbols(settings)  # empty symbols folder + offline
    assert symbols.status == "warn" and "Offline mode" in symbols.summary
    (settings.symbols_dir / "windows").mkdir()
    assert health.check_symbols(settings).status == "ok"


def test_settings_summary_hides_secrets(settings: Settings) -> None:
    rows = dict(health.settings_summary(settings))
    assert rows["FT_AI_API_KEY"] == "set"
    assert rows["FT_ARTIFACT_ZIP_PASSWORD"] == "infected"  # noqa: S105 - public convention
    assert "test-key" not in rows.values()
    assert rows["FT_AI_MODEL"] == "test-model"


def _fake_vol(tmp_path: Path, plugins: str, code: int = 0) -> Path:
    """A fake `vol` as a Python script (run via the current interpreter on every OS)."""
    script = tmp_path / "vol.py"
    script.write_text(
        f"import sys\nprint('Volatility 3 Framework 9.9.9')\nprint({plugins!r})\nsys.exit({code})\n"
    )
    return script


def test_volatility_test(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from app.tools import registry

    catalog = " ".join(p.name for p in registry.get_runner("volatility3").plugins())
    _set(monkeypatch, FT_VOL_EXECUTABLE=str(_fake_vol(tmp_path, catalog)))
    check = health.run_volatility_test()
    assert check.status == "ok"
    assert ("Reports", "Volatility 3 Framework 9.9.9") in check.details

    _set(monkeypatch, FT_VOL_EXECUTABLE=str(_fake_vol(tmp_path, "windows.info.Info")))
    check = health.run_volatility_test()
    assert check.status == "warn" and "not in it" in check.summary

    _set(monkeypatch, FT_VOL_EXECUTABLE=str(_fake_vol(tmp_path, "", code=2)))
    assert health.run_volatility_test().status == "fail"

    _set(monkeypatch, FT_VOL_EXECUTABLE=str(tmp_path / "nope"))
    assert "not found" in health.run_volatility_test().summary


def test_ai_test(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.ai import client as client_mod

    real = client_mod.AIClient
    sink: list[dict] = []
    transport = mock_transport(respond_with("OK"), sink)
    monkeypatch.setattr(client_mod, "AIClient", lambda s: real(s, transport=transport))
    check = health.run_ai_test()
    assert check.status == "ok" and ("Reply", "OK") in check.details
    assert sink[0]["json"]["max_tokens"] == 10

    failing = mock_transport(lambda request: httpx.Response(401, text="bad key"))
    monkeypatch.setattr(client_mod, "AIClient", lambda s: real(s, transport=failing))
    check = health.run_ai_test()
    assert check.status == "fail" and "401" in check.summary


def test_system_page_api_and_badge(
    client: TestClient, settings: Settings, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    page = client.get("/system")
    assert page.status_code == 200
    assert "System checks" in page.text and "Test volatility" in page.text
    assert "FT_AI_API_KEY" in page.text and "test-key" not in page.text

    data = client.get("/api/system/health").json()
    assert data["status"] == "fail"  # worker not started in tests
    assert {c["key"] for c in data["checks"]} >= {"disk", "worker", "audit"}

    # Top bar: worker not running -> problem badge on every page.
    health.clear_badge_cache()
    home = client.get("/").text
    assert 'href="/system"' in home and "health-fail" in home

    _set(monkeypatch, FT_VOL_EXECUTABLE=str(_fake_vol(tmp_path, "")))
    r = client.post("/ui/system/test/volatility", headers={"HX-Request": "true"})
    assert r.status_code == 200 and "Volatility test" in r.text
    assert client.post("/api/system/health/volatility").json()["key"] == "volatility"
    assert client.post("/ui/system/test/nope").status_code == 404
    assert client.get("/health").json() == {"status": "ok"}
