"""Settings changeable in the app (app/services/app_settings.py, /settings)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai import agent
from app.models import AuditEvent
from app.services import app_settings
from app.services import evidence as evidence_service


def test_override_reset_and_audit(session: Session) -> None:
    assert app_settings.get_value("agent_max_runs") == 5  # environment default
    changed = app_settings.update(
        session, {"agent_max_runs": "2", "agent_max_seconds": "1.5", "ai_tool_mode": "text"}
    )
    assert changed["agent_max_runs"] == (5, 2)
    assert app_settings.get_value("agent_max_seconds") == 90  # minutes -> seconds
    assert app_settings.get_value("ai_tool_mode", session) == "text"
    views = {v.spec.key: v for v in app_settings.list_settings(session)}
    assert views["agent_max_seconds"].display == 1.5 and views["agent_max_seconds"].overridden
    assert views["agent_max_steps"].overridden is False

    assert app_settings.update(session, {"agent_max_runs": "2"}) == {}  # unchanged
    assert app_settings.reset(session, "agent_max_runs")
    assert not app_settings.reset(session, "agent_max_runs")
    assert app_settings.get_value("agent_max_runs") == 5
    actions = session.scalars(select(AuditEvent.action)).all()
    assert "settings.update" in actions and "settings.reset" in actions


@pytest.mark.parametrize(
    ("values", "fragment"),
    [
        ({"agent_max_runs": "99"}, "must be 0-20"),
        ({"agent_max_steps": "2.5"}, "whole number"),
        ({"agent_max_steps": "x"}, "enter a number"),
        ({"ai_tool_mode": "magic"}, "choose one of"),
        ({"evidence_dir": "/elsewhere"}, "cannot be changed in the app"),
    ],
)
def test_validation(session: Session, values: dict, fragment: str) -> None:
    with pytest.raises(ValueError, match=fragment):
        app_settings.update(session, {"agent_max_runs": "3", **values})
    assert app_settings.get_value("agent_max_runs") == 5  # nothing saved


def test_agent_uses_effective_defaults(session: Session, monkeypatch) -> None:
    (ev,) = evidence_service.scan_evidence(session)
    app_settings.update(session, {"agent_max_steps": "7", "agent_max_runs": "1"})
    monkeypatch.setattr(agent, "_launch", lambda task_id: None)
    task = agent.start_task(session, ev.id, "g")
    assert task.limits["max_steps"] == 7 and task.limits["max_runs"] == 1


def test_settings_page_and_api(client: TestClient, session: Session) -> None:
    html = client.get("/settings").text
    assert "AI agent: default max steps" in html and "FT_AGENT_MAX_RUNS" in html
    assert 'href="/settings"' in client.get("/system").text  # nav link
    html = client.post("/settings", data={"agent_max_runs": "3", "ai_tool_mode": "native"}).text
    assert "Saved 2 change(s)." in html and "set in the app by" in html
    html = client.post("/settings", data={"agent_max_runs": "300"}).text
    assert "must be 0-20" in html
    html = client.post("/settings/agent_max_runs/reset").text
    assert "reset." in html
    data = {s["key"]: s for s in client.get("/api/system/settings").json()}
    assert (
        data["agent_max_runs"]["overridden"] is False and data["ai_tool_mode"]["value"] == "native"
    )
    assert client.put("/api/system/settings", json={"agent_max_steps": 9}).json()["changed"]
    assert client.put("/api/system/settings", json={"agent_max_steps": 0}).status_code == 422
    assert client.delete("/api/system/settings/agent_max_steps").json() == {"reset": True}
