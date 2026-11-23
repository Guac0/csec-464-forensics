"""API tests against a minimal app containing only the AI router (app.main is owned elsewhere)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.ai import service
from app.ai.client import AIClient
from app.api.ai import router
from app.config import Settings
from tests.test_ai_helpers import PSLIST, install_fake_runner, mock_transport, respond_with, seed


@pytest.fixture
def api(
    session: Session, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> Iterator[TestClient]:
    install_fake_runner(monkeypatch)
    answer = (
        "Odd [R1:0].\n```suggestions\n"
        f'[{{"plugin": "{PSLIST}", "args": {{"pid": [4]}}, "reason": "r"}}]\n```'
    )
    transport = mock_transport(respond_with(answer))
    monkeypatch.setattr(service, "AIClient", lambda s: AIClient(s, transport=transport))
    app = FastAPI()
    app.include_router(router)
    with TestClient(app) as c:
        yield c


def test_ask_summarize_and_list(api: TestClient, session: Session) -> None:
    ev, run = seed(session)
    assert run.id == 1

    r = api.post("/api/ai/ask", json={"evidence_id": ev.id, "question": "What is odd?"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["role"] == "assistant" and body["is_ai_output"] is True
    assert body["content"] == "Odd [R1:0]."
    assert body["citations"][0]["valid"] is True
    assert body["suggestions"][0]["valid"] is True
    assert body["model_returned"] == "test-model-2025"
    assert body["request_messages"][-1]["content"] == "What is odd?"

    r = api.post(f"/api/ai/summarize/{run.id}")
    assert r.status_code == 200, r.text

    r = api.get("/api/ai/messages", params={"evidence_id": ev.id})
    assert r.status_code == 200
    assert [m["role"] for m in r.json()] == ["user", "assistant", "user", "assistant"]
    assert r.json()[0]["is_ai_output"] is False


def test_errors(api: TestClient, session: Session) -> None:
    assert api.post("/api/ai/ask", json={"evidence_id": 42, "question": "q"}).status_code == 404
    assert api.post("/api/ai/summarize/42").status_code == 404
    assert api.post("/api/ai/ask", json={"evidence_id": 1, "question": ""}).status_code == 422
