"""Answers cut off by the token limit (finish_reason "length") are detected and shown."""

from __future__ import annotations

import json

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.ai import agent, service
from app.ai.client import AIClient
from app.config import Settings
from app.services import evidence as evidence_service
from app.services import export


def _client(settings: Settings, finish: str = "length") -> AIClient:
    def handler(request: httpx.Request) -> httpx.Response:
        choice = {"message": {"role": "assistant", "content": "The process list shows"},
                  "finish_reason": finish}  # fmt: skip
        return httpx.Response(200, json={"model": "m", "choices": [choice]})

    return AIClient(settings, transport=httpx.MockTransport(handler))


@pytest.fixture
def ev(session: Session):
    (e,) = evidence_service.scan_evidence(session)
    return e


def test_client_flags_truncation(settings: Settings) -> None:
    result = _client(settings).chat([{"role": "user", "content": "x"}])
    assert result.finish_reason == "length" and result.truncated
    assert not _client(settings, "stop").chat([{"role": "user", "content": "x"}]).truncated


def test_answer_marked_in_ui_and_export(client: TestClient, session, settings, ev) -> None:
    msg = service.ask(session, ev.id, "anything?", client=_client(settings))
    assert msg.finish_reason == "length" and msg.truncated
    html = client.get(f"/ui/evidence/{ev.id}/ai", headers={"HX-Request": "true"}).text
    assert "cut off by the token limit" in html and "FT_AI_MAX_TOKENS" in html
    assert "cut off by the token limit" in "\n".join(export._ai_section(session, ev))
    ok = service.ask(session, ev.id, "again?", client=_client(settings, "stop"))
    assert not ok.truncated


def test_agent_notes_truncation(session, settings, ev, monkeypatch) -> None:
    client = _client(settings)
    monkeypatch.setattr(agent, "_launch", lambda task_id: agent.run_task(task_id, client=client))
    task = agent.start_task(session, ev.id, "g")
    session.refresh(task)
    assert any("cut off by the token limit" in s.summary for s in task.steps)
    from app.models import AIMessage

    assert session.get(AIMessage, task.answer_message_id).truncated
    assert json.dumps(agent.view(task, session).as_dict(), default=str)
