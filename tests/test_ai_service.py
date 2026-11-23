from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from sqlalchemy.orm import Session

from app.ai import service
from app.ai.client import AIClient
from app.ai.context import NotFoundError
from app.config import Settings
from app.models import AIMessage
from tests.test_ai_helpers import PSLIST, install_fake_runner, mock_transport, respond_with, seed


@pytest.fixture(autouse=True)
def fake_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    install_fake_runner(monkeypatch)


def _answer(run_id: int) -> str:
    suggestions = [
        {"plugin": PSLIST, "args": {"pid": [101]}, "reason": "look closer"},
        {"plugin": "windows.nope.Nope", "args": {}, "reason": "bad"},
    ]
    return (
        f"p1.exe looks odd [R{run_id}:1]. Also [R{run_id}:999].\n\n"
        f"```suggestions\n{json.dumps(suggestions)}\n```\n"
    )


def test_ask_persists_full_provenance(session: Session, settings: Settings) -> None:
    ev, run = seed(session)
    sent: list[dict[str, Any]] = []
    client = AIClient(settings, transport=mock_transport(respond_with(_answer(run.id)), sent))

    msg = service.ask(session, ev.id, "Anything suspicious?", client=client)

    assert msg.role == "assistant" and msg.error is None
    assert msg.content == f"p1.exe looks odd [R{run.id}:1]. Also [R{run.id}:999]."
    assert "```suggestions" not in msg.content
    assert msg.model_requested == "test-model"
    assert msg.model_returned == "test-model-2025"
    assert msg.provider_base_url == "http://ai.test/v1"
    assert msg.params == {"model": "test-model", "temperature": 0.2, "max_tokens": 2000}
    assert msg.usage == {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    # exact messages sent are recorded
    assert msg.request_messages == sent[0]["json"]["messages"]
    roles = [m["role"] for m in msg.request_messages]
    assert roles == ["system", "user", "user"]
    assert PSLIST in msg.request_messages[0]["content"]  # allowlist rendered
    assert f"[R{run.id}:0]" in msg.request_messages[1]["content"]  # context
    assert msg.request_messages[-1]["content"] == "Anything suspicious?"
    assert msg.context_refs is not None and msg.context_refs["run_ids"] == [run.id]
    assert [(c["key"], c["valid"]) for c in msg.citations or []] == [
        (f"R{run.id}:1", True),
        (f"R{run.id}:999", False),
    ]
    sugg = msg.suggestions or []
    assert [s["valid"] for s in sugg] == [True, False]
    assert sugg[0]["normalized_args"] == {"pid": [101]}

    stored = service.get_messages(session, ev.id)
    assert [(m.role, m.id) for m in stored] == [("user", stored[0].id), ("assistant", msg.id)]
    assert stored[0].content == "Anything suspicious?"


def test_ask_includes_history(session: Session, settings: Settings) -> None:
    ev, run = seed(session)
    sent: list[dict[str, Any]] = []
    client = AIClient(settings, transport=mock_transport(respond_with("ok"), sent))
    service.ask(session, ev.id, "first?", client=client)
    service.ask(session, ev.id, "second?", client=client)

    messages = sent[1]["json"]["messages"]
    assert [m["role"] for m in messages] == ["system", "user", "user", "assistant", "user"]
    assert messages[2]["content"] == "first?" and messages[3]["content"] == "ok"
    assert messages[-1]["content"] == "second?"


def test_ask_provider_error_is_recorded(session: Session, settings: Settings) -> None:
    ev, _ = seed(session)
    client = AIClient(
        settings, transport=mock_transport(lambda r: httpx.Response(503, text="overloaded"))
    )
    msg = service.ask(session, ev.id, "Anything?", client=client)

    assert msg.role == "assistant"
    assert msg.error is not None and "HTTP 503" in msg.error
    assert msg.content.startswith("AI request failed:")
    assert msg.model_requested == "test-model" and msg.model_returned is None
    assert msg.provider_base_url == "http://ai.test/v1"
    assert msg.request_messages and msg.request_messages[-1]["content"] == "Anything?"
    assert msg.params is not None and msg.context_refs is not None
    assert session.get(AIMessage, msg.id) is not None

    # failed turns are not replayed as history
    sent: list[dict[str, Any]] = []
    ok = AIClient(settings, transport=mock_transport(respond_with("fine"), sent))
    service.ask(session, ev.id, "retry", client=ok)
    roles = [m["role"] for m in sent[0]["json"]["messages"]]
    assert roles == ["system", "user", "user", "user"]


def test_summarize_run(session: Session, settings: Settings) -> None:
    ev, run = seed(session)
    sent: list[dict[str, Any]] = []
    client = AIClient(settings, transport=mock_transport(respond_with("summary"), sent))
    msg = service.summarize_run(session, run.id, client=client)

    assert msg.content == "summary"
    assert msg.evidence_id == ev.id
    assert msg.context_refs is not None and msg.context_refs["run_ids"] == [run.id]
    assert f"R{run.id}" in sent[0]["json"]["messages"][-1]["content"]


def test_not_found(session: Session, settings: Settings) -> None:
    client = AIClient(settings, transport=mock_transport(respond_with("x")))
    with pytest.raises(NotFoundError):
        service.ask(session, 999, "q", client=client)
    with pytest.raises(NotFoundError):
        service.summarize_run(session, 999, client=client)
