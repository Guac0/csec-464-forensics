from __future__ import annotations

from typing import Any

import httpx
import pytest

from app.ai.client import AIClient, AIError
from app.config import Settings
from tests.test_ai_helpers import chat_response, mock_transport, respond_with

MESSAGES = [{"role": "user", "content": "hi"}]


def test_chat_success(settings: Settings) -> None:
    sent: list[dict[str, Any]] = []
    client = AIClient(settings, transport=mock_transport(respond_with("hello"), sent))
    result = client.chat(MESSAGES)

    assert result.content == "hello"
    assert result.model_requested == "test-model"
    assert result.model_returned == "test-model-2025"
    assert result.usage == {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    assert result.params == {"model": "test-model", "temperature": 0.2, "max_tokens": 2000}
    assert result.raw["id"] == "chatcmpl-1"

    req = sent[0]
    assert req["url"] == "http://ai.test/v1/chat/completions"
    assert req["headers"]["authorization"] == "Bearer test-key"
    assert req["json"] == {**result.params, "messages": MESSAGES}


def test_chat_overrides_and_no_api_key(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "ai_api_key", "")
    sent: list[dict[str, Any]] = []
    client = AIClient(settings, transport=mock_transport(respond_with("x"), sent))
    result = client.chat(MESSAGES, model="other", temperature=0.0, max_tokens=10)
    assert result.params == {"model": "other", "temperature": 0.0, "max_tokens": 10}
    assert sent[0]["json"]["model"] == "other"
    assert "authorization" not in sent[0]["headers"]


def test_chat_rejects_unknown_override(settings: Settings) -> None:
    client = AIClient(settings, transport=mock_transport(respond_with("x")))
    with pytest.raises(ValueError):
        client.chat(MESSAGES, stream=True)


def test_chat_http_error(settings: Settings) -> None:
    transport = mock_transport(lambda r: httpx.Response(500, text="internal oops"))
    with pytest.raises(AIError, match="HTTP 500.*internal oops"):
        AIClient(settings, transport=transport).chat(MESSAGES)


def test_chat_timeout(settings: Settings) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    with pytest.raises(AIError, match="timed out"):
        AIClient(settings, transport=mock_transport(handler)).chat(MESSAGES)


def test_chat_connect_error(settings: Settings) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    with pytest.raises(AIError, match="request failed"):
        AIClient(settings, transport=mock_transport(handler)).chat(MESSAGES)


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, text="not json"),
        httpx.Response(200, json=[1, 2]),
        httpx.Response(200, json={"choices": []}),
        httpx.Response(200, json={"model": "m"}),
        httpx.Response(200, json=chat_response("x") | {"choices": [{"message": {"content": 5}}]}),
    ],
)
def test_chat_malformed(settings: Settings, response: httpx.Response) -> None:
    with pytest.raises(AIError):
        AIClient(settings, transport=mock_transport(lambda r: response)).chat(MESSAGES)
