"""app/ai/probe.py: provider check and task report (for testing against the real provider)."""

from __future__ import annotations

import json

import httpx
import pytest
from sqlalchemy.orm import Session

from app.ai import agent, probe
from app.ai.client import AIClient
from app.config import Settings
from app.services import evidence as evidence_service


def _client(settings: Settings, native: bool) -> AIClient:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if "tools" in body and not native:
            return httpx.Response(400, text='{"error": "tools not supported"}')
        last = body["messages"][-1]
        if "tools" in body and last["role"] == "user":
            call = {"name": "get_time", "arguments": '{"timezone": "UTC"}'}
            tool_calls = [{"id": "t1", "type": "function", "function": call}]
            msg = {"role": "assistant", "content": None, "tool_calls": tool_calls}
        elif last["role"] == "tool":
            msg = {"role": "assistant", "content": "It is 12:00 UTC."}
        elif body["messages"][0]["role"] == "system":
            action = '```action\n{"tool": "get_time", "args": {"timezone": "UTC"}}\n```'
            msg = {"role": "assistant", "content": action}
        else:
            msg = {"role": "assistant", "content": "<think>easy</think>OK"}
        return httpx.Response(200, json={"model": "qwen3.6", "choices": [{"message": msg}]})

    return AIClient(settings, transport=httpx.MockTransport(handler))


@pytest.mark.parametrize("native", [True, False])
def test_probe_provider(session: Session, settings: Settings, native: bool) -> None:
    report = probe.probe_provider(_client(settings, native))
    assert "api_key" not in json.dumps(report["config"]).replace("api_key_set", "")
    assert report["plain_answer"]["content"] == "OK"
    assert report["plain_answer"]["reasoning_source"] == "<think> tags"
    verdict = report["verdict"]
    assert verdict["text_protocol_works"] and verdict["reasoning_returned"]
    if native:
        assert verdict["auto_mode_would_use"] == "native"
        assert report["native_tool_round_trip"]["mentions_tool_result"]
    else:
        assert verdict["auto_mode_would_use"] == "text"
        assert report["native_tool_call"]["http_status"] == 400


def test_task_report(session: Session, settings: Settings, monkeypatch, tmp_path, capsys) -> None:
    (ev,) = evidence_service.scan_evidence(session)

    def handler(request: httpx.Request) -> httpx.Response:
        msg = {"role": "assistant", "content": "<think>hmm</think>Nothing found."}
        return httpx.Response(200, json={"model": "m", "choices": [{"message": msg}]})

    client = AIClient(settings, transport=httpx.MockTransport(handler))
    monkeypatch.setattr(agent, "_launch", lambda task_id: agent.run_task(task_id, client=client))
    task = agent.start_task(session, ev.id, "find xyz")
    out = tmp_path / "r.json"
    assert probe.main(["--out", str(out), "task", str(task.id)]) == 0
    report = json.loads(out.read_text())
    assert report["task"]["status"] == "done" and report["answer"]["content"] == "Nothing found."
    assert report["answer"]["reasoning_chars"] > 0 and "reasoning" not in report["answer"]
    assert '"status": "done"' in capsys.readouterr().out
