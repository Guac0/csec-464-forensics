"""AI agent (feature 3a): read-only tools, native + text protocols, limits, cancel, UI, API."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai import agent
from app.ai import agent_tools as tools
from app.ai.client import AIClient, split_reasoning
from app.config import Settings
from app.models import (
    AIMessage,
    AITask,
    AITaskStatus,
    AuditEvent,
    Evidence,
    ResultRow,
    Run,
    RunStatus,
)
from app.services import evidence as evidence_service

PSLIST = "windows.pslist.PsList"
HX = {"HX-Request": "true"}


@pytest.fixture
def ev(session: Session) -> Evidence:
    (e,) = evidence_service.scan_evidence(session)
    e.os_info = {"os": "windows"}
    session.commit()
    return e


@pytest.fixture
def pslist(session: Session, ev: Evidence) -> Run:
    run = Run(
        evidence_id=ev.id,
        plugin=PSLIST,
        args={},
        status=RunStatus.SUCCEEDED,
        row_count=3,
        columns=[{"name": "PID", "type": "int"}, {"name": "ImageFileName", "type": "str"}],
    )
    session.add(run)
    session.flush()
    for i, name in enumerate(["System", "xyz.exe", "svchost.exe"]):
        session.add(
            ResultRow(run_id=run.id, row_idx=i, data={"PID": 4 + i * 100, "ImageFileName": name})
        )
    session.commit()
    return run


@pytest.fixture(autouse=True)
def _clear_mode_cache() -> None:
    agent._mode_cache.clear()


def _reply(content: str | None = "", tool_calls: list | None = None, model: str = "qwen3.6"):
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return httpx.Response(
        200,
        json={"model": model, "choices": [{"message": message}], "usage": {"total_tokens": 10}},
    )


def _call(name: str, args: dict, call_id: str = "c1") -> dict:
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(args)},
    }


def scripted(
    settings: Settings, replies: list[Callable[[dict], httpx.Response] | httpx.Response]
) -> tuple[AIClient, list[dict]]:
    sent: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        sent.append(body)
        reply = replies.pop(0)
        return reply(body) if callable(reply) else reply

    return AIClient(settings, transport=httpx.MockTransport(handler)), sent


def _start(
    session: Session,
    ev: Evidence,
    monkeypatch: pytest.MonkeyPatch,
    client: AIClient,
    goal: str = "find processes named xyz",
    **limits: Any,
) -> AITask:
    monkeypatch.setattr(agent, "_launch", lambda task_id: agent.run_task(task_id, client=client))
    task = agent.start_task(session, ev.id, goal, **limits)
    session.expire_all()
    return session.get(AITask, task.id)


# --------------------------------------------------------------------------- client


def test_client_tool_calls_and_reasoning(settings: Settings) -> None:
    client, sent = scripted(
        settings,
        [_reply("<think>let me look</think>", [_call("list_runs", {}), _call("x", {}, "c2")])],
    )
    result = client.chat([{"role": "user", "content": "hi"}], tools=[{"type": "function"}])
    assert sent[0]["tools"] == [{"type": "function"}]
    assert [c.name for c in result.tool_calls] == ["list_runs", "x"]
    assert result.content == "" and result.reasoning == "let me look"
    assert split_reasoning("<think>a</think>\nAnswer") == ("Answer", "a")


# --------------------------------------------------------------------------- tools


def test_tools_are_scoped_and_report_errors(session: Session, ev: Evidence, pslist: Run) -> None:
    out = tools.run_tool(session, ev.id, "list_runs", {})
    assert f"R{pslist.id} {PSLIST}" in out.text and "columns: PID, ImageFileName" in out.text
    out = tools.run_tool(session, ev.id, "search_rows", {"run_id": pslist.id, "query": "xyz"})
    assert "1 matching row(s)" in out.text and out.row_keys == [f"R{pslist.id}:1"]
    out = tools.run_tool(
        session, ev.id, "search_rows", {"run_id": pslist.id, "filters": {"PID": ">=200"}}
    )
    assert out.row_keys == [f"R{pslist.id}:2"]
    out = tools.run_tool(session, ev.id, "get_rows", {"keys": [f"R{pslist.id}:0", "R999:1"]})
    assert out.text.startswith("ERROR:") and "does not exist for this image" in out.text
    out = tools.run_tool(
        session, ev.id, "get_rows", {"keys": [f"R{pslist.id}:0", f"R{pslist.id}:9"]}
    )
    assert "System" in out.text and f"Not found: R{pslist.id}:9" in out.text
    other = Evidence(rel_path="other.raw", size_bytes=1, mtime=0)
    session.add(other)
    session.commit()
    out = tools.run_tool(session, other.id, "search_rows", {"run_id": pslist.id})
    assert "does not exist for this image" in out.text  # another image's run is invisible
    assert "unknown tool" in tools.run_tool(session, ev.id, "rm_rf", {}).text
    bad = tools.run_tool(
        session, ev.id, "search_rows", {"run_id": pslist.id, "filters": {"Nope": "1"}}
    )
    assert "unknown column" in bad.text


def test_tool_output_is_capped(session: Session, ev: Evidence, pslist: Run, monkeypatch) -> None:
    monkeypatch.setattr(tools, "MAX_RESULT_CHARS", 250)
    out = tools.run_tool(session, ev.id, "search_rows", {"run_id": pslist.id})
    assert tools.TRUNCATED in out.text and len(out.text) <= 250
    assert all(f"[{k}]" in out.text for k in out.row_keys)


# --------------------------------------------------------------------------- loop


def test_native_loop_answers_with_citations(
    session: Session, settings: Settings, ev: Evidence, pslist: Run, monkeypatch
) -> None:
    r = pslist.id
    client, sent = scripted(
        settings,
        [
            _reply(None, [_call("search_rows", {"run_id": r, "query": "xyz"})]),
            _reply(
                f"<think>found it</think>xyz.exe runs as PID 104 [R{r}:1].\n\n"
                '```suggestions\n[{"plugin": "windows.cmdline.CmdLine", "args": {"pid": [104]},'
                ' "reason": "how was it started"}]\n```'
            ),
        ],
    )
    task = _start(session, ev, monkeypatch, client)
    assert task.status == AITaskStatus.DONE and task.tool_mode == "native"
    assert task.steps_used == 2 and task.usage == {"total_tokens": 20}
    assert sent[0]["tools"][0]["function"]["name"] == "list_runs"
    assert "Goal: find processes named xyz" in sent[0]["messages"][2]["content"]
    # The tool result goes back as a "tool" message with the call id.
    assert (
        sent[1]["messages"][-1]["role"] == "tool"
        and "xyz.exe" in sent[1]["messages"][-1]["content"]
    )
    (step,) = task.steps
    assert step.tool == "search_rows" and step.row_keys == [f"R{r}:1"]

    answer = session.get(AIMessage, task.answer_message_id)
    assert answer.content == f"xyz.exe runs as PID 104 [R{r}:1]."  # no <think>, no block
    assert answer.citations[0]["valid"] and answer.citations[0]["support"] == "supported"
    assert answer.suggestions[0]["valid"]
    assert answer.context_refs["kind"] == "agent" and answer.context_refs["task_id"] == task.id
    assert session.get(AIMessage, task.user_message_id).content == "Goal: find processes named xyz"
    actions = session.scalars(select(AuditEvent.action)).all()
    for action in ("ai.agent.start", "ai.agent.tool", "ai.agent.answer", "ai.agent.finish"):
        assert action in actions


def test_text_protocol(session, settings, ev, pslist, monkeypatch) -> None:
    monkeypatch.setenv("FT_AI_TOOL_MODE", "text")
    from app.config import get_settings

    get_settings.cache_clear()
    client, sent = scripted(
        settings,
        [
            _reply('```action\n{"tool": "list_runs", "args": {}}\n```'),
            _reply("```action\nnot json\n```"),
            _reply(f"Done: nothing named xyz besides [R{pslist.id}:1]."),
        ],
    )
    task = _start(session, ev, monkeypatch, client)
    assert task.status == AITaskStatus.DONE and task.tool_mode == "text"
    assert "tools" not in sent[0] and "```action" in sent[0]["messages"][0]["content"]
    assert sent[1]["messages"][-1]["role"] == "user"
    assert sent[1]["messages"][-1]["content"].startswith("Result of list_runs:")
    assert [s.kind for s in task.steps] == ["tool", "error"]  # the bad block is reported back
    assert "not valid JSON" in sent[2]["messages"][-1]["content"]


def test_auto_falls_back_to_text(session, settings, ev, pslist, monkeypatch) -> None:
    client, sent = scripted(
        settings,
        [
            httpx.Response(
                400, text='{"error": "auto tool choice requires --enable-auto-tool-choice"}'
            ),
            _reply('```action\n{"tool": "list_runs", "args": {}}\n```'),
            _reply("Answer."),
        ],
    )
    task = _start(session, ev, monkeypatch, client)
    assert task.status == AITaskStatus.DONE and task.tool_mode == "text"
    assert "tools" in sent[0] and "tools" not in sent[1]
    assert "rejected tools (HTTP 400)" in task.steps[0].summary
    assert agent._mode_cache  # later tasks start in text mode directly

    # A model that ignores native tools and writes an action block also switches.
    agent._mode_cache.clear()
    client2, _ = scripted(
        settings,
        [_reply('```action\n{"tool": "list_runs", "args": {}}\n```'), _reply("Answer 2.")],
    )
    task2 = _start(session, ev, monkeypatch, client2)
    assert task2.tool_mode == "text" and task2.steps[1].tool == "list_runs"


def test_step_limit_forces_answer(session, settings, ev, pslist, monkeypatch) -> None:
    client, sent = scripted(
        settings,
        [
            _reply(None, [_call("list_runs", {})]),
            _reply(None, [_call("list_runs", {})]),
            _reply("Partial answer."),
        ],
    )
    task = _start(session, ev, monkeypatch, client, max_steps=2)
    assert task.status == AITaskStatus.DONE and task.steps_used == 2
    assert "Step limit reached" in task.steps[-1].summary
    assert (
        "tools" not in sent[-1]
        and "limit of this task is reached" in sent[-1]["messages"][-1]["content"]
    )
    assert session.get(AIMessage, task.answer_message_id).content == "Partial answer."


def test_provider_error_fails_task(session, settings, ev, monkeypatch) -> None:
    monkeypatch.setenv("FT_AI_TOOL_MODE", "native")
    from app.config import get_settings

    get_settings.cache_clear()
    client, _ = scripted(settings, [httpx.Response(500, text="boom")])
    task = _start(session, ev, monkeypatch, client)
    assert task.status == AITaskStatus.FAILED and "HTTP 500" in task.error
    assert task.answer_message_id is None


def test_cancel_and_recover(session, settings, ev, pslist, monkeypatch) -> None:
    def cancel_during_call(body: dict) -> httpx.Response:
        from app.db import SessionLocal

        with SessionLocal() as s:
            agent.cancel_task(s, s.scalars(select(AITask)).one().id)
        return _reply(None, [_call("list_runs", {})])

    client, _ = scripted(settings, [cancel_during_call])
    task = _start(session, ev, monkeypatch, client)
    assert task.status == AITaskStatus.CANCELLED and "Cancelled" in task.steps[-1].summary

    monkeypatch.setattr(agent, "_launch", lambda task_id: None)  # stays queued
    queued = agent.start_task(session, ev.id, "goal 2")
    assert agent.recover_tasks(session) == 1
    session.refresh(queued)
    assert queued.status == AITaskStatus.INTERRUPTED and "app stopped" in queued.error
    assert agent.cancel_task(session, queued.id).status == AITaskStatus.INTERRUPTED  # no-op


def test_start_validation_and_limits(session: Session, ev: Evidence, monkeypatch) -> None:
    monkeypatch.setattr(agent, "_launch", lambda task_id: None)
    with pytest.raises(agent.AgentError, match="enter a goal"):
        agent.start_task(session, ev.id, "  ")
    with pytest.raises(agent.AgentError, match="not found"):
        agent.start_task(session, 999, "x")
    task = agent.start_task(session, ev.id, "x", max_steps=500, max_seconds=1)
    assert task.limits == {"max_steps": 50, "max_seconds": 30, "max_runs": 5}
    default = agent.start_task(session, ev.id, "x", max_steps="", max_seconds=None)
    assert default.limits == {"max_steps": 12, "max_seconds": 600, "max_runs": 5}
    v = agent.view(default)
    assert v.active and v.left_s is None and v.elapsed_s == 0


# --------------------------------------------------------------------------- UI + API


def test_goal_from_chat_panel(
    client: TestClient, session, settings, ev, pslist, monkeypatch
) -> None:
    page = client.get(f"/evidence/{ev.id}").text
    assert 'name="mode" value="goal"' in page and 'name="max_steps"' in page

    r = pslist.id
    ai, _ = scripted(
        settings,
        [
            _reply(None, [_call("search_rows", {"run_id": r, "query": "xyz"})]),
            _reply(f"Found [R{r}:1]."),
        ],
    )
    monkeypatch.setattr(agent, "_launch", lambda task_id: agent.run_task(task_id, client=ai))
    resp = client.post(
        f"/ui/evidence/{ev.id}/ai/ask",
        data={"question": "find xyz", "mode": "goal", "max_steps": "5", "max_minutes": "2"},
        headers=HX,
    )
    task = session.scalars(select(AITask)).one()
    assert task.limits == {"max_steps": 5, "max_seconds": 120, "max_runs": 5}
    html = resp.text
    assert f'id="ai-task-{task.id}"' in html and "Goal: find xyz" in html
    assert "done" in html and "Found [" in html and f'href="/runs/{r}?row=1' in html
    assert f"R{r}: 1 match(es) for xyz" in html
    # The answer is shown inside the task card, not a second time in the history.
    assert html.count(f'id="ai-msg-{task.answer_message_id}"') == 1

    card = client.get(f"/ui/ai/tasks/{task.id}", headers=HX).text
    assert "every 2s" not in card  # finished: no polling


def test_running_card_polls_and_cancel(client: TestClient, session, ev, monkeypatch) -> None:
    monkeypatch.setattr(agent, "_launch", lambda task_id: None)
    task = agent.start_task(session, ev.id, "slow goal")
    task.status = AITaskStatus.RUNNING
    task.current_action = "Searching R1 for 'xyz'"
    from datetime import UTC, datetime

    task.started_at = datetime.now(UTC)
    session.commit()
    card = client.get(f"/ui/ai/tasks/{task.id}", headers=HX).text
    assert "every 2s" in card and "Searching R1 for &#39;xyz&#39;" in card and "Cancel" in card
    assert "Step 0 of max 12" in card
    resp = client.post(f"/ui/ai/tasks/{task.id}/cancel", headers=HX)
    assert "Cancelling" in resp.text
    session.refresh(task)
    assert task.cancel_requested


def test_api(client: TestClient, session, settings, ev, monkeypatch) -> None:
    monkeypatch.setattr(agent, "_launch", lambda task_id: None)
    data = client.post(
        "/api/ai/tasks", json={"evidence_id": ev.id, "goal": "g", "max_steps": 3}
    ).json()
    assert data["status"] == "queued" and data["limits"]["max_steps"] == 3
    assert client.get(f"/api/ai/tasks/{data['id']}").json()["goal"] == "g"
    assert [t["id"] for t in client.get(f"/api/ai/tasks?evidence_id={ev.id}").json()] == [
        data["id"]
    ]
    assert client.post(f"/api/ai/tasks/{data['id']}/cancel").json()["status"] == "cancelled"
    assert client.post("/api/ai/tasks", json={"evidence_id": ev.id, "goal": ""}).status_code == 422
    assert client.get("/api/ai/tasks/999").status_code == 404


def test_export_pairs_agent_answer_with_goal(session, settings, ev, pslist, monkeypatch) -> None:
    from app.ai import service
    from app.services import export

    client, _ = scripted(settings, [_reply(None, [_call("list_runs", {})]), _reply("All done.")])
    monkeypatch.setattr(agent, "_launch", lambda task_id: None)
    task = agent.start_task(session, ev.id, "find xyz")
    # Another question is answered while the task works: ids no longer line up.
    service.ask(session, ev.id, "other question?", client=scripted(settings, [_reply("Other.")])[0])
    agent.run_task(task.id, client=client)
    text = "\n".join(export._ai_section(session, ev))
    block = text.split("All done.")[0].rsplit("#### AI answer", 1)[1]
    assert "Goal: find xyz" in block and "other question?" not in block


def test_start_again_button(client: TestClient, session, ev, monkeypatch) -> None:
    monkeypatch.setattr(agent, "_launch", lambda task_id: None)
    task = agent.start_task(session, ev.id, "retry me", max_steps=4, max_seconds=90)
    agent.recover_tasks(session)
    card = client.get(f"/ui/ai/tasks/{task.id}", headers=HX).text
    assert "Start again" in card and 'name="question" value="retry me"' in card
    client.post(
        f"/ui/evidence/{ev.id}/ai/ask",
        data={"mode": "goal", "question": "retry me", "max_steps": "4", "max_minutes": "1.5"},
        headers=HX,
    )
    again = session.scalars(select(AITask).order_by(AITask.id.desc())).first()
    assert again.id != task.id and again.limits == {
        "max_steps": 4,
        "max_seconds": 90,
        "max_runs": 5,
    }
