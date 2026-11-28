"""AI agent run queuing (feature 3b): queue_run, approvals, waiting for runs, limits, cancel,
ETA, badges, saved reasoning."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai import agent
from app.ai.client import AIClient
from app.config import Settings
from app.db import SessionLocal
from app.models import (
    AIRunRequest,
    AITask,
    AITaskStatus,
    AuditEvent,
    Evidence,
    ResultRow,
    Run,
    RunOrigin,
    RunStatus,
)
from app.services import evidence as evidence_service

PSLIST = "windows.pslist.PsList"
CMDLINE = "windows.cmdline.CmdLine"
HX = {"HX-Request": "true"}


@pytest.fixture(autouse=True)
def _fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "POLL_SECONDS", 0.02)
    agent._mode_cache.clear()


@pytest.fixture
def ev(session: Session) -> Evidence:
    (e,) = evidence_service.scan_evidence(session)
    e.os_info = {"os": "windows"}
    session.commit()
    return e


@pytest.fixture
def pslist(session: Session, ev: Evidence) -> Run:
    run = Run(
        evidence_id=ev.id, plugin=PSLIST, args={}, status=RunStatus.SUCCEEDED, row_count=1,
        columns=[{"name": "PID", "type": "int"}, {"name": "ImageFileName", "type": "str"}],
    )  # fmt: skip
    session.add(run)
    session.flush()
    session.add(ResultRow(run_id=run.id, row_idx=0, data={"PID": 104, "ImageFileName": "xyz.exe"}))
    session.commit()
    return run


def _reply(content: str | None = "", tool_calls: list | None = None) -> httpx.Response:
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return httpx.Response(200, json={"model": "qwen3.6", "choices": [{"message": message}]})


def _queue(plugin: str, args: dict, reason: str = "need it", call_id: str = "q1") -> dict:
    payload = {"plugin": plugin, "args": args, "reason": reason}
    return {"id": call_id, "type": "function",
            "function": {"name": "queue_run", "arguments": json.dumps(payload)}}  # fmt: skip


def scripted(settings: Settings, replies: list) -> tuple[AIClient, list[dict]]:
    sent: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        sent.append(body)
        reply = replies.pop(0)
        return reply(body) if callable(reply) else reply

    return AIClient(settings, transport=httpx.MockTransport(handler)), sent


def wait_until(cond: Callable[[], Any], timeout: float = 20.0) -> Any:
    # Generous: under parallel test runs (pytest -n auto) a busy CI machine can be slow.
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        with SessionLocal() as s:
            value = cond(s)
            if value:
                return value
        time.sleep(0.02)
    raise AssertionError("condition not met in time")


def start_bg(session: Session, ev: Evidence, monkeypatch, client: AIClient, **kw: Any):
    """Start a task whose loop runs in a background thread (like production)."""
    threads: list[threading.Thread] = []

    def launch(task_id: int) -> None:
        t = threading.Thread(
            target=agent.run_task, args=(task_id,), kwargs={"client": client}, daemon=True
        )
        t.start()
        threads.append(t)

    monkeypatch.setattr(agent, "_launch", launch)
    task = agent.start_task(session, ev.id, kw.pop("goal", "what did xyz run?"), **kw)
    return task.id, threads


def finish_run(run_id: int, rows: list[dict] | None = None, status=RunStatus.SUCCEEDED) -> None:
    """Simulate the worker finishing a run."""
    with SessionLocal() as s:
        run = s.get(Run, run_id)
        run.status = status
        run.started_at = datetime.now(UTC) - timedelta(seconds=30)
        run.finished_at = datetime.now(UTC)
        rows = rows or []
        run.row_count = len(rows)
        run.columns = [{"name": k, "type": "str"} for k in (rows[0] if rows else {})]
        for i, data in enumerate(rows):
            s.add(ResultRow(run_id=run_id, row_idx=i, data=data))
        if status != RunStatus.SUCCEEDED:
            run.error = "boom\ndetails"
        s.commit()


def pending_request(s: Session) -> AIRunRequest | None:
    return s.scalars(select(AIRunRequest).where(AIRunRequest.status == "pending")).first()


def join(threads: list[threading.Thread]) -> None:
    for t in threads:
        t.join(timeout=30)
        assert not t.is_alive()


# --------------------------------------------------------------------------- approval flow


def test_approve_then_wait_for_run(session, settings, ev, pslist, monkeypatch) -> None:
    client, sent = scripted(
        settings,
        [_reply(None, [_queue(CMDLINE, {"pid": [104]})]), _reply("xyz ran evil.ps1 [R{}:0].")],
    )
    task_id, threads = start_bg(session, ev, monkeypatch, client)
    req = wait_until(pending_request)
    # The request is saved a moment before the task switches to "awaiting approval".
    wait_until(lambda s: s.get(AITask, task_id).status == AITaskStatus.AWAITING_APPROVAL)
    time.sleep(0.15)  # the clock is paused while waiting
    with SessionLocal() as s:
        decided = agent.decide(s, req.id, "approve")
        run_id = decided.run_id
        run = s.get(Run, run_id)
        assert run.origin == RunOrigin.AI_AGENT and run.ai_task_id == task_id
        assert run.args == {"pid": [104]} and decided.decided_by == "local"
    wait_until(lambda s: s.get(AITask, task_id).status == AITaskStatus.WAITING_FOR_RUNS)
    finish_run(run_id, [{"PID": "104", "Args": "powershell evil.ps1"}])
    join(threads)

    session.expire_all()
    task = session.get(AITask, task_id)
    assert task.status == AITaskStatus.DONE and task.paused_seconds >= 0
    result = sent[1]["messages"][-1]
    assert result["role"] == "tool" and result["tool_call_id"] == "q1"
    assert (
        f"R{run_id} {CMDLINE}" in result["content"] and "succeeded with 1 rows" in result["content"]
    )
    assert f"[R{run_id}:0]" in result["content"]
    assert "queue_run" in [t["function"]["name"] for t in sent[0]["tools"]]
    kinds = [s.kind for s in task.steps]
    assert kinds == ["request", "result"]
    actions = session.scalars(select(AuditEvent.action)).all()
    assert "ai.agent.approval" in actions


def test_yes_to_all_and_cancel_cascade(session, settings, ev, pslist, monkeypatch) -> None:
    client, _ = scripted(settings, [_reply(None, [_queue(CMDLINE, {})])])
    task_id, threads = start_bg(session, ev, monkeypatch, client, approve_all=True)
    run = wait_until(lambda s: s.scalars(select(Run).where(Run.ai_task_id == task_id)).first())
    # The run is saved a moment before its request is marked approved.
    wait_until(lambda s: s.scalars(select(AIRunRequest)).one().status == "auto")
    with SessionLocal() as s:
        req = s.scalars(select(AIRunRequest)).one()
        assert req.status == "auto" and req.decided_by == "yes to all"
        assert s.get(AITask, task_id).status in (
            AITaskStatus.WAITING_FOR_RUNS,
            AITaskStatus.RUNNING,
        )
        agent.cancel_task(s, task_id)  # cancels the task AND its queued run
    join(threads)
    session.expire_all()
    assert session.get(Run, run.id).status == RunStatus.CANCELLED
    assert session.get(AITask, task_id).status == AITaskStatus.CANCELLED


def test_deny_with_note_and_edit(session, settings, ev, pslist, monkeypatch) -> None:
    client, sent = scripted(
        settings,
        [
            _reply(
                None,
                [
                    _queue(CMDLINE, {}, call_id="a"),
                    _queue("windows.netscan.NetScan", {}, call_id="b"),
                ],
            ),
            _reply("Done."),
        ],
    )
    task_id, threads = start_bg(session, ev, monkeypatch, client)
    wait_until(lambda s: len(s.scalars(select(AIRunRequest)).all()) == 2)
    wait_until(lambda s: s.get(AITask, task_id).status == AITaskStatus.AWAITING_APPROVAL)
    with SessionLocal() as s:
        cmd, net = s.scalars(select(AIRunRequest).order_by(AIRunRequest.id)).all()
        agent.decide(s, net.id, "deny", note="too slow on this image")
        s.refresh(cmd)
        assert cmd.status == "pending"  # one left: the task keeps waiting
        edited = agent.decide(s, cmd.id, "edit", args={"pid": [104]})
        assert edited.status == "edited" and edited.final_args == {"pid": [104]}
        run_id = edited.run_id
    finish_run(run_id, [{"PID": "104"}])
    join(threads)
    by_id = {
        m.get("tool_call_id"): m["content"] for m in sent[1]["messages"] if m["role"] == "tool"
    }
    assert 'The analyst changed the options to {"pid": [104]}' in by_id["a"]
    assert "denied" in by_id["b"] and "too slow on this image" in by_id["b"]
    with pytest.raises(agent.ApprovalError, match="no longer pending"):
        agent.decide(session, net.id, "approve")


def test_redundant_and_limits(session, settings, ev, pslist, monkeypatch) -> None:
    client, sent = scripted(
        settings,
        [
            _reply(None, [_queue(PSLIST, {}, call_id="a")]),  # already ran -> pointer
            _reply(
                None,
                [
                    _queue(CMDLINE, {}, call_id="b"),
                    _queue("windows.netscan.NetScan", {}, call_id="c"),
                ],
            ),
            _reply("Done."),
        ],
    )
    monkeypatch.setattr(agent, "_launch", lambda task_id: None)
    task = agent.start_task(session, ev.id, "g", max_runs=1, approve_all=True)
    threads: list[threading.Thread] = []
    t = threading.Thread(
        target=agent.run_task, args=(task.id,), kwargs={"client": client}, daemon=True
    )
    t.start()
    threads.append(t)
    run = wait_until(lambda s: s.scalars(select(Run).where(Run.ai_task_id == task.id)).first())
    finish_run(run.id)
    join(threads)
    first = sent[1]["messages"][-1]["content"]
    assert f"already exists as R{pslist.id}" in first and f"run_id={pslist.id}" in first
    tool_msgs = {
        m.get("tool_call_id"): m["content"] for m in sent[2]["messages"] if m["role"] == "tool"
    }
    assert "runs limit of this task (1) is reached" in tool_msgs["c"]
    assert session.scalars(select(AIRunRequest)).all()[0].plugin == CMDLINE  # refused: not stored


def test_read_only_task_has_no_queue_tool(session, settings, ev, monkeypatch) -> None:
    client, sent = scripted(settings, [_reply("Nothing to do.")])
    monkeypatch.setattr(agent, "_launch", lambda task_id: agent.run_task(task_id, client=client))
    agent.start_task(session, ev.id, "g", max_runs=0)
    assert "queue_run" not in [t["function"]["name"] for t in sent[0]["tools"]]


def test_time_limit_while_waiting_for_run(session, settings, ev, monkeypatch) -> None:
    monkeypatch.setattr(agent, "SECONDS_LIMITS", (0, 3600))
    client, sent = scripted(
        settings, [_reply(None, [_queue(CMDLINE, {})]), _reply("Partial: run still going.")]
    )
    task_id, threads = start_bg(session, ev, monkeypatch, client, approve_all=True, max_seconds=1)
    join(threads)
    assert "the time limit was reached before it finished" in sent[1]["messages"][-2]["content"]
    assert "limit of this task is reached" in sent[1]["messages"][-1]["content"]
    session.expire_all()
    assert session.get(AITask, task_id).status == AITaskStatus.DONE
    run = session.scalars(select(Run).where(Run.ai_task_id == task_id)).one()
    assert run.status == RunStatus.QUEUED  # not cancelled: only cancelling the task does that


def test_pending_requests_expire_when_task_ends(session, settings, ev, monkeypatch) -> None:
    client, _ = scripted(settings, [_reply(None, [_queue(CMDLINE, {})])])
    task_id, threads = start_bg(session, ev, monkeypatch, client)
    req = wait_until(pending_request)
    with SessionLocal() as s:
        agent.cancel_task(s, task_id)
    join(threads)
    session.expire_all()
    assert session.get(AIRunRequest, req.id).status == "expired"
    with pytest.raises(agent.ApprovalError):
        agent.decide(session, req.id, "approve")


# --------------------------------------------------------------------------- ETA


def test_run_estimate_scales_by_image_size(session: Session, ev: Evidence) -> None:
    big = Evidence(rel_path="big.raw", size_bytes=ev.size_bytes * 2, mtime=0)
    session.add(big)
    session.flush()
    now = datetime.now(UTC)
    for seconds in (60, 100, 400):
        session.add(Run(evidence_id=big.id, plugin=CMDLINE, status=RunStatus.SUCCEEDED,
                        started_at=now - timedelta(seconds=seconds), finished_at=now))  # fmt: skip
    current = Run(evidence_id=ev.id, plugin=CMDLINE, status=RunStatus.QUEUED)
    session.add(current)
    session.commit()
    assert agent.estimate_run_seconds(session, current) == (50, 3)  # median 100 s, half size
    other = Run(evidence_id=ev.id, plugin="windows.netscan.NetScan", status=RunStatus.QUEUED)
    session.add(other)
    session.commit()
    assert agent.estimate_run_seconds(session, other) == (None, 0)


# --------------------------------------------------------------------------- UI + API


def test_ui_approval_card_and_badges(
    client: TestClient, session, settings, ev, pslist, monkeypatch
) -> None:
    ai, _ = scripted(
        settings,
        [
            _reply(None, [_queue(CMDLINE, {"pid": [104]}, reason="see how xyz started")]),
            _reply("Done."),
        ],
    )
    task_id, threads = start_bg(session, ev, monkeypatch, ai)
    req = wait_until(pending_request)
    card = client.get(f"/ui/ai/tasks/{task_id}", headers=HX).text
    assert "Waiting for your approval" in card and "every 2s" not in card  # no polling: forms
    assert "see how xyz started" in card and "Edit options first" in card
    assert 'name="arg_pid" value="104"' in card and "Approve all remaining" in card

    resp = client.post(
        f"/ui/ai/run-requests/{req.id}/decide",
        data={"action": "edit", "arg_pid": "104, 200"},
        headers=HX,
    )
    assert "options edited and approved by local" in resp.text and "every 2s" in resp.text
    session.expire_all()
    run = session.scalars(select(Run).where(Run.ai_task_id == task_id)).one()
    assert run.args == {"pid": [104, 200]}
    runs_html = client.get(f"/ui/evidence/{ev.id}/runs", headers=HX).text
    assert f"#ai-task-{task_id}" in runs_html and f"AI task {task_id}" in runs_html
    run_page = client.get(f"/runs/{run.id}").text
    assert "queued by AI" in run_page and "options edited and approved by local" in run_page
    finish_run(run.id)
    join(threads)


def test_goal_form_and_api(client: TestClient, session, ev, monkeypatch) -> None:
    page = client.get(f"/evidence/{ev.id}").text
    assert 'name="approve_all"' in page and 'name="max_runs"' in page
    monkeypatch.setattr(agent, "_launch", lambda task_id: None)
    client.post(
        f"/ui/evidence/{ev.id}/ai/ask",
        data={"mode": "goal", "question": "g", "max_runs": "2", "approve_all": "on"},
        headers=HX,
    )
    task = session.scalars(select(AITask)).one()
    assert task.approve_all and task.limits["max_runs"] == 2

    data = client.post(
        "/api/ai/tasks", json={"evidence_id": ev.id, "goal": "g2", "max_runs": 0}
    ).json()
    assert data["limits"]["max_runs"] == 0 and data["approve_all"] is False
    with SessionLocal() as s:
        req = AIRunRequest(task_id=data["id"], plugin=CMDLINE, args={}, status="pending")
        s.add(req)
        s.commit()
        req_id = req.id
    out = client.post(f"/api/ai/run-requests/{req_id}", json={"action": "deny", "note": "no"})
    assert out.json()["status"] == "denied"
    assert (
        client.post(f"/api/ai/run-requests/{req_id}", json={"action": "approve"}).status_code == 409
    )
    assert client.post(f"/api/ai/tasks/{data['id']}/approve-all").json()["approve_all"] is True
    bad = client.post("/api/runs", json={"evidence_id": ev.id, "plugin": PSLIST, "origin": "agent"})
    assert bad.status_code == 422


# --------------------------------------------------------------------------- reasoning


def test_reasoning_saved_and_shown(client: TestClient, session, settings, ev) -> None:
    from app.ai import service
    from app.services import export

    ai, _ = scripted(settings, [_reply("<think>PID 4 is System, so...</think>All normal.")])
    msg = service.ask(session, ev.id, "anything odd?", client=ai)
    assert msg.content == "All normal." and msg.reasoning == "PID 4 is System, so..."
    html = client.get(f"/ui/evidence/{ev.id}/ai", headers=HX).text
    assert "Model reasoning" in html and "PID 4 is System, so..." in html
    text = "\n".join(export._ai_section(session, ev))
    assert "Model reasoning" in text and "PID 4 is System, so..." in text
