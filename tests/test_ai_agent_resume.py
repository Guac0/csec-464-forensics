"""AI agent tasks resume after an app restart (from their last checkpoint)."""

from __future__ import annotations

import threading

import pytest
from sqlalchemy import select

from app.ai import agent
from app.db import SessionLocal
from app.models import AIRunRequest, AITask, AITaskStatus, AuditEvent, Run, RunStatus
from tests.test_ai_agent_runs import (  # noqa: F401 - fixtures
    CMDLINE,
    _fast,
    _queue,
    _reply,
    ev,
    finish_run,
    join,
    pending_request,
    pslist,
    scripted,
    wait_until,
)


class _Crash(BaseException):
    """Simulates the process dying (not caught by the task's error handling)."""


def _crashing_thread(task_id: int, client) -> threading.Thread:
    def target() -> None:
        try:
            agent.run_task(task_id, client=client)
        except _Crash:
            pass

    t = threading.Thread(target=target)
    t.start()
    return t


def _restart(monkeypatch: pytest.MonkeyPatch, session, client) -> list[threading.Thread]:
    """What the app does at startup: resume active tasks (in background threads)."""
    threads: list[threading.Thread] = []

    def launch(task_id: int) -> None:
        t = threading.Thread(target=agent.run_task, args=(task_id,), kwargs={"client": client})
        t.start()
        threads.append(t)

    monkeypatch.setattr(agent, "_launch", launch)
    assert agent.recover_tasks(session, resume=True) == 1
    return threads


def test_resume_while_awaiting_approval(session, settings, ev, pslist, monkeypatch) -> None:  # noqa: F811
    monkeypatch.setattr(agent, "_launch", lambda task_id: None)
    task = agent.start_task(session, ev.id, "what did xyz run?")
    first, _ = scripted(settings, [_reply(None, [_queue(CMDLINE, {"pid": [104]})])])

    real_sleep = agent._Loop._sleep
    monkeypatch.setattr(agent._Loop, "_sleep", lambda self: (_ for _ in ()).throw(_Crash()))
    _crashing_thread(task.id, first).join(timeout=10)
    monkeypatch.setattr(agent._Loop, "_sleep", real_sleep)

    session.expire_all()
    task = session.get(AITask, task.id)
    assert task.status == AITaskStatus.AWAITING_APPROVAL and task.state["turn"]
    req = pending_request(session)
    assert req is not None  # the request survives the "restart"

    second, sent = scripted(settings, [_reply("xyz ran evil.ps1.")])
    threads = _restart(monkeypatch, session, second)
    wait_until(lambda s: s.get(AITask, task.id).status == AITaskStatus.AWAITING_APPROVAL)
    with SessionLocal() as s:
        run_id = agent.decide(s, req.id, "approve").run_id
    finish_run(run_id, [{"PID": "104", "Args": "evil.ps1"}])
    join(threads)

    session.expire_all()
    task = session.get(AITask, task.id)
    assert task.status == AITaskStatus.DONE and task.resumed_count == 1
    # The first call after the restart already carries the tool result: nothing was redone.
    assert len(sent) == 1 and sent[0]["messages"][-1]["role"] == "tool"
    assert f"R{run_id} {CMDLINE}" in sent[0]["messages"][-1]["content"]
    assert any("resumed" in s.summary for s in task.steps)
    assert "ai.agent.resumed" in session.scalars(select(AuditEvent.action)).all()


def test_resume_mid_call_redoes_the_step(session, settings, ev, monkeypatch) -> None:  # noqa: F811
    monkeypatch.setattr(agent, "_launch", lambda task_id: None)
    task = agent.start_task(session, ev.id, "anything odd?")

    def crash(_body):
        raise _Crash

    first, _ = scripted(settings, [crash])
    _crashing_thread(task.id, first).join(timeout=10)
    session.expire_all()
    assert session.get(AITask, task.id).status == AITaskStatus.RUNNING

    second, sent = scripted(settings, [_reply("Nothing odd.")])
    join(_restart(monkeypatch, session, second))
    session.expire_all()
    task = session.get(AITask, task.id)
    assert task.status == AITaskStatus.DONE and task.steps_used == 1  # not double-counted
    assert "Goal: anything odd?" in sent[0]["messages"][2]["content"]


def test_resume_while_waiting_for_runs(session, settings, ev, monkeypatch) -> None:  # noqa: F811
    monkeypatch.setattr(agent, "_launch", lambda task_id: None)
    task = agent.start_task(session, ev.id, "g", approve_all=True)
    first, _ = scripted(settings, [_reply(None, [_queue(CMDLINE, {})])])
    monkeypatch.setattr(agent._Loop, "_sleep", lambda self: (_ for _ in ()).throw(_Crash()))
    _crashing_thread(task.id, first).join(timeout=10)
    monkeypatch.undo()
    monkeypatch.setattr(agent, "POLL_SECONDS", 0.02)

    session.expire_all()
    assert session.get(AITask, task.id).status == AITaskStatus.WAITING_FOR_RUNS
    run = session.scalars(select(Run).where(Run.ai_task_id == task.id)).one()
    # The worker's own recovery marks runs that were running as interrupted.
    finish_run(run.id, status=RunStatus.INTERRUPTED)

    second, sent = scripted(settings, [_reply("The run was interrupted.")])
    join(_restart(monkeypatch, session, second))
    assert f"R{run.id}" in sent[0]["messages"][-1]["content"]
    assert "interrupted" in sent[0]["messages"][-1]["content"]
    session.expire_all()
    assert session.get(AITask, task.id).status == AITaskStatus.DONE
    assert session.scalars(select(AIRunRequest)).one().status == "auto"
