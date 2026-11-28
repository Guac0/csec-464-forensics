"""AI "what should I run next?" (feature 2): state context, service, run provenance, UI."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai import service
from app.ai.client import AIClient
from app.ai.context import build_state_context
from app.config import Settings
from app.models import AIMessage, AuditEvent, Evidence, ResultRow, Run, RunOrigin, RunStatus
from app.services import evidence as evidence_service
from app.services import recommendations as recs
from app.services import runs as runs_service
from app.tools import content
from app.tools.base import ArgValidationError, ToolRequest
from app.tools.base import GuideStep as Step
from tests.test_ai_helpers import mock_transport, respond_with

PSLIST = "windows.pslist.PsList"
PSTREE = "windows.pstree.PsTree"
CMDLINE = "windows.cmdline.CmdLine"
NETSCAN = "windows.netscan.NetScan"
HX = {"HX-Request": "true"}

ANSWER = (
    "Processes were listed; p1.exe was flagged [R{run}:1], so look at how it was started.\n\n"
    "```suggestions\n"
    '[{"plugin": "windows.cmdline.CmdLine", "args": {"pid": [101]}, "reason": "flagged"},'
    ' {"plugin": "windows.nope.Nope", "args": {}, "reason": "bad"}]\n```'
)


@pytest.fixture
def ev(session: Session) -> Evidence:
    (e,) = evidence_service.scan_evidence(session)
    e.os_info = {"os": "windows"}
    session.commit()
    return e


@pytest.fixture
def guide(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        content.current(), "baseline", [Step(PSLIST, "procs"), Step(NETSCAN, "net")]
    )
    monkeypatch.setattr(content.current(), "next", {PSLIST: [Step(PSTREE, "tree")]})


@pytest.fixture
def pslist(session: Session, ev: Evidence) -> Run:
    run = Run(evidence_id=ev.id, plugin=PSLIST, args={}, status=RunStatus.SUCCEEDED, row_count=2)
    session.add(run)
    session.flush()
    session.add_all(
        [
            ResultRow(run_id=run.id, row_idx=0, data={"PID": 100, "ImageFileName": "p0.exe"}),
            ResultRow(
                run_id=run.id,
                row_idx=1,
                data={"PID": 101, "ImageFileName": "p1.exe"},
                annotations=[{"hook": "h", "tag": "odd-parent", "severity": "high", "note": ""}],
            ),
        ]
    )
    run.findings = [{"hook": "h", "title": "Odd parent", "severity": "high", "rows": [1]}]
    session.add(Run(evidence_id=ev.id, plugin=NETSCAN, status=RunStatus.FAILED, error="boom\nx"))
    session.commit()
    return run


def _client(settings: Settings, content: str, sent: list[dict[str, Any]] | None = None):
    return AIClient(settings, transport=mock_transport(respond_with(content), sent))


# --------------------------------------------------------------------------- context


def test_state_context(session: Session, ev: Evidence, guide: None, pslist: Run) -> None:
    recs.dismiss(session, ev.id, NETSCAN, {})
    text, refs = build_state_context(session, ev.id)
    assert f"R{pslist.id} {PSLIST} args {{}}: succeeded, 2 rows" in text
    assert "flagged rows by tag: odd-parent (1)" in text and "Odd parent" in text
    assert f"{NETSCAN} args {{}}: failed (boom)" in text  # first error line only
    assert (
        "Static recommendations not yet run" in text and f"{PSTREE} args {{}} (next): tree" in text
    )
    assert "Dismissed by the analyst" in text
    # Only the flagged row is sent, never the whole run.
    assert f"[R{pslist.id}:1]" in text and f"[R{pslist.id}:0]" not in text
    assert refs["kind"] == "recommend" and refs["row_refs_included"] == [f"R{pslist.id}:1"]


def test_state_context_caps_flagged_rows(session: Session, ev: Evidence, pslist: Run) -> None:
    text, refs = build_state_context(session, ev.id, max_flagged_rows=0)
    assert "more exist" in text and refs["row_refs_included"] == []


# --------------------------------------------------------------------------- service


def test_recommend_next(
    session: Session, settings: Settings, ev: Evidence, guide: None, pslist: Run
) -> None:
    sent: list[dict[str, Any]] = []
    client = _client(settings, ANSWER.replace("{run}", str(pslist.id)), sent)
    msg = service.recommend_next(session, ev.id, focus="  credential\n theft ", client=client)
    session.commit()

    user = session.get(AIMessage, msg.id - 1)
    assert user.content == "What should I run next? Focus: credential theft"
    prompt = sent[0]["json"]["messages"][-1]["content"]
    assert "Recommend what the analyst should run next" in prompt and "credential theft" in prompt
    assert "Runs so far" in sent[0]["json"]["messages"][1]["content"]

    assert msg.context_refs["kind"] == "recommend"
    assert [s["valid"] for s in msg.suggestions] == [True, False]
    assert msg.suggestions[0]["normalized_args"] == {"pid": [101]}
    assert "```suggestions" not in msg.content
    assert service.latest_recommendation(session, ev.id).id == msg.id
    actions = session.scalars(select(AuditEvent.action)).all()
    assert "ai.recommend.request" in actions and "ai.recommend.response" in actions

    # A normal question afterwards does not replace the latest recommendation.
    service.ask(session, ev.id, "anything else?", client=_client(settings, "No."))
    assert service.latest_recommendation(session, ev.id).id == msg.id


def test_recommend_next_provider_error(session: Session, settings: Settings, ev: Evidence) -> None:
    import httpx

    client = AIClient(settings, transport=mock_transport(lambda r: httpx.Response(500)))
    msg = service.recommend_next(session, ev.id, client=client)
    assert msg.error and service.latest_recommendation(session, ev.id).id == msg.id


def test_run_links_ai_message(session: Session, settings: Settings, ev: Evidence) -> None:
    msg = service.recommend_next(session, ev.id, client=_client(settings, "Run pslist."))
    req = ToolRequest(plugin=PSLIST, args={})
    run = runs_service.create_run(session, ev.id, req, RunOrigin.AI_SUGGESTED, ai_message_id=msg.id)
    assert run.ai_message_id == msg.id
    with pytest.raises(ArgValidationError, match="only allowed for origin 'ai'"):
        runs_service.create_run(session, ev.id, req, RunOrigin.MANUAL, ai_message_id=msg.id)
    with pytest.raises(ArgValidationError, match="not found for this evidence"):
        runs_service.create_run(
            session,
            ev.id,
            req,
            RunOrigin.AI_SUGGESTED,
            ai_message_id=msg.id - 1,  # user turn
        )


# --------------------------------------------------------------------------- UI


def test_panel_ask_ai_and_run_suggestion(
    client: TestClient,
    session: Session,
    settings: Settings,
    ev: Evidence,
    guide: None,
    pslist: Run,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    page = client.get(f"/evidence/{ev.id}").text
    assert "Ask AI what to run next" in page and 'name="focus"' in page

    real = service.recommend_next
    monkeypatch.setattr(
        service,
        "recommend_next",
        lambda s, e, focus="", client=None: real(
            s, e, focus, client=_client(settings, ANSWER.replace("{run}", str(pslist.id)))
        ),
    )
    resp = client.post(
        f"/ui/evidence/{ev.id}/recommendations/ai", data={"focus": "lsass"}, headers=HX
    )
    assert resp.headers["HX-Trigger"] == "ai-history-changed"
    html = resp.text
    msg = service.latest_recommendation(session, ev.id)
    assert "AI suggestions" in html and f'href="#ai-msg-{msg.id}"' in html
    assert CMDLINE in html and "1 invalid suggestion" in html
    assert f'name="ai_message_id" value="{msg.id}"' in html

    # Chat shows it too, with the analyst's turn.
    chat = client.get(f"/ui/evidence/{ev.id}/ai", headers=HX).text
    assert "What should I run next? Focus: lsass" in chat
    assert f'name="ai_message_id" value="{msg.id}"' in chat

    # Running the suggestion links the run to the answer; the suggestion then shows its run.
    resp = client.post(
        f"/ui/evidence/{ev.id}/runs",
        data={
            "plugin": CMDLINE,
            "origin": "ai",
            "args_json": '{"pid": [101]}',
            "ai_message_id": str(msg.id),
        },
        headers=HX,
    )
    assert resp.status_code == 200
    run = session.scalars(select(Run).where(Run.plugin == CMDLINE)).one()
    assert run.origin == RunOrigin.AI_SUGGESTED and run.ai_message_id == msg.id
    panel = client.get(f"/ui/evidence/{ev.id}/recommendations").text
    assert f'href="/runs/{run.id}"' in panel and "queued" in panel
    run_page = client.get(f"/runs/{run.id}").text
    assert f"/evidence/{ev.id}#ai-msg-{msg.id}" in run_page and "AI answer" in run_page


def test_panel_ai_error_and_api(
    client: TestClient,
    session: Session,
    settings: Settings,
    ev: Evidence,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import httpx

    real = service.recommend_next
    failing = AIClient(settings, transport=mock_transport(lambda r: httpx.Response(500)))
    monkeypatch.setattr(
        service,
        "recommend_next",
        lambda s, e, focus="", client=None: real(s, e, focus, client=failing),
    )
    html = client.post(f"/ui/evidence/{ev.id}/recommendations/ai", headers=HX).text
    assert "AI request failed" in html or "AI error" in html
    data = client.post("/api/ai/recommend", json={"evidence_id": ev.id, "focus": "x"}).json()
    assert data["context_refs"]["kind"] == "recommend" and data["error"]
    assert client.post("/api/ai/recommend", json={"evidence_id": 999}).status_code == 404
