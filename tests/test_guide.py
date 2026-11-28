"""Investigation guide (app/tools/volatility/guide.py) and recommendations for an image."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditEvent, Evidence, ResultRow, Run, RunOrigin, RunStatus
from app.services import evidence as evidence_service
from app.services import recommendations as recs
from app.tools import guide as guide_tools
from app.tools import registry
from app.tools.base import GuideStep as Step
from app.tools.volatility import guide as guide_module

HX = {"HX-Request": "true"}

PSLIST = "windows.pslist.PsList"
PSTREE = "windows.pstree.PsTree"
CMDLINE = "windows.cmdline.CmdLine"
NETSCAN = "windows.netscan.NetScan"
INFO = "windows.info.Info"


def runner():
    return registry.get_runner("volatility3")


# --------------------------------------------------------------------------- guide checks


def test_shipped_guide_is_valid() -> None:
    """Fails CI when someone adds an invalid step to app/tools/volatility/guide.py."""
    _, problems = guide_tools.check_guide(runner())
    assert [str(p) for p in problems] == []


@pytest.mark.parametrize(
    ("baseline", "next_steps", "fragment"),
    [
        ([Step("windows.nope.Nope", "x")], {}, "unknown plugin"),
        ([Step(PSLIST, "")], {}, "reason is required"),
        ([Step(PSLIST, "x" * 300)], {}, "reason is too long"),
        ([Step(PSLIST, "x", args={"nope": 1})], {}, "args:"),
        ([Step(PSLIST, "x", when="has_rows")], {}, "only applies to NEXT"),
        ([Step(PSLIST, "x", priority=3)], {}, "baseline keeps its order"),
        ([Step(PSLIST, "x"), Step(PSLIST, "y")], {}, "listed twice"),
        ([], {PSLIST: [Step(PSTREE, "x", when="sometimes")]}, "unknown 'when'"),
        ([], {PSLIST: [Step(PSTREE, "x", when="tag:")]}, "unknown 'when'"),
        ([], {"windows.nope.Nope": [Step(PSTREE, "x")]}, "never fires"),
        (["not a step"], {}, "not a Step"),
    ],
)
def test_guide_problems_detected(
    monkeypatch: pytest.MonkeyPatch, baseline: list, next_steps: dict, fragment: str
) -> None:
    monkeypatch.setattr(guide_module, "BASELINE", baseline)
    monkeypatch.setattr(guide_module, "NEXT", next_steps)
    guide, problems = guide_tools.check_guide(runner())
    assert fragment in " | ".join(str(p) for p in problems)
    # Invalid steps are skipped, never recommended.
    assert all(s.plugin != "windows.nope.Nope" for s in guide.baseline)


def test_guide_normalises_args(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(guide_module, "BASELINE", [Step(PSLIST, "x", args={"pid": ["4"]})])
    guide, problems = guide_tools.check_guide(runner())
    assert problems == [] and guide.baseline[0].args == {"pid": [4]}


def test_markdown_and_cli(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert guide_tools.main() == 0
    out = capsys.readouterr().out
    assert "## Baseline (in order)" in out and f"`{PSTREE}`" in out
    assert "has rows tagged 'suspicious-parent'" in out and "## Problems (0)" in out
    monkeypatch.setattr(guide_module, "BASELINE", [Step("windows.nope.Nope", "x")])
    assert guide_tools.main() == 1
    assert "unknown plugin" in capsys.readouterr().out


# --------------------------------------------------------------------------- recommendations


@pytest.fixture
def ev(session: Session) -> Evidence:
    (e,) = evidence_service.scan_evidence(session)
    return e


@pytest.fixture
def small_guide(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        guide_module, "BASELINE", [Step(PSLIST, "processes"), Step(NETSCAN, "network")]
    )
    monkeypatch.setattr(
        guide_module,
        "NEXT",
        {
            INFO: [Step(PSLIST, "identified")],
            PSLIST: [
                Step(PSTREE, "tree", when="has_rows", priority=1),
                Step(CMDLINE, "flagged", when="has_flags", priority=5),
                Step(CMDLINE, "pid 4", args={"pid": [4]}),
            ],
            NETSCAN: [Step(PSTREE, "owners")],
            PSTREE: [Step("linux.pslist.PsList", "other OS")],  # not in catalog -> problem
        },
    )


def _run(session: Session, ev: Evidence, plugin: str, status=RunStatus.SUCCEEDED, **kw) -> Run:
    run = Run(evidence_id=ev.id, plugin=plugin, args=kw.pop("args", {}), status=status, **kw)
    session.add(run)
    session.commit()
    return run


def _keys(r: recs.Recommendations) -> list[tuple[str, dict]]:
    return [(i.plugin, i.args) for i in r.items]


def test_baseline_first_in_order(session: Session, ev: Evidence, small_guide: None) -> None:
    r = recs.recommend(session, ev.id)
    assert _keys(r) == [(PSLIST, {}), (NETSCAN, {})]
    assert [i.baseline_pos for i in r.items] == [1, 2]
    assert (r.baseline_total, r.baseline_done, r.identified) == (2, 0, False)
    assert r.guide_problems == 1  # the linux step


def test_done_failed_and_identified(session: Session, ev: Evidence, small_guide: None) -> None:
    _run(session, ev, INFO)  # auto-enumerate plugin succeeded -> identified
    _run(session, ev, NETSCAN, status=RunStatus.QUEUED)  # queued = done
    failed = _run(session, ev, PSLIST, status=RunStatus.FAILED)
    r = recs.recommend(session, ev.id)
    assert r.identified and r.baseline_done == 1
    assert _keys(r) == [(PSLIST, {})]
    item = r.items[0]
    assert item.last_failed_run_id == failed.id
    assert item.reasons == ["processes", "identified"]  # baseline + NEXT[info] merged
    assert item.sources[0]["plugin"] == INFO


def test_next_conditions_and_ranking(session: Session, ev: Evidence, small_guide: None) -> None:
    empty = _run(session, ev, PSLIST, row_count=0)
    r = recs.recommend(session, ev.id)
    # No rows, no flags: only the unconditional step (and the baseline netscan).
    assert _keys(r) == [(NETSCAN, {}), (CMDLINE, {"pid": [4]})]

    pslist = _run(session, ev, PSLIST, args={"pid": [1]}, row_count=2)
    session.add_all(
        [
            ResultRow(run_id=pslist.id, row_idx=0, data={"PID": 1}),
            ResultRow(
                run_id=pslist.id,
                row_idx=1,
                data={"PID": 2},
                annotations=[{"hook": "h", "tag": "odd", "severity": "high", "note": ""}],
            ),
        ]
    )
    _run(session, ev, NETSCAN)
    session.commit()
    r = recs.recommend(session, ev.id)
    # flagged (priority 5) > tree (priority 1, suggested by pslist AND netscan) > pid 4 (0).
    assert _keys(r) == [(CMDLINE, {}), (PSTREE, {}), (CMDLINE, {"pid": [4]})]
    tree = r.items[1]
    assert {s["plugin"] for s in tree.sources} == {PSLIST, NETSCAN}
    assert tree.reasons == ["tree", "owners"]
    assert empty.id not in {s["run_id"] for s in tree.sources}


def test_tag_condition(
    session: Session, ev: Evidence, small_guide: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(guide_module, "NEXT", {PSLIST: [Step(PSTREE, "t", when="tag:odd")]})
    run = _run(session, ev, PSLIST, row_count=1)
    session.add(ResultRow(run_id=run.id, row_idx=0, data={}, annotations=[{"tag": "other"}]))
    session.commit()
    assert (PSTREE, {}) not in _keys(recs.recommend(session, ev.id))
    session.add(ResultRow(run_id=run.id, row_idx=1, data={}, annotations=[{"tag": "odd"}]))
    session.commit()
    assert (PSTREE, {}) in _keys(recs.recommend(session, ev.id))


def test_other_os_hidden(session: Session, ev: Evidence, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.tools.base import InvestigationGuide

    fake = InvestigationGuide(baseline=(Step("linux.pslist.PsList", "x"), Step(PSLIST, "y")))
    monkeypatch.setattr(guide_tools, "check_guide", lambda _r: (fake, []))
    monkeypatch.setattr(recs, "check_guide", lambda _r: (fake, []))
    assert len(recs.recommend(session, ev.id).items) == 2  # OS unknown: show both
    ev.os_info = {"os": "windows"}
    session.commit()
    r = recs.recommend(session, ev.id)
    assert _keys(r) == [(PSLIST, {})] and r.baseline_total == 1 and r.identified


def test_dismiss_restore_and_audit(session: Session, ev: Evidence, small_guide: None) -> None:
    assert recs.dismiss(session, ev.id, NETSCAN, {})
    assert not recs.dismiss(session, ev.id, NETSCAN, {})  # already dismissed
    r = recs.recommend(session, ev.id)
    assert _keys(r) == [(PSLIST, {})] and [d.plugin for d in r.dismissed] == [NETSCAN]
    assert recs.restore(session, ev.id, NETSCAN, {})
    assert not recs.restore(session, ev.id, NETSCAN, {})
    assert len(recs.recommend(session, ev.id).items) == 2
    actions = session.scalars(select(AuditEvent.action)).all()
    assert "recommendation.dismiss" in actions and "recommendation.restore" in actions


def test_run_baseline_skips_dismissed(session: Session, ev: Evidence, small_guide: None) -> None:
    recs.dismiss(session, ev.id, NETSCAN, {})
    created = recs.run_baseline(session, ev.id)
    assert [(r.plugin, r.origin) for r in created] == [(PSLIST, RunOrigin.RECOMMENDED)]
    assert recs.run_baseline(session, ev.id) == []  # nothing left
    assert "evidence.run_baseline" in session.scalars(select(AuditEvent.action)).all()


# --------------------------------------------------------------------------- web + API


def test_panel_run_edit_dismiss(
    client: TestClient, session: Session, ev: Evidence, small_guide: None
) -> None:
    page = client.get(f"/evidence/{ev.id}").text
    assert 'id="recommendations"' in page and "Recommended next" in page
    assert "Identify the image first" in page

    html = client.get(f"/ui/evidence/{ev.id}/recommendations").text
    assert "processes" in html and "Baseline 1/2" in html
    assert f'href="/evidence/{ev.id}?plugin={PSLIST}&amp;args=%7B%7D#query"' in html

    resp = client.post(
        f"/ui/evidence/{ev.id}/recommendations/run",
        data={"plugin": PSLIST, "args_json": "{}"},
        headers=HX,
    )
    assert resp.status_code == 200 and resp.headers.get("HX-Trigger") == "runs-changed"
    run = session.scalars(select(Run)).one()
    assert run.origin == RunOrigin.RECOMMENDED

    resp = client.post(
        f"/ui/evidence/{ev.id}/recommendations/dismiss",
        data={"plugin": NETSCAN, "args_json": "{}"},
        headers=HX,
    )
    assert "Dismissed (1)" in resp.text
    resp = client.post(
        f"/ui/evidence/{ev.id}/recommendations/restore",
        data={"plugin": NETSCAN, "args_json": "{}"},
        headers=HX,
    )
    assert "Dismissed (" not in resp.text

    bad = client.post(
        f"/ui/evidence/{ev.id}/recommendations/run",
        data={"plugin": "evil.Plugin", "args_json": "{}"},
        headers=HX,
    )
    assert bad.status_code == 200 and "plugin not allowed" in bad.text


def test_edit_prefills_form(client: TestClient, ev: Evidence) -> None:
    html = client.get(f'/evidence/{ev.id}?plugin={PSLIST}&args={{"pid":[4,8]}}').text
    assert 'name="arg_pid" value="4, 8"' in html


def test_run_baseline_button_and_show_all(
    client: TestClient, session: Session, ev: Evidence, small_guide: None
) -> None:
    resp = client.post(f"/ui/evidence/{ev.id}/recommendations/baseline", headers=HX)
    assert resp.status_code == 200 and "Queued 2 baseline step(s)" in resp.text
    assert len(session.scalars(select(Run)).all()) == 2
    # 2 baseline queued; the guide's NEXT steps need succeeded runs, so nothing else is left.
    html = client.get(f"/ui/evidence/{ev.id}/recommendations?all=1").text
    assert "Nothing to recommend right now" in html and "Show all" not in html


def test_guide_page_and_api(client: TestClient, ev: Evidence, small_guide: None) -> None:
    html = client.get("/guide").text
    assert "Investigation guide" in html and "linux.pslist.PsList" in html
    assert "Problems (1)" in html
    data = client.get(f"/api/evidence/{ev.id}/recommendations").json()
    assert [i["plugin"] for i in data["items"]] == [PSLIST, NETSCAN]
    assert data["items"][0]["kind"] == "baseline" and data["guide_problems"] == 1
    assert client.get("/api/evidence/999/recommendations").status_code == 404


def test_show_all_and_system_check(
    client: TestClient, ev: Evidence, small_guide: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(recs, "DEFAULT_SHOWN", 1)
    html = client.get(f"/ui/evidence/{ev.id}/recommendations").text
    assert "Show all (2)" in html and NETSCAN not in html.split("Show all")[0].split("<ul")[1]
    html = client.get(f"/ui/evidence/{ev.id}/recommendations?all=1").text
    assert "Show top 1" in html and NETSCAN in html

    from app.services import health

    check = health.check_guide()
    assert check.status == "warn" and "1 guide step(s) skipped" in check.summary
