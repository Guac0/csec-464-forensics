"""Indicator watchlists: normalising, matching, automatic + on-demand checks, UI and export."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.jobs import worker as worker_mod
from app.jobs.worker import Worker
from app.models import AuditEvent, Evidence, Indicator, IndicatorHit, IndicatorType, Run, RunStatus
from app.services import cases, export, indicators, results, run_deletion
from app.services import evidence as evidence_service
from app.services import runs as runs_service
from app.services.indicators import Matcher, guess_type, normalize, validate
from app.tools.base import ParsedRow, ToolRequest
from tests.test_backend_fakes import install_fake_runner, make_fake_execute

T = IndicatorType


@pytest.fixture
def images(session: Session, settings: Settings) -> tuple[Evidence, Evidence]:
    (settings.evidence_dir / "host2.raw").write_bytes(b"\0" * 64)
    evs = {e.rel_path: e for e in evidence_service.scan_evidence(session)}
    return evs["sample.raw"], evs["host2.raw"]


@pytest.fixture
def case(session: Session, images) -> int:
    a, b = images
    c = cases.create_case(session, "APT X")
    cases.add_evidence(session, c.id, a.id, "host-1")
    cases.add_evidence(session, c.id, b.id, "host-2")
    return c.id


def _run(session: Session, ev: Evidence, rows: list[dict]) -> Run:
    run = Run(evidence_id=ev.id, plugin="windows.pslist.PsList", status=RunStatus.SUCCEEDED)
    session.add(run)
    session.flush()
    run.row_count = results.store_rows(
        session, run.id, (ParsedRow(r) for r in rows), search_index=False
    )
    session.commit()
    return run


ROWS = [
    {"PID": 4, "ImageFileName": "System", "Path": None},
    {"PID": 666, "ImageFileName": "UPDATER.EXE", "Path": "c:/users/public/updater.exe"},
    {"PID": 700, "ImageFileName": "svchost.exe", "Remote": "203.0.113.045"},
]


# ------------------------------------------------------------------------------ pure


def test_normalize_validate_guess() -> None:
    assert normalize(T.PATH, "C:/Users//Public/") == "c:\\users\\public"
    assert normalize(T.IP, "2001:DB8::0:1") == "2001:db8::1"
    assert normalize(T.IP, "010.000.000.001") == "10.0.0.1"
    assert normalize(T.DOMAIN, "Evil.Example.") == "evil.example"
    assert (
        validate(T.HASH, "D41D8CD98F00B204E9800998ECF8427E") == "d41d8cd98f00b204e9800998ecf8427e"
    )
    for kind, bad in [(T.HASH, "xyz"), (T.HASH, "abc"), (T.IP, "999.1.1.1"), (T.TEXT, "  ")]:
        with pytest.raises(ValueError):
            validate(kind, bad)
    assert guess_type("10.0.0.5") == T.IP
    assert guess_type("d41d8cd98f00b204e9800998ecf8427e") == T.HASH
    assert guess_type("HKEY_LOCAL_MACHINE\\Software\\Run") == T.REGISTRY
    assert guess_type("C:\\Windows\\evil.dll") == T.PATH
    assert guess_type("updater.exe") == T.PROCESS
    assert guess_type("evil-c2.example.com") == T.DOMAIN
    assert guess_type("Global\\xyz_lock") == T.PATH  # backslash: treated as a path
    assert guess_type("svc account") == T.TEXT
    assert guess_type("pid.101.0x1000.dmp") == T.TEXT  # file name, not a domain


def _ind(i: int, kind: T, value: str, mode: str = "exact", column: str = "") -> Indicator:
    return Indicator(
        id=i, type=kind, value=value, normalized=validate(kind, value),
        match_mode=mode, column=column,
    )  # fmt: skip


def test_matcher() -> None:
    m = Matcher.for_indicators(
        [
            _ind(1, T.PROCESS, "updater.exe"),
            _ind(2, T.PATH, "C:\\Users\\Public\\updater.exe"),
            _ind(3, T.IP, "203.0.113.45"),
            _ind(4, T.TEXT, "svchost", "contains"),
            _ind(5, T.TEXT, "system", column="Path"),  # wrong column: no hit
            _ind(6, T.TEXT, "public"),  # exact: "c:/users/public/updater.exe" is not "public"
        ]
    )
    hits = [m.match_row(r) for r in ROWS]
    assert hits[0] == []
    assert sorted(hits[1]) == [
        (1, "ImageFileName", "UPDATER.EXE"),
        (1, "Path", "c:/users/public/updater.exe"),  # process name = file name of a path
        (2, "Path", "c:/users/public/updater.exe"),
    ]
    assert sorted(hits[2]) == [(3, "Remote", "203.0.113.045"), (4, "ImageFileName", "svchost.exe")]
    assert m.match_row({"x": {"nested": "updater.exe"}, "y": True, "z": ["updater.exe"]}) == []
    assert not Matcher.for_indicators([])


# ------------------------------------------------------------------------------ service


def test_watchlist_crud(session: Session, case: int) -> None:
    ind = indicators.add_indicator(session, case, "ip", " 203.0.113.45 ", comment="C2")
    assert ind.normalized == "203.0.113.45" and ind.checked_at is None
    with pytest.raises(ValueError, match="already on the case"):
        indicators.add_indicator(session, case, "ip", "203.0.113.45")
    indicators.add_indicator(session, case, "ip", "203.0.113.45", mode="contains")  # different
    with pytest.raises(ValueError):
        indicators.add_indicator(session, case, "nonsense", "x")
    with pytest.raises(LookupError):
        indicators.add_indicator(session, 999, "ip", "10.0.0.1")
    assert indicators.remove_indicator(session, ind.id) == case
    actions = [
        e.action
        for e in session.scalars(select(AuditEvent).where(AuditEvent.action.like("indicator.%")))
    ]
    assert actions == ["indicator.add", "indicator.add", "indicator.remove"]


def test_on_demand_check_and_lifecycle(session: Session, case: int, images) -> None:
    a, b = images
    run_a = _run(session, a, ROWS)
    run_b = _run(session, b, [{"Remote": "203.0.113.45"}, {"Remote": "10.0.0.1"}])
    ip = indicators.add_indicator(session, case, "ip", "203.0.113.45")
    indicators.add_indicator(session, case, "process", "updater.exe")
    # Existing runs are not checked until asked.
    assert session.scalar(select(IndicatorHit.id)) is None
    assert indicators.unchecked_count(session, case) == 2

    assert indicators.check_case(session, case) == 4
    assert indicators.unchecked_count(session, case) == 0
    counts = indicators.hit_counts(session, case)
    assert counts[ip.id] == {a.id: 1, b.id: 1}
    assert [h.hit.row_idx for h in indicators.hits(session, case, evidence_id=b.id)] == [0]
    assert indicators.row_hits(session, case, run_a.id) == {
        1: ["updater.exe", "updater.exe"],
        2: ["203.0.113.45"],
    }

    # Adding an image means existing runs are unchecked again.
    third = cases.create_case(session, "tmp")  # a case with one image, to add the other later
    cases.add_evidence(session, third.id, a.id)
    indicators.add_indicator(session, third.id, "text", "x")
    indicators.check_case(session, third.id)
    assert indicators.unchecked_count(session, third.id) == 0
    cases.add_evidence(session, third.id, b.id)
    assert indicators.unchecked_count(session, third.id) == 1

    # Deleting a run or removing an image drops its hits.
    run_deletion.delete_run(session, run_b.id, "redo")
    assert indicators.hit_counts(session, case)[ip.id] == {a.id: 1}
    cases.remove_evidence(session, case, a.id)
    assert indicators.hit_counts(session, case) == {}
    assert (
        session.scalars(
            select(AuditEvent).where(
                AuditEvent.action == "indicators.check_case", AuditEvent.object_id == case
            )
        )
        .one()
        .details["hits"]
        == 4
    )


def test_background_check(session: Session, case: int, images) -> None:
    a, _ = images
    _run(session, a, ROWS)
    indicators.add_indicator(session, case, "process", "svchost.exe")
    assert indicators.start_case_check(case)
    deadline = time.monotonic() + 10
    while indicators.job_state(case).get("running") and time.monotonic() < deadline:
        time.sleep(0.02)
    state = indicators.job_state(case)
    assert state["hits"] == 1 and state["total"] == 1 and state["done"] == 1


def test_new_runs_are_checked_automatically(
    session: Session, case: int, images, monkeypatch: pytest.MonkeyPatch
) -> None:
    a, _ = images
    install_fake_runner(monkeypatch)
    indicators.add_indicator(session, case, "ip", "203.0.113.45")
    monkeypatch.setattr(worker_mod, "execute", make_fake_execute(ROWS))
    run = runs_service.create_run(session, a.id, ToolRequest("windows.info.Info"))
    run.status = RunStatus.RUNNING
    session.commit()
    Worker()._process(session, run.id, __import__("threading").Event())
    session.expire_all()
    (hit,) = session.scalars(select(IndicatorHit).where(IndicatorHit.run_id == run.id))
    assert (hit.row_idx, hit.column, hit.evidence_id) == (2, "Remote", a.id)
    event = session.scalars(
        select(AuditEvent).where(AuditEvent.action == "indicators.match_run")
    ).one()
    assert event.details["hits"] == 1


def test_indicators_never_reach_ai_context(session: Session, case: int, images) -> None:
    from app.ai.context import build_context

    a, _ = images
    _run(session, a, ROWS)
    indicators.add_indicator(session, case, "text", "only-in-the-watchlist")
    indicators.check_case(session, case)
    text, _ = build_context(session, a.id)
    assert "only-in-the-watchlist" not in text


# ------------------------------------------------------------------------------ export


def test_reports(session: Session, case: int, images) -> None:
    a, b = images
    _run(session, a, ROWS)
    indicators.add_indicator(session, case, "ip", "203.0.113.45", comment="C2")
    indicators.check_case(session, case)
    case_report = export.build_report(session, case_id=case)
    assert "### Indicators" in case_report and "host\\-1: 1, host\\-2: 0" in case_report
    assert "`203.0.113.045`" in case_report  # the cell as found
    image_report = export.build_report(session, a.id)
    leads = image_report.split("## Leads from linked evidence")[1]
    assert "matching the case's indicator watchlist" in leads and "`R1:2`" in leads
    other_report = export.build_report(session, b.id)
    assert "No hits." in other_report.split("## Leads from linked evidence")[1]


# ------------------------------------------------------------------------------ API + UI


def test_api(client: TestClient, session: Session, case: int, images) -> None:
    a, _ = images
    _run(session, a, ROWS)
    r = client.post(
        f"/api/cases/{case}/indicators", json={"type": "process", "value": "UPDATER.exe"}
    )
    assert r.status_code == 201 and r.json()["normalized"] == "updater.exe"
    assert (
        client.post(
            f"/api/cases/{case}/indicators", json={"type": "hash", "value": "zz"}
        ).status_code
        == 422
    )
    assert client.post(f"/api/cases/{case}/indicators/check").status_code == 202
    deadline = time.monotonic() + 10
    while indicators.job_state(case).get("running") and time.monotonic() < deadline:
        time.sleep(0.02)
    data = client.get(f"/api/cases/{case}/indicators").json()
    assert data["indicators"][0]["hits_by_evidence"] == {str(a.id): 2}
    assert data["check"]["hits"] == 2
    hits = client.get(f"/api/cases/{case}/indicators/hits?evidence_id={a.id}").json()
    assert {h["column"] for h in hits} == {"ImageFileName", "Path"} and hits[0]["row"] == "R1:1"
    ind_id = data["indicators"][0]["id"]
    assert client.delete(f"/api/cases/{case}/indicators/{ind_id}").status_code == 204
    assert client.delete(f"/api/cases/{case}/indicators/{ind_id}").status_code == 404


def test_ui(client: TestClient, session: Session, case: int, images) -> None:
    a, b = images
    run = _run(session, a, ROWS)
    # From a row: the dialog lists the row's values with guessed types.
    dialog = client.get(
        f"/ui/indicators/from-row?run_id={run.id}&row_idx=1",
        headers={"HX-Request": "true", "HX-Current-URL": f"http://t/runs/{run.id}?case={case}"},
    ).text
    assert 'data-type="path"' in dialog and 'data-type="process"' in dialog
    assert f'name="case_id" value="{case}"' in dialog and 'value="R1:1"' in dialog
    r = client.post(
        "/ui/indicators",
        data={
            "case_id": case, "type": "process", "value": "UPDATER.EXE", "match_mode": "exact",
            "column": "ImageFileName", "only_column": "1", "source_key": "R1:1",
            "next": f"/runs/{run.id}?case={case}",
        },
        follow_redirects=False,
    )  # fmt: skip
    assert r.headers["location"] == f"/runs/{run.id}?case={case}"
    ind = session.scalars(select(Indicator)).one()
    assert ind.column == "ImageFileName" and ind.source_key == "R1:1"

    page = client.get(f"/cases/{case}").text
    assert "Indicators (1)" in page and "not yet checked against existing runs" in page
    r = client.post(f"/ui/cases/{case}/indicators/check", headers={"HX-Request": "true"})
    assert 'id="indicator-check"' in r.text
    deadline = time.monotonic() + 10
    while indicators.job_state(case).get("running") and time.monotonic() < deadline:
        time.sleep(0.02)
    page = client.get(f"/cases/{case}").text
    assert "host-1: 1" in page and "host-2: 0" in page

    # Image page (in the case) lists the hit; the run page marks the row.
    ev_page = client.get(f"/evidence/{a.id}?case={case}").text
    assert "Indicator hits on this image (1)" in ev_page and f"R{run.id}:1" in ev_page
    assert "Indicator hits" not in client.get(f"/evidence/{a.id}").text
    run_page = client.get(f"/runs/{run.id}?case={case}").text
    assert 'title="matches indicator(s): UPDATER.EXE">IOC' in run_page and "+IOC" in run_page
    assert ">IOC</span>" not in client.get(f"/runs/{run.id}").text  # no case: no marks

    r = client.post("/ui/indicators", data={"case_id": case, "type": "hash", "value": "nope"})
    assert r.status_code == 422 and "Indicator not added" in r.text
    client.post(f"/ui/indicators/{ind.id}/remove")
    assert "Indicators (0)" in client.get(f"/cases/{case}").text
