"""Before/after comparison of one plugin's results on two images of a case."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import AuditEvent, Evidence, Run, RunStatus
from app.services import cases, compare, export, results, run_deletion
from app.services import evidence as evidence_service
from app.tools.base import ParsedRow

PSLIST = "windows.pslist.PsList"
BEFORE = [
    {"PID": 4, "ImageFileName": "System", "Threads": 100, "Wow64": False},
    {"PID": 600, "ImageFileName": "svchost.exe", "Threads": 9, "Wow64": False},
    {"PID": 700, "ImageFileName": "svchost.exe", "Threads": 9, "Wow64": False},
    {"PID": 800, "ImageFileName": "explorer.exe", "Threads": 30, "Wow64": False},
    {"PID": 900, "ImageFileName": "notepad.exe", "Threads": 2, "Wow64": False},
]
AFTER = [
    {"PID": 4, "ImageFileName": "System", "Threads": 120, "Wow64": False},  # same (Threads ignored)
    {"PID": 610, "ImageFileName": "svchost.exe", "Threads": 9, "Wow64": False},
    {"PID": 710, "ImageFileName": "svchost.exe", "Threads": 9, "Wow64": False},
    {"PID": 720, "ImageFileName": "svchost.exe", "Threads": 9, "Wow64": False},  # one more
    {"PID": 810, "ImageFileName": "explorer.exe", "Threads": 31, "Wow64": True},  # changed
    {"PID": 666, "ImageFileName": "=evil.exe", "Threads": 1, "Wow64": False},  # new
]


@pytest.fixture
def setup(session: Session, settings: Settings) -> dict:
    for name in ("before.raw", "after.raw", "unrelated.raw"):
        (settings.evidence_dir / name).write_bytes(b"\0" * 64)
    evs = {e.rel_path: e for e in evidence_service.scan_evidence(session)}
    case = cases.create_case(session, "Laptop")
    cases.add_evidence(session, case.id, evs["before.raw"].id, "before")
    cases.add_evidence(session, case.id, evs["after.raw"].id, "after")
    return {
        "case": case.id,
        "before": evs["before.raw"],
        "after": evs["after.raw"],
        "unrelated": evs["unrelated.raw"],
        "run_a": _run(session, evs["before.raw"], BEFORE),
        "run_b": _run(session, evs["after.raw"], AFTER),
    }


def _run(session: Session, ev: Evidence, rows: list[dict], plugin: str = PSLIST, **kw) -> Run:
    run = Run(evidence_id=ev.id, plugin=plugin, status=RunStatus.SUCCEEDED, **kw)
    session.add(run)
    session.flush()
    run.row_count = results.store_rows(
        session, run.id, (ParsedRow(r) for r in rows), search_index=False
    )
    session.commit()
    return run


# ------------------------------------------------------------------------------ service


def test_default_comparison(session: Session, setup: dict) -> None:
    a, b = setup["run_a"], setup["run_b"]
    keys, ignored = compare.default_settings(a, b)
    assert keys == ["ImageFileName"]  # catalog compare_keys for pslist
    assert ignored == ["PID", "Threads"]  # built-in volatile columns
    cmp = compare.compare(session, a, b)
    assert cmp.compared == ["Wow64"]
    assert cmp.counts == {"only_a": 1, "only_b": 2, "changed": 1, "same": 3}
    assert cmp.only_a == [4]  # notepad
    assert sorted(cmp.only_b) == [3, 5]  # the extra svchost and evil.exe
    assert cmp.changed == [(3, 4, ["Wow64"])]  # explorer
    assert cmp.warnings == []


def test_custom_settings_and_errors(session: Session, setup: dict) -> None:
    a, b = setup["run_a"], setup["run_b"]
    # Counting Threads as a change: System and explorer change too.
    cmp = compare.compare(session, a, b, ["ImageFileName"], ["PID"])
    assert cmp.counts["changed"] == 2 and cmp.changed[0][2] == ["Threads"]
    # Every column as identity: changes become add/remove pairs.
    cmp = compare.compare(session, a, b, ["ImageFileName", "Wow64"], ["PID", "Threads"])
    assert cmp.counts == {"only_a": 2, "only_b": 3, "changed": 0, "same": 3}
    with pytest.raises(compare.CompareError, match="at least one column"):
        compare.compare(session, a, b, ["Nope"], [])
    other = _run(session, setup["after"], [{"Variable": "x", "Value": 1}], "windows.info.Info")
    with pytest.raises(compare.CompareError, match="same plugin"):
        compare.compare(session, a, other)
    run_deletion.delete_run(session, b.id, "redo")
    with pytest.raises(compare.CompareError, match="no results"):
        compare.compare(session, a, b)


def test_warnings_and_catalog_keys_for_info(session: Session, setup: dict) -> None:
    info = "windows.info.Info"
    a = _run(
        session,
        setup["before"],
        [{"Variable": "SystemTime", "Value": "t1"}, {"Variable": "NtBuildLab", "Value": "x"}],
        info,
        tool_version="2.28.2",
    )
    b = _run(
        session,
        setup["after"],
        [
            {"Variable": "SystemTime", "Value": "t2", "Extra": 1},
            {"Variable": "NtBuildLab", "Value": "x", "Extra": 1},
        ],
        info,
        tool_version="2.29.0",
        args={"x": 1},
    )
    cmp = compare.compare(session, a, b)
    assert cmp.keys == ["Variable"] and cmp.changed == [(0, 0, ["Value"])] and cmp.same == 1
    assert any("different arguments" in w for w in cmp.warnings)
    assert any("different tool versions" in w for w in cmp.warnings)
    assert any("only one run" in w and "Extra" in w for w in cmp.warnings)


def test_scope_save_recompute_csv(session: Session, setup: dict) -> None:
    case, a, b = setup["case"], setup["run_a"], setup["run_b"]
    stranger = _run(session, setup["unrelated"], BEFORE)
    with pytest.raises(compare.CompareError, match="not in this case"):
        compare.check_scope(session, case, a, stranger)

    cmp = compare.compare(session, a, b)
    saved = compare.save(session, case, cmp, comment="new evil.exe")
    assert saved.title == "PsList: before.raw vs after.raw"
    assert saved.counts == cmp.counts and saved.keys == ["ImageFileName"]
    again = compare.recompute(session, saved)
    assert again.counts == cmp.counts
    assert compare.url(case, saved).startswith(f"/cases/{case}/compare?run_a={a.id}&run_b={b.id}")

    body = compare.to_csv(session, cmp)
    lines = body.strip().splitlines()
    assert lines[0] == "category,image,row,ImageFileName,differences"
    assert "only_b,after.raw,R2:5,'=evil.exe," in body  # formula-escaped
    assert "changed,before.raw / after.raw,R1:3 / R2:4,explorer.exe,Wow64: False -> True" in body

    run_deletion.delete_run(session, b.id, "redo")
    assert "no results" in compare.recompute(session, saved)
    compare.delete_saved(session, saved.id)
    assert compare.list_saved(session, case) == []
    actions = [
        e.action
        for e in session.scalars(select(AuditEvent).where(AuditEvent.action.like("comparison.%")))
    ]
    assert actions == ["comparison.save", "comparison.delete"]


def test_case_report(session: Session, setup: dict) -> None:
    cmp = compare.compare(session, setup["run_a"], setup["run_b"])
    compare.save(session, setup["case"], cmp, title="Before vs after")
    report = export.build_report(session, case_id=setup["case"])
    section = report.split("### Comparisons")[1]
    assert "#### Before vs after" in section
    assert "only in A 1, only in B 2, changed 1, same 3" in section
    assert "`R2:5`" in section and "ImageFileName=\\=evil.exe" not in section
    assert "`ImageFileName==evil.exe`" in section  # inside code span, unescaped


# ------------------------------------------------------------------------------ API + UI


def test_api(client: TestClient, setup: dict) -> None:
    case, a, b = setup["case"], setup["run_a"], setup["run_b"]
    r = client.post(f"/api/cases/{case}/compare", json={"run_a": a.id, "run_b": b.id})
    assert r.status_code == 200 and r.json()["counts"]["changed"] == 1
    assert r.json()["changed"][0] == {"a": f"R{a.id}:3", "b": f"R{b.id}:4", "columns": ["Wow64"]}
    r = client.post(f"/api/cases/{case}/compare", json={"run_a": a.id, "run_b": 999})
    assert r.status_code == 404
    r = client.post(
        f"/api/cases/{case}/comparisons", json={"run_a": a.id, "run_b": b.id, "title": "t"}
    )
    assert r.status_code == 201
    saved = client.get(f"/api/cases/{case}/comparisons").json()
    assert saved[0]["title"] == "t" and saved[0]["counts_when_saved"]["only_b"] == 2
    assert client.delete(f"/api/cases/{case}/comparisons/{saved[0]['id']}").status_code == 204


def test_ui(client: TestClient, session: Session, setup: dict) -> None:
    case, before, after = setup["case"], setup["before"], setup["after"]
    page = client.get(f"/cases/{case}").text
    assert 'action="/cases/1/compare"' in page and "Compare…" in page

    step = client.get(f"/cases/{case}/compare?a={before.id}&b={after.id}").text
    assert f'<option value="{PSLIST}"' in step  # plugins with runs on both images

    r = client.get(f"/cases/{case}/compare?a={before.id}&b={after.id}&plugin={PSLIST}")
    html = r.text
    assert "only in A: 1" in html and "only in B: 2" in html and "changed: 1" in html
    assert "=evil.exe" in html and "notepad.exe" in html
    assert "<strong>Wow64</strong>: False → True" in html
    assert f'href="/runs/{setup["run_b"].id}?case={case}&row=5#row-' in html

    custom = client.get(
        f"/cases/{case}/compare?run_a={setup['run_a'].id}&run_b={setup['run_b'].id}"
        "&custom=1&keys=ImageFileName&ignore=PID"
    ).text
    assert "changed: 2" in custom

    csv = client.get(
        f"/cases/{case}/compare.csv?run_a={setup['run_a'].id}&run_b={setup['run_b'].id}"
    )
    assert csv.status_code == 200 and csv.text.startswith("category,image,row")
    assert 'filename="compare-run1-run2.csv"' in csv.headers["content-disposition"]

    r = client.post(
        f"/ui/cases/{case}/comparisons",
        data={
            "run_a": setup["run_a"].id, "run_b": setup["run_b"].id,
            "keys_json": '["ImageFileName"]', "ignore_json": '["PID", "Threads"]',
            "title": "After infection",
        },
        follow_redirects=False,
    )  # fmt: skip
    assert r.headers["location"] == f"/cases/{case}#comparisons"
    page = client.get(f"/cases/{case}").text
    assert "After infection" in page and "only A 1 · only B 2 · changed 1 · same 3" in page

    # Images outside the case are refused; plugins without runs on both explain why.
    stranger = _run(session, setup["unrelated"], BEFORE)
    html = client.get(f"/cases/{case}/compare?run_a={stranger.id}&run_b={setup['run_b'].id}").text
    assert "both images must be in this case" in html
    html = client.get(
        f"/cases/{case}/compare?a={before.id}&b={after.id}&plugin=windows.info.Info"
    ).text
    assert "has no finished run on both images" in html
    assert client.get(f"/cases/{case}/compare.csv?a={before.id}").status_code == 422
