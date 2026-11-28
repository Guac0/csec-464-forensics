"""Large results: column inference, optional full-text index, search/filter/sort, exports (CSV,
JSON Lines, raw), the results UI, and the migration backfill."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import AuditEvent, Evidence, ResultRow, Run, RunStatus
from app.services import evidence as evidence_service
from app.services import results
from app.services import runs as runs_service
from app.tools.base import ParsedRow

HX = {"HX-Request": "true"}

ROWS: list[dict[str, Any]] = [
    {"PID": 4, "Name": "System", "Size": 10, "Path": None},
    {"PID": 88, "Name": "smss.exe", "Size": 2.5, "Path": "C:\\Windows\\smss.exe"},
    {"PID": 400, "Name": "=cmd|' /C calc'!A0", "Size": -3, "Path": "C:\\Temp\\evil.exe"},
    {"PID": 1000, "Name": "svchost.exe", "Size": 7, "Path": "C:\\Windows\\svchost.exe"},
    {"PID": 1004, "Name": "svchost.exe", "Size": None, "Path": {"nested": [1, 2]}},
]


@pytest.fixture
def evidence(session: Session) -> Evidence:
    (ev,) = evidence_service.scan_evidence(session)
    return ev


def make_run(session: Session, evidence: Evidence, search_index: bool = False) -> Run:
    run = Run(evidence_id=evidence.id, plugin="windows.pslist.PsList", status=RunStatus.SUCCEEDED)
    session.add(run)
    session.flush()
    n = results.store_rows(
        session, run.id, (ParsedRow(data=d) for d in ROWS), search_index=search_index
    )
    run.row_count = n
    session.commit()
    return run


def idxs(session: Session, run: Run, **view: Any) -> list[int]:
    rows, _ = results.query_rows(session, run, results.RowView(**view), limit=1000)
    return [r.row_idx for r in rows]


# ------------------------------------------------------------------------------- ingest


def test_columns_are_recorded_in_order_with_types(session: Session, evidence: Evidence) -> None:
    run = make_run(session, evidence)
    assert run.columns == [
        {"name": "PID", "type": "int"},
        {"name": "Name", "type": "str"},
        {"name": "Size", "type": "float"},  # ints and floats merge to float; nulls ignored
        {"name": "Path", "type": "mixed"},  # str + JSON object
    ]
    assert run.search_indexed is False


def test_search_index_matches_scan(session: Session, evidence: Evidence) -> None:
    plain = make_run(session, evidence)
    indexed = make_run(session, evidence, search_index=True)
    assert indexed.search_indexed
    count = session.execute(text("SELECT count(*) FROM result_rows_fts")).scalar_one()
    assert count == len(ROWS)
    for q in ("svchost", "SVCHOST", "windows\\sm", "evil", "nested", "zz", "4"):
        assert idxs(session, plain, q=q) == idxs(session, indexed, q=q), q
    assert idxs(session, indexed, q="svchost") == [3, 4]
    # Windows paths (backslashes are escaped in the stored JSON) are found by the scan too.
    assert idxs(session, plain, q="C:\\Windows\\sv") == [3]
    assert idxs(session, indexed, q='"quote') == []  # FTS syntax is escaped


def test_index_existing_run(session: Session, evidence: Evidence) -> None:
    run = make_run(session, evidence)
    assert results.index_run(session, run.id) == len(ROWS)
    assert run.search_indexed and idxs(session, run, q="smss") == [1]
    assert results.index_run(session, run.id) == len(ROWS)  # rebuild, no duplicates
    count = session.execute(text("SELECT count(*) FROM result_rows_fts")).scalar_one()
    assert count == len(ROWS)


# ------------------------------------------------------------------------------- query


@pytest.mark.parametrize(
    ("filters", "expected"),
    [
        ({"PID": ">100"}, [2, 3, 4]),
        ({"PID": ">=1000"}, [3, 4]),
        ({"PID": "<=88"}, [0, 1]),
        ({"PID": "=4"}, [0]),
        ({"PID": "!=4"}, [1, 2, 3, 4]),
        ({"Size": "<0"}, [2]),
        ({"Name": "svc"}, [3, 4]),  # contains, case-insensitive
        ({"Name": "=svchost.exe"}, [3, 4]),
        ({"Name": "SVC", "PID": ">1002"}, [4]),
        ({"Path": "temp"}, [2]),
        ({"Nope": "x"}, [0, 1, 2, 3, 4]),  # unknown columns are ignored
        ({"PID": "   "}, [0, 1, 2, 3, 4]),
    ],
)
def test_column_filters(
    session: Session, evidence: Evidence, filters: dict[str, str], expected: list[int]
) -> None:
    run = make_run(session, evidence)
    assert idxs(session, run, filters=filters) == expected


def test_sorting(session: Session, evidence: Evidence) -> None:
    run = make_run(session, evidence)
    assert idxs(session, run, sort="Size") == [2, 1, 3, 0, 4]  # numeric, nulls last
    assert idxs(session, run, sort="Size", desc=True) == [0, 3, 1, 2, 4]
    # Text sorts case-insensitively: "=cmd...", "smss.exe", "svchost.exe" x2, "System".
    assert idxs(session, run, sort="Name") == [2, 1, 3, 4, 0]
    assert idxs(session, run, sort="Bogus") == [0, 1, 2, 3, 4]
    assert idxs(session, run, desc=True) == [4, 3, 2, 1, 0]


def test_view_params_round_trip() -> None:
    view = results.RowView.from_params(
        {"q": " x ", "tag": "*", "f.PID": ">4", "f.Name": "", "sort": "PID", "desc": "1", "z": 1}
    )
    assert view == results.RowView(
        q="x", annotated=True, filters={"PID": ">4"}, sort="PID", desc=True
    )
    assert results.RowView.from_params(view.to_params()) == view
    assert view.to_params(sort="Name", desc=None) == {
        "q": "x",
        "tag": "*",
        "f.PID": ">4",
        "sort": "Name",
    }
    assert results.parse_filter(" >= 10 ") == (">=", "10")
    assert results.parse_filter("abc") == ("contains", "abc")


# ------------------------------------------------------------------------------- exports


def _csv(body: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(body)))


def test_csv_and_jsonl_exports(client: TestClient, session: Session, evidence: Evidence) -> None:
    run = make_run(session, evidence)
    r = client.get(f"/api/runs/{run.id}/export", params={"format": "csv"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert f'filename="run-{run.id}-pslist.csv"' in r.headers["content-disposition"]
    table = _csv(r.text)
    assert table[0] == [
        "citation",
        "row_idx",
        "depth",
        "parent_idx",
        "PID",
        "Name",
        "Size",
        "Path",
        "flags",
    ]
    assert len(table) == 1 + len(ROWS)
    assert table[3][5] == "'=cmd|' /C calc'!A0"  # formula neutralised
    assert table[3][6] == "-3"  # negative numbers stay numbers
    assert table[5][7] == '{"nested": [1, 2]}'

    r = client.get(
        f"/api/runs/{run.id}/export",
        params={"format": "jsonl", "f.Name": "svchost", "sort": "PID", "desc": "1"},
    )
    lines = [json.loads(line) for line in r.text.splitlines()]
    assert [x["data"]["PID"] for x in lines] == [1004, 1000]
    assert lines[0]["citation"] == f"R{run.id}:4"
    assert "filtered" in r.headers["content-disposition"]

    exports = list(session.scalars(select(AuditEvent).where(AuditEvent.action == "run.export")))
    assert [(e.category, e.details["format"]) for e in exports] == [
        ("key_read", "csv"),
        ("key_read", "jsonl"),
    ]
    assert exports[1].details["view"]["filters"] == {"Name": "svchost"}


def test_raw_export_checks_hash(
    client: TestClient, session: Session, evidence: Evidence, settings: Settings
) -> None:
    import hashlib

    run = make_run(session, evidence)
    assert client.get(f"/api/runs/{run.id}/export", params={"format": "raw"}).status_code == 404
    out = settings.data_dir / "runs" / str(run.id) / "stdout.jsonl"
    out.parent.mkdir(parents=True)
    out.write_bytes(b'\n{"PID": 4}\n')
    run.stdout_path = f"runs/{run.id}/stdout.jsonl"
    run.stdout_sha256 = hashlib.sha256(out.read_bytes()).hexdigest()
    session.commit()
    r = client.get(f"/api/runs/{run.id}/export", params={"format": "raw"})
    assert r.status_code == 200 and r.content == b'\n{"PID": 4}\n'
    out.write_bytes(b"tampered")
    assert client.get(f"/api/runs/{run.id}/export", params={"format": "raw"}).status_code == 409


def test_rows_api_filters_and_bad_column(
    client: TestClient, session: Session, evidence: Evidence
) -> None:
    run = make_run(session, evidence)
    body = client.get(
        f"/api/runs/{run.id}/rows", params={"f.PID": ">100", "sort": "PID", "desc": "true"}
    ).json()
    assert body["total"] == 3 and [r["data"]["PID"] for r in body["rows"]] == [1004, 1000, 400]
    run.columns = [*run.columns, {"name": 'we"ird', "type": "str"}]
    session.commit()
    r = client.get(f"/api/runs/{run.id}/rows", params={'f.we"ird': "x"})
    assert r.status_code == 422
    assert client.get(f"/api/runs/{run.id}").json()["columns"][0] == {"name": "PID", "type": "int"}
    indexed = client.post(f"/api/runs/{run.id}/search-index").json()
    assert indexed["search_indexed"] is True


# ------------------------------------------------------------------------------- UI


def test_results_ui(client: TestClient, session: Session, evidence: Evidence) -> None:
    run = make_run(session, evidence)
    page = client.get(f"/runs/{run.id}").text
    assert 'id="view-form"' in page and 'name="f.PID"' in page and 'id="export-dialog"' in page
    assert f'href="/runs/{run.id}?sort=Size"' in page  # sortable header

    frag = client.get(
        f"/ui/runs/{run.id}/rows", params={"f.PID": ">100", "sort": "PID"}, headers=HX
    ).text
    assert "Rows 1–3 of 3" in frag and "1 column filter" in frag and "sorted by PID ↑" in frag
    assert 'value="&gt;100"' in frag  # filter value kept (escaped)
    assert f'href="/runs/{run.id}?f.PID=%3E100&amp;sort=PID&amp;desc=1"' in frag  # toggle desc

    r = client.get(f"/ui/runs/{run.id}/export", params={"choice": "csv:view", "f.Name": "svchost"})
    assert len(_csv(r.text)) == 3
    r = client.get(f"/ui/runs/{run.id}/export", params={"choice": "csv:all", "f.Name": "x"})
    assert len(_csv(r.text)) == 1 + len(ROWS)
    assert client.get(f"/ui/runs/{run.id}/export", params={"choice": "exe"}).status_code == 422


def test_get_rows_service_signature(session: Session, evidence: Evidence) -> None:
    run = make_run(session, evidence)
    rows, total = runs_service.get_rows(
        session, run.id, filters={"PID": ">100"}, sort="PID", desc=True, limit=2
    )
    assert total == 3 and [r.data["PID"] for r in rows] == [1004, 1000]


# ------------------------------------------------------------------------------- migration


def test_worker_ingest_records_columns(session: Session, evidence: Evidence, monkeypatch) -> None:  # noqa: ANN001
    import time

    from app.jobs import worker as worker_mod
    from app.tools.base import ToolRequest
    from tests.test_backend_fakes import install_fake_runner, make_fake_execute

    install_fake_runner(monkeypatch)
    monkeypatch.setattr(worker_mod, "execute", make_fake_execute([{"PID": 4, "X": "a"}]))
    run = runs_service.create_run(session, evidence.id, ToolRequest("windows.info.Info"))
    w = worker_mod.Worker(poll_interval=0.02)
    w.start()
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            session.expire_all()
            run = session.get(Run, run.id)
            if run.status == RunStatus.SUCCEEDED and run.phase is None:
                break
            time.sleep(0.02)
    finally:
        w.stop()
    assert run.columns == [{"name": "PID", "type": "int"}, {"name": "X", "type": "str"}]
    assert session.scalar(select(ResultRow.data).where(ResultRow.run_id == run.id)) == {
        "PID": 4,
        "X": "a",
    }
