"""Backend JSON API tests (worker disabled; fake tool runner)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import ResultRow, Run, RunStatus
from tests.test_backend_fakes import FakeRunner, install_fake_runner


@pytest.fixture
def fake_runner(monkeypatch: pytest.MonkeyPatch) -> FakeRunner:
    return install_fake_runner(monkeypatch)


def _scan(client: TestClient) -> int:
    resp = client.post("/api/evidence/scan")
    assert resp.status_code == 200
    (ev,) = resp.json()
    return ev["id"]


def test_health(client: TestClient) -> None:
    assert client.get("/health").json() == {"status": "ok"}


def test_evidence_endpoints(client: TestClient) -> None:
    ev_id = _scan(client)
    listed = client.get("/api/evidence").json()
    assert [e["rel_path"] for e in listed] == ["sample.raw"]

    resp = client.patch(f"/api/evidence/{ev_id}", json={"description": "suspect laptop"})
    assert resp.status_code == 200
    assert client.get(f"/api/evidence/{ev_id}").json()["description"] == "suspect laptop"

    assert client.post(f"/api/evidence/{ev_id}/hash").status_code == 202
    assert client.get("/api/evidence/999").status_code == 404


def test_create_run_validation_error_is_422(client: TestClient, fake_runner: FakeRunner) -> None:
    ev_id = _scan(client)
    resp = client.post("/api/runs", json={"evidence_id": ev_id, "plugin": "windows.evil.Evil"})
    assert resp.status_code == 422
    assert "plugin not allowed" in resp.json()["detail"]

    resp = client.post(
        "/api/runs",
        json={"evidence_id": ev_id, "plugin": "windows.pslist.PsList", "args": {"pid": "x"}},
    )
    assert resp.status_code == 422

    resp = client.post("/api/runs", json={"evidence_id": 999, "plugin": "windows.info.Info"})
    assert resp.status_code == 404


def test_run_lifecycle_api(client: TestClient, session: Session, fake_runner: FakeRunner) -> None:
    ev_id = _scan(client)
    resp = client.post(
        "/api/runs",
        json={
            "evidence_id": ev_id,
            "plugin": "windows.pslist.PsList",
            "args": {"pid": [4]},
            "origin": "preset",
        },
    )
    assert resp.status_code == 201
    run = resp.json()
    assert run["status"] == "queued" and run["origin"] == "preset" and run["args"] == {"pid": [4]}

    assert [r["id"] for r in client.get(f"/api/runs?evidence_id={ev_id}").json()] == [run["id"]]
    assert client.get("/api/runs?evidence_id=999").json() == []
    assert client.get(f"/api/runs/{run['id']}").json()["plugin"] == "windows.pslist.PsList"

    resp = client.post(f"/api/runs/{run['id']}/cancel")
    assert resp.status_code == 200 and resp.json()["status"] == "cancelled"
    assert client.post("/api/runs/999/cancel").status_code == 404

    auto = client.post(f"/api/evidence/{ev_id}/auto")
    assert auto.status_code == 201
    assert {r["origin"] for r in auto.json()} == {"auto"}
    assert len(auto.json()) == 2


def test_rows_endpoint(client: TestClient, session: Session) -> None:
    ev_id = _scan(client)
    run = Run(evidence_id=ev_id, plugin="windows.pslist.PsList", status=RunStatus.SUCCEEDED)
    session.add(run)
    session.flush()
    for i, name in enumerate(["System", "lsass.exe", "evil.exe"]):
        session.add(ResultRow(run_id=run.id, row_idx=i, data={"name": name}))
    session.commit()

    body = client.get(f"/api/runs/{run.id}/rows?limit=2").json()
    assert body["total"] == 3
    assert [r["citation"] for r in body["rows"]] == [f"R{run.id}:0", f"R{run.id}:1"]

    body = client.get(f"/api/runs/{run.id}/rows", params={"q": "EVIL"}).json()
    assert body["total"] == 1
    assert body["rows"][0] == {
        "citation": f"R{run.id}:2",
        "row_idx": 2,
        "depth": 0,
        "parent_idx": None,
        "data": {"name": "evil.exe"},
        "annotations": None,
    }
    assert client.get("/api/runs/999/rows").status_code == 404


def test_notes_api(client: TestClient) -> None:
    ev_id = _scan(client)
    resp = client.post("/api/notes", json={"body": "pid 666 looks odd", "evidence_id": ev_id})
    assert resp.status_code == 201
    note = resp.json()
    case_id = client.post("/api/cases", json={"name": "c"}).json()["id"]
    assert client.post("/api/notes", json={"body": "global"}).status_code == 422
    client.post("/api/notes", json={"body": "case note", "case_id": case_id})
    assert [n["body"] for n in client.get(f"/api/notes?case_id={case_id}").json()] == ["case note"]

    assert len(client.get("/api/notes").json()) == 2
    assert [n["id"] for n in client.get(f"/api/notes?evidence_id={ev_id}").json()] == [note["id"]]

    resp = client.patch(f"/api/notes/{note['id']}", json={"body": "pid 666 is malware"})
    assert resp.json()["body"] == "pid 666 is malware"
    assert client.patch(f"/api/notes/{note['id']}", json={"body": " "}).status_code == 422
    assert client.post("/api/notes", json={"body": "x", "evidence_id": 999}).status_code == 404

    assert client.delete(f"/api/notes/{note['id']}").status_code == 204
    assert client.get(f"/api/notes/{note['id']}").status_code == 404
    assert client.delete(f"/api/notes/{note['id']}").status_code == 404
