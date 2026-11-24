"""Smoke test of the UI wired into the real app factory and real services (no fakes)."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

pytest.importorskip("app.main")

from app.models import AIMessage, Evidence, ResultRow, Run, RunStatus  # noqa: E402

HX = {"HX-Request": "true"}


def test_real_app_pages(client, session: Session) -> None:
    r = client.post("/ui/scan", headers=HX)
    assert r.status_code == 200 and "sample.raw" in r.text
    ev = session.query(Evidence).filter_by(rel_path="sample.raw").one()

    assert "Temporary UI" in client.get("/").text
    page = client.get(f"/evidence/{ev.id}")
    assert page.status_code == 200 and '<option value="windows.' in page.text

    r = client.post("/ui/notes", headers=HX, data={"body": "real note", "evidence_id": ev.id})
    assert "real note" in r.text

    r = client.post(f"/ui/evidence/{ev.id}/runs", headers=HX, data={"plugin": "nope.Nope"})
    assert r.headers.get("HX-Retarget") == "#run-form-errors"

    run = Run(evidence_id=ev.id, plugin="windows.pslist.PsList", status=RunStatus.SUCCEEDED)
    session.add(run)
    session.commit()
    for i in range(150):
        session.add(ResultRow(run_id=run.id, row_idx=i, data={"PID": i, "Name": f"p{i}"}))
    session.add(
        AIMessage(
            evidence_id=ev.id,
            role="assistant",
            content=f"<b>x</b> [R{run.id}:120]",
            citations=[{"key": f"R{run.id}:120", "valid": True}],
        )
    )
    session.commit()

    r = client.get(f"/runs/{run.id}", params={"row": 120})
    assert f'<tr id="row-{run.id}-120" class="highlight">' in r.text
    r = client.get(f"/ui/runs/{run.id}/rows", params={"q": "p14"}, headers=HX)
    assert "of 11" in r.text
    r = client.get(f"/ui/evidence/{ev.id}/ai", headers=HX)
    assert "&lt;b&gt;x&lt;/b&gt;" in r.text
    assert f'href="/runs/{run.id}?row=120#row-{run.id}-120"' in r.text
    assert client.get("/static/htmx.min.js").status_code == 200
