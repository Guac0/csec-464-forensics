"""Cases (groups of images) and sharing items between a case's images."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app import db
from app.config import Settings
from app.models import AIMessage, AuditEvent, Evidence, Note, ResultRow, Run, RunStatus
from app.services import cases, notes, results, run_deletion, sharing
from app.services import evidence as evidence_service
from app.tools.base import ParsedRow


@pytest.fixture
def images(session: Session, settings: Settings) -> tuple[Evidence, Evidence, Evidence]:
    for name in ("before.raw", "after.raw"):
        (settings.evidence_dir / name).write_bytes(b"\0" * 64)
    evs = {e.rel_path: e for e in evidence_service.scan_evidence(session)}
    return evs["before.raw"], evs["after.raw"], evs["sample.raw"]


def _run(session: Session, ev: Evidence, rows: list[dict], findings=None) -> Run:
    run = Run(
        evidence_id=ev.id,
        plugin="windows.pslist.PsList",
        status=RunStatus.SUCCEEDED,
        findings=findings,
    )
    session.add(run)
    session.flush()
    run.row_count = results.store_rows(
        session, run.id, (ParsedRow(r) for r in rows), search_index=False
    )
    session.commit()
    return run


def _actions(session: Session, prefix: str) -> list[str]:
    return [
        e.action
        for e in session.scalars(
            select(AuditEvent).where(AuditEvent.action.like(prefix + "%")).order_by(AuditEvent.seq)
        )
    ]


# ------------------------------------------------------------------------------ cases


def test_case_lifecycle(session: Session, images) -> None:
    before, after, other = images
    case = cases.create_case(session, "  APT   X ", "two snapshots")
    assert case.name == "APT X"
    with pytest.raises(ValueError, match="already exists"):
        cases.create_case(session, "APT X")
    with pytest.raises(ValueError, match="must not be empty"):
        cases.create_case(session, " ")

    cases.add_evidence(session, case.id, before.id, "before")
    cases.add_evidence(session, case.id, after.id)
    with pytest.raises(ValueError, match="already in case"):
        cases.add_evidence(session, case.id, after.id)
    cases.set_label(session, case.id, after.id, "after")
    assert cases.labels(session, case.id) == {before.id: "before", after.id: "after"}
    assert [(e.id, lbl) for e, lbl in cases.member_evidence(session, case.id)] == [
        (before.id, "before"),
        (after.id, "after"),
    ]

    # An image can be in several cases.
    second = cases.create_case(session, "Lateral movement")
    cases.add_evidence(session, second.id, after.id, "host-2")
    assert [c.name for c, _ in cases.cases_for_evidence(session, after.id)] == [
        "APT X",
        "Lateral movement",
    ]
    assert cases.cases_for_evidence(session, other.id) == []

    with pytest.raises(ValueError, match="not empty"):
        cases.delete_case(session, second.id)
    cases.remove_evidence(session, second.id, after.id)
    cases.delete_case(session, second.id)
    cases.update_case(session, case.id, name="APT-X")
    assert _actions(session, "case.") == [
        "case.create",
        "case.add_evidence",
        "case.add_evidence",
        "case.label",
        "case.create",
        "case.add_evidence",
        "case.remove_evidence",
        "case.delete",
        "case.update",
    ]


# ------------------------------------------------------------------------------ sharing


def test_share_rows_findings_notes_ai_and_latest_state(session: Session, images) -> None:
    before, after, other = images
    case = cases.create_case(session, "APT X")
    cases.add_evidence(session, case.id, before.id, "before")
    cases.add_evidence(session, case.id, after.id, "after")
    run = _run(
        session,
        after,
        [{"PID": 4, "Name": "System"}, {"PID": 666, "Name": "evil.exe"}],
        findings=[{"hook": "h", "title": "Odd parent", "detail": "d", "severity": "high"}],
    )
    note = notes.create_note(session, "dropper in Public", evidence_id=after.id)
    msg = AIMessage(evidence_id=after.id, role="assistant", content="Looks like a dropper [R1:1]")
    session.add(msg)
    session.commit()

    row = sharing.share(session, case.id, "row", run_id=run.id, row_idx=1, comment="the dropper")
    sharing.share(session, case.id, "finding", run_id=run.id, finding_index=0)
    shared_note = sharing.share(session, case.id, "note", note_id=note.id)
    sharing.share(session, case.id, "ai_answer", ai_message_id=msg.id)
    assert row.source_key == f"R{run.id}:1" and row.source_evidence_id == after.id
    with pytest.raises(ValueError, match="already shared"):
        sharing.share(session, case.id, "row", run_id=run.id, row_idx=1)
    with pytest.raises(LookupError):
        sharing.share(session, case.id, "row", run_id=run.id, row_idx=99)

    # What the OTHER image sees: all four, current, pointing at "after".
    seen = sharing.resolved_for_case(session, case.id, exclude_evidence_id=before.id)
    assert [r.status for r in seen] == ["ok"] * 4
    assert seen[0].text == "PID=666, Name=evil.exe" and seen[0].source.id == after.id
    assert seen[0].link == f"/runs/{run.id}?case={case.id}&row=1#row-{run.id}-1"
    assert seen[3].kind_label.startswith("AI answer")
    assert sharing.resolved_for_case(session, case.id, exclude_evidence_id=after.id) == []
    assert set(sharing.shared_keys(session, case.id, after.id)) == {
        f"R{run.id}:1",
        f"F{run.id}:h/Odd parent",
        f"N{note.id}",
        f"A{msg.id}",
    }

    # Latest state: edits show as "changed", deletions as "gone".
    notes.update_note(session, note.id, "dropper in C:\\Users\\Public")
    r = sharing.resolve(session, shared_note)
    assert r.status == "changed" and "Public" in r.text
    run_deletion.delete_run(session, run.id, "redo")
    states = {r.item.kind.value: r.status for r in sharing.resolved_for_case(session, case.id)}
    assert states == {"row": "gone", "finding": "gone", "note": "changed", "ai_answer": "ok"}
    notes.delete_note(session, note.id)
    assert sharing.resolve(session, shared_note).status == "gone"

    assert _actions(session, "share.") == ["share.create"] * 4


def test_sharing_rules(session: Session, images) -> None:
    before, after, other = images
    case = cases.create_case(session, "APT X")
    cases.add_evidence(session, case.id, before.id)
    run = _run(session, other, [{"PID": 1}])
    with pytest.raises(ValueError, match="not in case"):
        sharing.share(session, case.id, "row", run_id=run.id, row_idx=0)
    case_note = notes.create_note(session, "case level", case_id=case.id)
    with pytest.raises(ValueError, match="only notes on an image"):
        sharing.share(session, case.id, "note", note_id=case_note.id)
    err = AIMessage(evidence_id=before.id, role="assistant", content="", error="timeout")
    session.add(err)
    session.commit()
    with pytest.raises(ValueError, match="no content"):
        sharing.share(session, case.id, "ai_answer", ai_message_id=err.id)
    with pytest.raises(ValueError):
        sharing.share(session, case.id, "bogus", run_id=run.id)


def test_removing_an_image_unshares_its_items(session: Session, images) -> None:
    before, after, _ = images
    case = cases.create_case(session, "APT X")
    cases.add_evidence(session, case.id, before.id)
    cases.add_evidence(session, case.id, after.id)
    run = _run(session, after, [{"PID": 1}])
    keep_run = _run(session, before, [{"PID": 2}])
    sharing.share(session, case.id, "row", run_id=run.id, row_idx=0)
    kept = sharing.share(session, case.id, "row", run_id=keep_run.id, row_idx=0)
    assert cases.remove_evidence(session, case.id, after.id) == 1
    assert [i.id for i in sharing.list_items(session, case.id)] == [kept.id]
    assert session.scalar(select(ResultRow.id).where(ResultRow.run_id == run.id))  # untouched
    removed = session.scalars(select(AuditEvent).where(AuditEvent.action == "share.remove")).one()
    assert removed.details["reason"] == "image removed from the case"


def test_shared_items_never_reach_ai_context(session: Session, images) -> None:
    from app.ai.context import build_context

    before, after, _ = images
    case = cases.create_case(session, "APT X")
    cases.add_evidence(session, case.id, before.id)
    cases.add_evidence(session, case.id, after.id)
    run = _run(session, after, [{"PID": 666, "Name": "only-on-after.exe"}])
    sharing.share(session, case.id, "row", run_id=run.id, row_idx=0)
    notes.create_note(session, "case-level secret", case_id=case.id)
    text_, _refs = build_context(session, before.id)
    assert "only-on-after.exe" not in text_ and "case-level secret" not in text_


# ------------------------------------------------------------------------------ migration


def test_migration_moves_global_notes_into_general_case(settings: Settings) -> None:
    from alembic import command

    engine = db.init_engine()
    cfg = db.alembic_config()
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "0008_run_deletion")
        for i, path in enumerate(("a.raw", "b.raw")):
            conn.execute(
                text(
                    "INSERT INTO evidence (id, rel_path, size_bytes, mtime, description, "
                    "created_at) VALUES (:i, :p, 1, 0, '', '2026-01-01')"
                ),
                {"i": i + 1, "p": path},
            )
        conn.execute(
            text(
                "INSERT INTO notes (body, created_at, updated_at) "
                "VALUES ('g', '2026-01-01', '2026-01-01')"
            )
        )
        conn.execute(
            text(
                "INSERT INTO notes (body, evidence_id, created_at, updated_at) "
                "VALUES ('e', 1, '2026-01-01', '2026-01-01')"
            )
        )
    db.migrate(engine)
    with db.SessionLocal() as s:
        (general,) = cases.list_cases(s)
        assert general.name == "General"
        assert {e.rel_path for e, _ in cases.member_evidence(s, general.id)} == {"a.raw", "b.raw"}
        by_body = {n.body: n for n in s.scalars(select(Note))}
        assert by_body["g"].case_id == general.id and by_body["e"].case_id is None


def test_migration_without_global_notes_creates_no_case(session: Session) -> None:
    assert cases.list_cases(session) == []


# ------------------------------------------------------------------------------ API + UI


def test_api(client: TestClient, session: Session, images) -> None:
    before, after, _ = images
    case_id = client.post("/api/cases", json={"name": "APT X"}).json()["id"]
    assert client.post("/api/cases", json={"name": "APT X"}).status_code == 422
    assert (
        client.post(
            f"/api/cases/{case_id}/evidence", json={"evidence_id": before.id, "label": "before"}
        ).status_code
        == 201
    )
    client.post(f"/api/cases/{case_id}/evidence", json={"evidence_id": after.id})
    assert (
        client.patch(f"/api/cases/{case_id}/evidence/{after.id}", json={"label": "after"}).json()[
            "label"
        ]
        == "after"
    )
    run = _run(session, after, [{"PID": 666}])
    r = client.post(
        f"/api/cases/{case_id}/shared",
        json={"kind": "row", "run_id": run.id, "row_idx": 0, "comment": "odd"},
    )
    assert (
        r.status_code == 201
        and r.json()["status"] == "ok"
        and r.json()["current_text"] == "PID=666"
    )
    item_id = r.json()["id"]
    assert (
        client.post(
            f"/api/cases/{case_id}/shared", json={"kind": "row", "run_id": run.id, "row_idx": 0}
        ).status_code
        == 409
    )
    data = client.get(f"/api/cases/{case_id}").json()
    assert [m["label"] for m in data["members"]] == ["before", "after"] and len(data["shared"]) == 1
    assert client.get(f"/api/cases/{case_id}/shared?exclude_evidence_id={after.id}").json() == []
    assert client.delete(f"/api/cases/{case_id}").status_code == 409
    assert client.delete(f"/api/cases/{case_id}/shared/{item_id}").status_code == 204
    assert client.delete(f"/api/cases/{case_id}/shared/{item_id}").status_code == 404
    r = client.get(f"/api/export?case_id={case_id}")
    assert r.status_code == 200 and "# Case export: APT X" in r.text
    assert 'filename="case-APT_X-' in r.headers["content-disposition"]


def test_ui_flow(client: TestClient, session: Session, images) -> None:
    before, after, other = images
    r = client.post(
        "/ui/cases", data={"name": "APT X", "description": "snapshots"}, follow_redirects=False
    )
    case_url = r.headers["location"]
    case_id = int(case_url.rsplit("/", 1)[1])
    client.post(f"/ui/cases/{case_id}/members", data={"evidence_id": before.id, "label": "before"})
    client.post(f"/ui/cases/{case_id}/members", data={"evidence_id": after.id, "label": "after"})
    page = client.get(case_url).text
    assert "Case: APT X" in page and f'href="/evidence/{before.id}?case={case_id}"' in page
    assert "Nothing shared yet" in page and "other" not in page.split("add an image")[0][-50:]

    run = _run(
        session,
        after,
        [{"PID": 666, "Name": "evil.exe"}],
        findings=[{"hook": "h", "title": "Odd", "detail": "", "severity": "low"}],
    )
    # Run page in case context: share buttons for rows and findings, dialog targets the case.
    run_page = client.get(f"/runs/{run.id}?case={case_id}").text
    assert (
        "Case APT X" in run_page
        and 'data-kind="row"' in run_page
        and 'data-kind="finding"' in run_page
    )
    assert f'name="case_id" value="{case_id}"' in run_page
    r = client.post(
        "/ui/share",
        data={
            "case_id": case_id,
            "kind": "row",
            "run_id": run.id,
            "row_idx": 0,
            "comment": "dropper?",
            "next": f"/runs/{run.id}?case={case_id}",
        },
        follow_redirects=False,
    )
    assert r.headers["location"] == f"/runs/{run.id}?case={case_id}"
    assert "shared ✕" in client.get(f"/runs/{run.id}?case={case_id}").text
    assert (
        client.post(
            "/ui/share", data={"case_id": case_id, "kind": "row", "run_id": run.id, "row_idx": 0}
        ).status_code
        == 409
    )
    r = client.post(
        "/ui/share",
        data={
            "case_id": case_id,
            "kind": "row",
            "run_id": run.id,
            "row_idx": 0,
            "next": "//evil.example",
        },
        follow_redirects=False,
    )
    assert r.status_code == 409

    # The other image, opened in the case, shows it as a lead from "after".
    ev_page = client.get(f"/evidence/{before.id}?case={case_id}").text
    assert "Shared in case APT X (1)" in ev_page and "PID=666, Name=evil.exe" in ev_page
    assert "dropper?" in ev_page and "(after)" in ev_page
    # Without case context: no shared panel, case chips instead.
    plain = client.get(f"/evidence/{before.id}").text
    assert "Shared in case" not in plain and f'href="/evidence/{before.id}?case={case_id}"' in plain
    # Wrong case: warning, no case context.
    assert "is not in case 999" in client.get(f"/evidence/{before.id}?case=999").text
    # Not in any case: no share buttons.
    assert "Not in any case" in client.get(f"/evidence/{other.id}").text

    # Case notes on the case page.
    r = client.post(
        "/ui/notes", data={"case_id": case_id, "body": "kickoff"}, follow_redirects=False
    )
    assert r.headers["location"] == f"/cases/{case_id}#notes"
    assert "kickoff" in client.get(case_url).text

    # Un-share from the case page; remove an image.
    item = sharing.list_items(session, case_id)[0]
    client.post(f"/ui/shared/{item.id}/remove", data={"next": case_url})
    assert "Nothing shared yet" in client.get(case_url).text
    client.post(f"/ui/cases/{case_id}/members/{after.id}/remove")
    assert cases.labels(session, case_id) == {before.id: "before"}
    r = client.post(f"/ui/cases/{case_id}/delete")
    assert r.status_code == 409 and "Cannot delete" in r.text


def test_share_redirects_stay_on_site() -> None:
    from app.web.cases_pages import _safe_next

    assert _safe_next("/runs/1?case=2#row-1-0", "/") == "/runs/1?case=2#row-1-0"
    for bad in ("//evil.example", "https://evil.example", "/\\evil", "", None):
        assert _safe_next(bad, "/fallback") == "/fallback"
