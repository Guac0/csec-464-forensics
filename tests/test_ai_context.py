from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from app.ai.context import TRUNCATED_MARKER, NotFoundError, build_context
from app.tools import content
from app.tools.content import AIContext, AIRows
from tests.test_ai_helpers import seed


def test_context_contents_and_refs(session: Session) -> None:
    ev, run = seed(session, n_rows=3)
    text, refs = build_context(session, ev.id)

    assert "file: sample.raw" in text
    assert "ab" * 32 in text
    assert '"build": "19041"' in text
    assert "Test image" in text
    assert "evidence note" in text
    assert "case note" not in text  # case notes span several images: never in one image's context
    assert f"## Run R{run.id}: windows.pslist.PsList" in text
    assert f'[R{run.id}:0] {{"PID": 100' in text
    assert "boom" not in text  # failed runs are excluded by default

    assert refs == {
        "evidence_id": ev.id,
        "run_ids": [run.id],
        "row_refs_included": [f"R{run.id}:{i}" for i in range(3)],
        "truncated": False,
    }


def test_context_max_rows_per_run(session: Session) -> None:
    ev, run = seed(session, n_rows=10)
    text, refs = build_context(session, ev.id, max_rows_per_run=4)
    assert refs["row_refs_included"] == [f"R{run.id}:{i}" for i in range(4)]
    assert "showing first 4 of 10 rows" in text


def test_context_explicit_run_ids_and_row_refs(session: Session) -> None:
    ev, run = seed(session, n_rows=10)
    failed_id = run.id + 1
    text, refs = build_context(
        session, ev.id, run_ids=[failed_id], row_refs=[f"R{run.id}:7", "R999:1", "bogus"]
    )
    assert refs["run_ids"] == [failed_id]
    assert refs["row_refs_included"] == [f"R{run.id}:7"]
    assert refs["row_refs_missing"] == ["R999:1", "bogus"]
    assert "error: boom" in text
    assert "Rows selected by the analyst" in text


def test_context_truncation_is_deterministic(session: Session) -> None:
    ev, run = seed(session, n_rows=50)
    text, refs = build_context(session, ev.id, max_chars=800)
    text2, refs2 = build_context(session, ev.id, max_chars=800)

    assert (text, refs) == (text2, refs2)
    assert refs["truncated"] is True
    assert len(text) <= 800
    assert text.endswith(TRUNCATED_MARKER)
    included = refs["row_refs_included"]
    assert 0 < len(included) < 50
    # every included key appears as a complete row line, nothing after it
    for key in included:
        assert f"[{key}]" in text
    assert f"[R{run.id}:{len(included)}]" not in text


def test_context_unknown_evidence(session: Session) -> None:
    with pytest.raises(NotFoundError):
        build_context(session, 12345)


# --- per-plugin AI rows (Plugin.ai_context / select_ai_rows in a content file) -------------


def test_context_per_plugin_limit_and_columns(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    ev, run = seed(session, n_rows=10)
    rules = AIRows(AIContext(max_rows=3, columns=("PID",)))
    monkeypatch.setitem(content.current().ai, run.plugin, rules)
    text, refs = build_context(session, ev.id)
    assert refs["row_refs_included"] == [f"R{run.id}:{i}" for i in range(3)]
    assert f'[R{run.id}:0] {{"PID": 100}}' in text and "p0.exe" not in text


def test_context_custom_row_selection(session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    ev, run = seed(session, n_rows=10)

    def odd(rows):
        return (r.row_idx for r in rows if r.data["PID"] % 2)

    monkeypatch.setitem(content.current().ai, run.plugin, AIRows(AIContext(max_rows=2), odd))
    text, refs = build_context(session, ev.id)
    assert refs["row_refs_included"] == [f"R{run.id}:1", f"R{run.id}:3"]
    assert "chosen by the plugin's row selection 2 of 10 rows" in text


def test_context_failing_row_selection_falls_back(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    ev, run = seed(session, n_rows=5)

    def broken(rows):
        raise KeyError("nope")

    monkeypatch.setitem(content.current().ai, run.plugin, AIRows(AIContext(max_rows=2), broken))
    text, refs = build_context(session, ev.id)
    assert refs["row_refs_included"] == [f"R{run.id}:0", f"R{run.id}:1"]
    assert "custom row selection failed: KeyError" in text
