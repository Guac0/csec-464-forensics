from __future__ import annotations

from sqlalchemy.orm import Session

from app.ai.citations import extract_citations, validate_citations
from tests.test_ai_helpers import seed


def test_extract_citations() -> None:
    text = (
        "Process p1 [R1:2] spawned p2 [R1:3, R1:4]; again [R1:2]. "
        "Not a citation: R5:6, [r1:1], [R1:x], (R2:3). Leading zeros [R01:002]."
    )
    assert extract_citations(text) == ["R1:2", "R1:3", "R1:4"]  # R01:002 == R1:2


def test_extract_citations_empty() -> None:
    assert extract_citations("") == []
    assert extract_citations("no refs here") == []


def test_validate_citations(session: Session) -> None:
    _, run = seed(session, n_rows=2)
    text = f"see [R{run.id}:1] and [R{run.id}:99, R999:0]"
    result = validate_citations(session, text)
    assert [(c["key"], c["valid"]) for c in result] == [
        (f"R{run.id}:1", True),
        (f"R{run.id}:99", False),
        ("R999:0", False),
    ]
    assert result[0]["run_id"] == run.id and result[0]["row_idx"] == 1
    assert result[0]["url"] == f"/runs/{run.id}?row=1#row-{run.id}-1"


def test_validate_citations_none(session: Session) -> None:
    assert validate_citations(session, "nothing") == []
