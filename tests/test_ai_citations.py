from __future__ import annotations

from sqlalchemy.orm import Session

from app.ai.citations import (
    NOT_FOUND,
    SUPPORTED,
    UNCHECKED,
    UNSUPPORTED,
    citation_status,
    extract_citations,
    extract_values,
    validate_citations,
)
from app.models import ResultRow
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


def test_extract_values_typed_only() -> None:
    text = (
        "svchost.exe (PID 1234, PPID 600) at C:\\Windows\\System32\\svchost.exe talks to "
        "010.0.0.5 port 443 at 0x7ffe0000 running `cmd.exe /c whoami` [R1:2]. "
        "There are 3 processes, version 1.2.3.4.5, time 10:22:33."
    )
    values = extract_values(text)
    assert ("path", "C:\\Windows\\System32\\svchost.exe") in values
    assert ("ip", "010.0.0.5") in values and ("hex", "0x7ffe0000") in values
    assert {v for k, v in values if k == "number"} == {"1234", "600", "443"}
    assert ("text", "cmd.exe /c whoami") in values and ("file", "cmd.exe") in values
    assert not any(v in ("3", "1", "2", "10:22:33") for _, v in values)  # bare numbers/citations
    assert extract_values("Nothing checkable here [R1:2].") == []


def _row(session: Session, run_id: int, idx: int, data: dict) -> None:
    session.add(ResultRow(run_id=run_id, row_idx=idx, data=data))
    session.commit()


def test_support_checks_values_against_cited_row(session: Session) -> None:
    _, run = seed(session, n_rows=2)  # rows: PID 100/p0.exe, PID 101/p1.exe
    r = run.id
    text = (
        f"p0.exe has PID 100 [R{r}:0]. p1.exe has PID 555 [R{r}:1]. "
        f"Two processes ran [R{r}:0]. Missing row [R{r}:9]."
    )
    by_key = {c["key"]: c for c in validate_citations(session, text)}
    assert by_key[f"R{r}:0"]["support"] == SUPPORTED
    assert by_key[f"R{r}:0"]["checked"] == ["p0.exe", "PID/port 100"]
    assert by_key[f"R{r}:1"]["support"] == UNSUPPORTED
    assert by_key[f"R{r}:1"]["unsupported_values"] == ["PID/port 555"]
    assert by_key[f"R{r}:9"]["support"] == NOT_FOUND and not by_key[f"R{r}:9"]["valid"]


def test_support_unchecked_and_multi_row_sentence(session: Session) -> None:
    _, run = seed(session, n_rows=2)
    r = run.id
    assert validate_citations(session, f"Looks normal [R{r}:0].")[0]["support"] == UNCHECKED
    # One sentence citing two rows is checked against both rows together.
    text = f"p0.exe (PID 100) spawned p1.exe (PID 101) [R{r}:0, R{r}:1]."
    assert {c["support"] for c in validate_citations(session, text)} == {SUPPORTED}


def test_support_normalises_volatility_forms(session: Session) -> None:
    _, run = seed(session, n_rows=0)
    _row(
        session,
        run.id,
        0,
        {
            "ImageFileName": "MicrosoftEdgeU",  # truncated to 14 chars by Windows
            "Path": "\\Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe",
            "Offset(V)": 0x7FFE0000,
            "ForeignAddr": "10.0.0.5",
        },
    )
    text = (
        f"MicrosoftEdgeUpdate.exe and C:\\Windows\\System32\\svchost.exe at 0x7ffe0000 "
        f"talk to 010.000.0.5 [R{run.id}:0]."
    )
    (c,) = validate_citations(session, text)
    assert c["support"] == SUPPORTED, c["unsupported_values"]


def test_citation_status() -> None:
    assert citation_status({"key": "R1:2", "valid": True}) == UNCHECKED
    assert citation_status({"key": "R1:2", "valid": False}) == NOT_FOUND
    assert citation_status({"valid": True, "support": UNSUPPORTED}) == UNSUPPORTED


def test_support_includes_tree_parent_and_children(session: Session) -> None:
    _, run = seed(session, n_rows=0)
    session.add_all(
        [
            ResultRow(run_id=run.id, row_idx=0, data={"ImageFileName": "wininit.exe", "PID": 480}),
            ResultRow(
                run_id=run.id,
                row_idx=1,
                depth=1,
                parent_idx=0,
                data={"ImageFileName": "services.exe", "PID": 600, "PPID": 480},
            ),
            ResultRow(run_id=run.id, row_idx=2, data={"ImageFileName": "other.exe", "PID": 7}),
        ]
    )
    session.commit()
    r = run.id
    up = validate_citations(session, f"services.exe runs under wininit.exe [R{r}:1].")
    down = validate_citations(session, f"wininit.exe started services.exe [R{r}:0].")
    unrelated = validate_citations(session, f"other.exe started services.exe [R{r}:2].")
    assert up[0]["support"] == down[0]["support"] == SUPPORTED
    assert unrelated[0]["support"] == UNSUPPORTED
