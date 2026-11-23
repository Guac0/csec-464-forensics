"""Citation extraction and validation for AI output.

Citation format: ``[R12:34]`` (run 12, row 34), or several in one bracket: ``[R1:2, R1:3]``.
"""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy import select, tuple_
from sqlalchemy.orm import Session

from app.models import ResultRow

_KEY = r"R\d+:\d+"
_BRACKET_RE = re.compile(rf"\[\s*({_KEY}(?:\s*[,;]\s*{_KEY})*)\s*\]")
_KEY_RE = re.compile(r"R(\d+):(\d+)")


def parse_key(key: str) -> tuple[int, int] | None:
    """'R12:34' -> (12, 34); None if not a citation key."""
    m = _KEY_RE.fullmatch(key.strip())
    return (int(m.group(1)), int(m.group(2))) if m else None


def extract_citations(text: str) -> list[str]:
    """Ordered, de-duplicated citation keys found in bracketed citations."""
    seen: dict[str, None] = {}
    for bracket in _BRACKET_RE.finditer(text or ""):
        for m in _KEY_RE.finditer(bracket.group(1)):
            seen.setdefault(f"R{int(m.group(1))}:{int(m.group(2))}", None)
    return list(seen)


def citation_url(run_id: int, row_idx: int) -> str:
    """UI link for a cited row (see CONTRACTS.md)."""
    return f"/runs/{run_id}?row={row_idx}#row-{run_id}-{row_idx}"


def validate_citations(session: Session, text: str) -> list[dict[str, Any]]:
    """Check that every cited row exists.

    TODO: value-level verification (does the claim actually match the cited row's data?).
    """
    keys = extract_citations(text)
    pairs = [p for k in keys if (p := parse_key(k)) is not None]
    existing: set[tuple[int, int]] = set()
    if pairs:
        stmt = select(ResultRow.run_id, ResultRow.row_idx).where(
            tuple_(ResultRow.run_id, ResultRow.row_idx).in_(pairs)
        )
        existing = {(r, i) for r, i in session.execute(stmt).all()}
    return [
        {
            "key": f"R{r}:{i}",
            "run_id": r,
            "row_idx": i,
            "valid": (r, i) in existing,
            "url": citation_url(r, i),
        }
        for r, i in pairs
    ]
