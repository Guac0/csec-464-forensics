"""Assemble the data context sent to the AI provider.

The context is built from stored data only (evidence metadata, analyst notes, parsed result
rows). Every row is prefixed with its citation key so the model can cite it as [R<run>:<row>].
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.ai.citations import parse_key
from app.models import Evidence, Note, ResultRow, Run, RunStatus
from app.services import integrity

TRUNCATED_MARKER = "[truncated]"


class NotFoundError(LookupError):
    """Requested evidence / run does not exist."""


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str, separators=(", ", ": "))


def format_row(row: ResultRow) -> str:
    indent = "  " * max(row.depth, 0)
    text = f"{indent}[{row.citation}] {_json(row.data)}"
    if row.annotations:
        flags = "; ".join(
            f"{a.get('tag')} ({a.get('severity')})" + (f": {a['note']}" if a.get("note") else "")
            for a in row.annotations
        )
        text += f"  <- automated flags: {flags}"
    return text


def _findings_block(run: Run, max_rows: int = 10) -> list[str]:
    """Hook findings for a run, labelled as automated heuristics with their supporting rows."""
    if not run.findings:
        return []
    lines = ["automated findings (post-run hooks; heuristics to verify, not conclusions):"]
    for f in run.findings:
        rows = f.get("rows") or []
        cites = ", ".join(f"R{run.id}:{i}" for i in rows[:max_rows])
        if len(rows) > max_rows:
            cites += f", ... ({len(rows)} rows)"
        line = f"- [{f.get('severity')}] {f.get('title')}"
        if f.get("detail"):
            line += f" - {f['detail']}"
        if cites:
            line += f" (rows: {cites})"
        lines.append(line)
    return lines


class _Builder:
    """Appends blocks in order until max_chars; stops deterministically at the first overflow."""

    def __init__(self, max_chars: int) -> None:
        self.max_chars = max_chars
        self.parts: list[str] = []
        self.length = 0
        self.truncated = False
        self.row_keys: list[str] = []

    def add(self, text: str, row_key: str | None = None) -> bool:
        if self.truncated:
            return False
        sep = 1 if self.parts else 0
        budget = self.max_chars - len(TRUNCATED_MARKER) - 1
        if self.length + sep + len(text) <= budget:
            self.parts.append(text)
            self.length += sep + len(text)
            if row_key is not None and row_key not in self.row_keys:
                self.row_keys.append(row_key)
            return True
        # Partial non-row text is kept (cut at the budget); rows are never cut in half so a
        # cited key always refers to a complete row.
        remaining = budget - self.length - sep
        if row_key is None and remaining > 0:
            self.parts.append(text[:remaining])
        self.parts.append(TRUNCATED_MARKER)
        self.truncated = True
        return False

    def text(self) -> str:
        return "\n".join(self.parts)


def _evidence_block(ev: Evidence) -> str:
    lines = [
        "## Evidence",
        f"evidence_id: {ev.id}",
        f"file: {ev.rel_path}",
        f"size_bytes: {ev.size_bytes}",
        f"sha256: {ev.sha256 or '(not yet hashed)'}",
        f"integrity: {integrity.status(ev)}",
        f"os_info: {_json(ev.os_info) if ev.os_info else '(unknown)'}",
    ]
    if ev.description:
        lines.append(f"description: {ev.description}")
    return "\n".join(lines)


def _requested_rows(
    session: Session, evidence_id: int, row_refs: Iterable[str]
) -> tuple[list[ResultRow], list[str]]:
    """Resolve "R<run>:<row>" refs to rows belonging to this evidence; return (rows, missing)."""
    rows: list[ResultRow] = []
    missing: list[str] = []
    seen: set[tuple[int, int]] = set()
    for ref in row_refs:
        pair = parse_key(ref.strip("[] "))
        if pair is None or pair in seen:
            if pair is None:
                missing.append(ref)
            continue
        seen.add(pair)
        row = session.execute(
            select(ResultRow)
            .join(Run, Run.id == ResultRow.run_id)
            .where(
                ResultRow.run_id == pair[0],
                ResultRow.row_idx == pair[1],
                Run.evidence_id == evidence_id,
            )
        ).scalar_one_or_none()
        if row is None:
            missing.append(f"R{pair[0]}:{pair[1]}")
        else:
            rows.append(row)
    return rows, missing


def build_context(
    session: Session,
    evidence_id: int,
    run_ids: list[int] | None = None,
    row_refs: list[str] | None = None,
    max_rows_per_run: int = 50,
    max_chars: int = 60000,
) -> tuple[str, dict[str, Any]]:
    """Return (context_text, context_refs) for one evidence item.

    Order: evidence info, notes, explicitly requested rows (in full), then runs (each with up
    to max_rows_per_run rows). Explicit rows come before run listings so they survive
    truncation.
    """
    ev = session.get(Evidence, evidence_id)
    if ev is None:
        raise NotFoundError(f"evidence {evidence_id} not found")

    b = _Builder(max_chars)
    b.add(_evidence_block(ev))

    notes = (
        session.execute(
            select(Note)
            .where(or_(Note.evidence_id == evidence_id, Note.evidence_id.is_(None)))
            .order_by(Note.created_at, Note.id)
        )
        .scalars()
        .all()
    )
    if notes:
        b.add("\n## Analyst notes")
        for n in notes:
            scope = "evidence" if n.evidence_id is not None else "global"
            b.add(f"- ({scope} note {n.id}) {n.body}")

    missing_refs: list[str] = []
    if row_refs:
        rows, missing_refs = _requested_rows(session, evidence_id, row_refs)
        if rows:
            b.add("\n## Rows selected by the analyst")
            for row in rows:
                b.add(format_row(row), row_key=row.citation)

    stmt = select(Run).where(Run.evidence_id == evidence_id)
    if run_ids is None:
        stmt = stmt.where(Run.status == RunStatus.SUCCEEDED)
    else:
        stmt = stmt.where(Run.id.in_(run_ids))
    runs = session.execute(stmt.order_by(Run.id)).scalars().all()

    included_runs: list[int] = []
    for run in runs:
        header = [
            f"\n## Run R{run.id}: {run.plugin}",
            f"tool: {run.tool}",
            f"args: {_json(run.args or {})}",
            f"status: {run.status.value}",
            f"row_count: {run.row_count}",
        ]
        if run.error:
            header.append(f"error: {run.error}")
        header.extend(_findings_block(run))
        rows = list(
            session.execute(
                select(ResultRow)
                .where(ResultRow.run_id == run.id)
                .order_by(ResultRow.row_idx)
                .limit(max_rows_per_run)
            )
            .scalars()
            .all()
        )
        shown_first = len(rows)
        # Rows flagged by hooks beyond the first N are included too, so flags are never hidden
        # just because the row appears late in the output.
        flagged = (
            session.execute(
                select(ResultRow)
                .where(
                    ResultRow.run_id == run.id,
                    ResultRow.row_idx >= shown_first,
                    ResultRow.annotations.is_not(None),
                )
                .order_by(ResultRow.row_idx)
                .limit(max_rows_per_run)
            )
            .scalars()
            .all()
        )
        rows.extend(flagged)
        if rows and run.row_count > len(rows):
            note = f"(showing first {shown_first} of {run.row_count} rows"
            note += f" plus {len(flagged)} later flagged rows)" if flagged else ")"
            header.append(note)
        # TODO(forensics): per-plugin summarization / row selection (e.g. only suspicious
        # malfind hits, collapsed pstree branches) instead of the first N rows.
        if not b.add("\n".join(header)):
            break
        included_runs.append(run.id)
        for row in rows:
            if not b.add(format_row(row), row_key=row.citation):
                break
        if b.truncated:
            break

    refs: dict[str, Any] = {
        "evidence_id": evidence_id,
        "run_ids": included_runs,
        "row_refs_included": b.row_keys,
        "truncated": b.truncated,
    }
    if missing_refs:
        refs["row_refs_missing"] = missing_refs
    return b.text(), refs
