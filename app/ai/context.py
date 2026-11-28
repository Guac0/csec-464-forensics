"""Assemble the data context sent to the AI provider.

The context is built from stored data only (evidence metadata, analyst notes, parsed result
rows). Every row is prefixed with its citation key so the model can cite it as [R<run>:<row>].
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai.citations import parse_key
from app.models import Evidence, Note, ResultRow, Run, RunStatus
from app.services import integrity
from app.tools import content
from app.tools.hooks import HookRow

logger = logging.getLogger(__name__)

TRUNCATED_MARKER = "[truncated]"


class NotFoundError(LookupError):
    """Requested evidence / run does not exist."""


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str, separators=(", ", ": "))


def format_row(row: ResultRow, columns: Iterable[str] = ()) -> str:
    """``[R1:2] {...}`` (+ hook flags). ``columns``: show only these (per-plugin AI context)."""
    indent = "  " * max(row.depth, 0)
    data = row.data
    wanted = tuple(columns)
    if wanted and isinstance(data, dict):
        data = {k: v for k, v in data.items() if k in wanted}
    text = f"{indent}[{row.citation}] {_json(data)}"
    if row.annotations:
        flags = "; ".join(
            f"{a.get('tag')} ({a.get('severity')})" + (f": {a['note']}" if a.get("note") else "")
            for a in row.annotations
        )
        text += f"  <- automated flags: {flags}"
    return text


def _artifacts_line(run: Run, limit: int = 10) -> str:
    """Files the run wrote (e.g. --dump), with hashes, for the model to reference."""
    parts = []
    for a in run.artifacts[:limit]:
        where = f", row R{run.id}:{a.source_row_idx}" if a.source_row_idx is not None else ""
        parts.append(
            f"{a.filename} ({a.file_type}, {a.size_bytes} bytes, sha256 {a.sha256}{where})"
        )
    more = f"; ... ({len(run.artifacts)} total)" if len(run.artifacts) > limit else ""
    return "dumped files: " + "; ".join(parts) + more


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


def _selected_rows(
    session: Session, run: Run, rules: Any, limit: int
) -> tuple[list[ResultRow] | None, str]:
    """Rows picked by the plugin file's ``select_ai_rows`` (None = use the first ``limit``).
    A failing selector falls back to the default and says so in the run header."""
    if rules is None or rules.select is None:
        return None, ""
    stream = (
        HookRow(r.row_idx, r.depth, r.parent_idx, dict(r.data or {}))
        for r in session.execute(
            select(ResultRow).where(ResultRow.run_id == run.id).order_by(ResultRow.row_idx)
        )
        .yield_per(1000)
        .scalars()
    )
    try:
        picked: list[int] = []
        for idx in rules.select(stream):
            if int(idx) not in picked:
                picked.append(int(idx))
            if len(picked) >= limit:
                break
    except Exception as exc:  # noqa: BLE001  (team code must not break AI answers)
        logger.warning("select_ai_rows for %s failed: %s", run.plugin, exc)
        return None, f"(custom row selection failed: {type(exc).__name__}; showing first rows)"
    by_idx = {
        r.row_idx: r
        for r in session.execute(
            select(ResultRow).where(ResultRow.run_id == run.id, ResultRow.row_idx.in_(picked))
        ).scalars()
    }
    return [by_idx[i] for i in picked if i in by_idx], ""


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
            # Only this image's notes: case notes span several images and are not mixed into
            # one image's AI context.
            .where(Note.evidence_id == evidence_id)
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
        stmt = stmt.where(Run.status == RunStatus.SUCCEEDED, Run.deleted_at.is_(None))
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
        if run.artifacts:
            header.append(_artifacts_line(run))
        rules = content.current().ai.get(run.plugin)
        limit = (rules.settings.max_rows if rules else None) or max_rows_per_run
        columns = rules.settings.columns if rules else ()
        rows, note = _selected_rows(session, run, rules, limit)
        custom = rows is not None
        if note:
            header.append(note)
        if rows is None:
            rows = list(
                session.execute(
                    select(ResultRow)
                    .where(ResultRow.run_id == run.id)
                    .order_by(ResultRow.row_idx)
                    .limit(limit)
                )
                .scalars()
                .all()
            )
        shown_first = len(rows)
        shown = {r.row_idx for r in rows}
        # Rows flagged by hooks beyond the first N are included too, so flags are never hidden
        # just because the row appears late in the output.
        flagged_q = select(ResultRow).where(
            ResultRow.run_id == run.id, ResultRow.annotations.is_not(None)
        )
        if not custom:
            flagged_q = flagged_q.where(ResultRow.row_idx >= shown_first)
        flagged = [
            r
            for r in session.execute(
                flagged_q.order_by(ResultRow.row_idx).limit(max_rows_per_run + len(shown))
            )
            .scalars()
            .all()
            if r.row_idx not in shown
        ][:max_rows_per_run]
        rows.extend(flagged)
        if rows and run.row_count > len(rows):
            what = "chosen by the plugin's row selection" if custom else "first"
            note = f"(showing {what} {shown_first} of {run.row_count} rows"
            note += f" plus {len(flagged)} other flagged rows)" if flagged else ")"
            header.append(note)
        if not b.add("\n".join(header)):
            break
        included_runs.append(run.id)
        for row in rows:
            if not b.add(format_row(row, columns), row_key=row.citation):
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


MAX_FLAGGED_ROWS = 30


def _notes_block(session: Session, evidence_id: int) -> list[str]:
    notes = session.scalars(
        select(Note).where(Note.evidence_id == evidence_id).order_by(Note.created_at, Note.id)
    ).all()
    return ["\n## Analyst notes", *(f"- (note {n.id}) {n.body}" for n in notes)] if notes else []


def build_state_context(
    session: Session,
    evidence_id: int,
    max_flagged_rows: int = MAX_FLAGGED_ROWS,
    max_chars: int = 30000,
) -> tuple[str, dict[str, Any]]:
    """Context for "what should I run next?": the investigation STATE, not bulk rows.

    Order: evidence info, notes, every run (plugin, args, status, row count, hook tags and
    findings), the guide's static recommendations, recommendations the analyst dismissed, then
    up to ``max_flagged_rows`` hook-flagged rows (newest runs first) so the model can choose
    specific options (e.g. a PID).
    """
    from app.services import recommendations as recs_svc
    from app.services import runs as runs_svc

    ev = session.get(Evidence, evidence_id)
    if ev is None:
        raise NotFoundError(f"evidence {evidence_id} not found")
    b = _Builder(max_chars)
    b.add(_evidence_block(ev))
    for line in _notes_block(session, evidence_id):
        b.add(line)

    runs = list(
        session.scalars(
            select(Run)
            .where(Run.evidence_id == evidence_id, Run.deleted_at.is_(None))
            .order_by(Run.id)
        )
    )
    b.add("\n## Runs so far (oldest first)")
    if not runs:
        b.add("(none yet)")
    for run in runs:
        line = f"- R{run.id} {run.plugin} args {_json(run.args or {})}: {run.status.value}"
        if run.status == RunStatus.SUCCEEDED:
            line += f", {run.row_count or 0} rows"
            tags = runs_svc.annotation_tags(session, run.id)
            if tags:
                line += "; flagged rows by tag: " + ", ".join(f"{t} ({n})" for t, n in tags)
        elif run.error:
            line += f" ({run.error.splitlines()[0][:200]})"
        b.add(line)
        for finding in _findings_block(run):
            b.add("  " + finding)

    recs = recs_svc.recommend(session, evidence_id)
    if recs.items:
        b.add(
            "\n## Static recommendations not yet run (from the team's investigation guide; "
            "you may agree, reorder or suggest something better)"
        )
        for r in recs.items:
            kind = f"baseline {r.baseline_pos}/{recs.baseline_total}" if r.baseline_pos else "next"
            b.add(f"- {r.plugin} args {_json(r.args)} ({kind}): {' / '.join(r.reasons)}")
    if recs.dismissed:
        b.add("\n## Dismissed by the analyst for this image (do not suggest these again)")
        for r in recs.dismissed:
            b.add(f"- {r.plugin} args {_json(r.args)}")

    run_ids = [r.id for r in runs if r.status == RunStatus.SUCCEEDED]
    flagged = list(
        session.scalars(
            select(ResultRow)
            .where(ResultRow.run_id.in_(run_ids), ResultRow.annotations.is_not(None))
            .order_by(ResultRow.run_id.desc(), ResultRow.row_idx)
            .limit(max_flagged_rows + 1)
        )
    )
    if flagged:
        more = len(flagged) > max_flagged_rows
        b.add(
            f"\n## Rows flagged by post-run hooks (first {max_flagged_rows}"
            f"{', more exist' if more else ''}; heuristics, not conclusions)"
        )
        for row in flagged[:max_flagged_rows]:
            if not b.add(format_row(row), row_key=row.citation):
                break
    refs: dict[str, Any] = {
        "kind": "recommend",
        "evidence_id": evidence_id,
        "run_ids": [r.id for r in runs],
        "row_refs_included": b.row_keys,
        "static_recommendations": [r.key for r in recs.items],
        "truncated": b.truncated,
    }
    return b.text(), refs
