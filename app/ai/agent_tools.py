"""Read-only tools of the AI agent (app/ai/agent.py), scoped to ONE image.

Every tool only reads data the app already stored for the task's image: its runs, their result
rows and hook findings. Nothing here runs a plugin, writes data or sees other images. Row
values are evidence (possibly attacker-controlled text): they are returned as data, prefixed
with their citation key ``[R<run>:<row>]``.

Adding a tool: write a function ``(session, evidence_id, args) -> ToolOutput``, add a
``ToolSpec`` to ``TOOLS`` (its JSON schema is shown to the model) and a test in
tests/test_ai_agent.py. Tools here stay read-only: the one acting tool, ``queue_run``, is
handled by the agent loop itself because it needs the analyst's approval (app/ai/agent.py).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select, tuple_
from sqlalchemy.orm import Session

from app.ai.citations import parse_key
from app.ai.context import format_row
from app.models import ResultRow, Run, RunStatus
from app.services import results as results_svc
from app.services import runs as runs_svc

MAX_RESULT_CHARS = 8000
MAX_SEARCH_LIMIT = 50
DEFAULT_SEARCH_LIMIT = 20
MAX_GET_ROWS = 30
TRUNCATED = "[output truncated: narrow the search or page with offset]"


class ToolError(Exception):
    """A tool call the model got wrong (unknown run, bad args): reported back to the model."""


@dataclass
class ToolOutput:
    text: str  # what the model sees
    summary: str  # one line for the analyst's step list
    row_keys: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]  # JSON schema (object)
    fn: Callable[[Session, int, dict[str, Any]], ToolOutput]

    def openai(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _int(args: dict[str, Any], name: str, default: int | None = None) -> int:
    value = args.get(name, default)
    if isinstance(value, bool) or value is None:
        raise ToolError(f"'{name}' must be an integer")
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ToolError(f"'{name}' must be an integer, got {value!r}") from None


def _run(session: Session, evidence_id: int, run_id: int) -> Run:
    run = session.get(Run, run_id)
    if run is None or run.evidence_id != evidence_id or run.deleted_at is not None:
        raise ToolError(f"run {run_id} does not exist for this image (use list_runs)")
    return run


def _cap(lines: list[str]) -> tuple[str, bool]:
    """Join lines up to MAX_RESULT_CHARS; whole lines only (a row is never cut in half)."""
    out: list[str] = []
    size = 0
    for line in lines:
        if size + len(line) + 1 > MAX_RESULT_CHARS - len(TRUNCATED) - 1:
            out.append(TRUNCATED)
            return "\n".join(out), True
        out.append(line)
        size += len(line) + 1
    return "\n".join(out), False


# --------------------------------------------------------------------------- tools


def list_runs(session: Session, evidence_id: int, args: dict[str, Any]) -> ToolOutput:
    runs = session.scalars(
        select(Run).where(Run.evidence_id == evidence_id, Run.deleted_at.is_(None)).order_by(Run.id)
    ).all()
    lines = []
    for run in runs:
        line = f"R{run.id} {run.plugin} args {_json(run.args or {})}: {run.status.value}"
        if run.status == RunStatus.SUCCEEDED:
            columns = results_svc.column_names(run)
            line += f", {run.row_count or 0} rows; columns: {', '.join(columns) or '?'}"
            tags = runs_svc.annotation_tags(session, run.id)
            if tags:
                line += "; flagged by tag: " + ", ".join(f"{t} ({n})" for t, n in tags)
            if run.findings:
                line += f"; {len(run.findings)} hook finding(s)"
        lines.append(line)
    text, _ = _cap(lines or ["No runs on this image yet."])
    return ToolOutput(text, f"{len(runs)} run(s)")


def search_rows(session: Session, evidence_id: int, args: dict[str, Any]) -> ToolOutput:
    run = _run(session, evidence_id, _int(args, "run_id"))
    if run.status != RunStatus.SUCCEEDED:
        raise ToolError(f"run {run.id} has no rows (status {run.status.value})")
    filters = args.get("filters") or {}
    if not isinstance(filters, dict):
        raise ToolError('\'filters\' must be an object like {"ImageFileName": "svchost"}')
    known = set(results_svc.column_names(run))
    unknown = [c for c in filters if known and c not in known]
    if unknown:
        raise ToolError(f"unknown column(s) {unknown}; columns are: {sorted(map(str, known))}")
    view = results_svc.RowView(
        q=str(args.get("query") or "").strip(),
        annotated=bool(args.get("flagged_only")),
        tag=str(args.get("tag") or "").strip(),
        filters={str(k): str(v) for k, v in filters.items()},
    )
    limit = max(1, min(_int(args, "limit", DEFAULT_SEARCH_LIMIT), MAX_SEARCH_LIMIT))
    offset = max(0, _int(args, "offset", 0))
    try:
        rows, total = results_svc.query_rows(session, run, view, offset=offset, limit=limit)
    except ValueError as exc:
        raise ToolError(str(exc)) from exc
    header = (
        f"{total} matching row(s) in R{run.id} ({run.plugin}); showing {len(rows)} from "
        f"offset {offset}."
    )
    text, truncated = _cap([header, *(format_row(r) for r in rows)])
    shown = [r.citation for r in rows]
    if truncated:
        shown = [k for k in shown if f"[{k}]" in text]
    what = view.q or ", ".join(f"{k} {v}" for k, v in view.filters.items()) or "all rows"
    return ToolOutput(text, f"R{run.id}: {total} match(es) for {what}", shown)


def get_rows(session: Session, evidence_id: int, args: dict[str, Any]) -> ToolOutput:
    keys = args.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ToolError("'keys' must be a non-empty list like [\"R12:3\"]")
    pairs = []
    for key in keys[:MAX_GET_ROWS]:
        pair = parse_key(str(key))
        if pair is None:
            raise ToolError(f"invalid row key {key!r}; use the form R<run>:<row>")
        pairs.append(pair)
    run_ids = {r for r, _ in pairs}
    for run_id in run_ids:
        _run(session, evidence_id, run_id)
    rows = session.scalars(
        select(ResultRow)
        .where(tuple_(ResultRow.run_id, ResultRow.row_idx).in_(pairs))
        .order_by(ResultRow.run_id, ResultRow.row_idx)
    ).all()
    found = {r.citation for r in rows}
    missing = [f"R{r}:{i}" for r, i in pairs if f"R{r}:{i}" not in found]
    lines = [format_row(r) for r in rows]
    if missing:
        lines.append(f"Not found: {', '.join(missing)}")
    text, _ = _cap(lines)
    return ToolOutput(text, f"read {len(rows)} row(s)", [r.citation for r in rows])


def get_findings(session: Session, evidence_id: int, args: dict[str, Any]) -> ToolOutput:
    if args.get("run_id") is not None:
        runs = [_run(session, evidence_id, _int(args, "run_id"))]
    else:
        runs = list(
            session.scalars(
                select(Run)
                .where(Run.evidence_id == evidence_id, Run.deleted_at.is_(None))
                .order_by(Run.id)
            )
        )
    lines, keys = [], []
    for run in runs:
        for f in run.findings or []:
            rows = [f"R{run.id}:{i}" for i in (f.get("rows") or [])[:20]]
            keys += rows
            line = f"R{run.id} [{f.get('severity')}] {f.get('title')}"
            if f.get("detail"):
                line += f" - {f['detail']}"
            if rows:
                line += f" (rows: {', '.join(rows)})"
            lines.append(line)
    text, _ = _cap(
        ["Hook findings are automated heuristics to verify, not conclusions.", *lines]
        if lines
        else ["No hook findings."]
    )
    return ToolOutput(text, f"{len(lines)} finding(s)", keys)


_RUN_ID = {"type": "integer", "description": "Run id, e.g. 12 for R12"}

TOOLS: dict[str, ToolSpec] = {
    t.name: t
    for t in (
        ToolSpec(
            "list_runs",
            "List this image's runs: id, plugin, options, status, row count, column names and "
            "flagged-row tags. Start here.",
            {"type": "object", "properties": {}},
            list_runs,
        ),
        ToolSpec(
            "search_rows",
            "Search the rows of one run. 'query' is a case-insensitive text search over the "
            "row; 'filters' maps a column to a value (substring) or a comparison such as "
            "'>=1000', '=4', '!=0'. Returns matching rows with their citation keys.",
            {
                "type": "object",
                "properties": {
                    "run_id": _RUN_ID,
                    "query": {"type": "string", "description": "Text to search for"},
                    "filters": {
                        "type": "object",
                        "description": 'Column filters, e.g. {"ImageFileName": "svchost"}',
                        "additionalProperties": {"type": "string"},
                    },
                    "flagged_only": {
                        "type": "boolean",
                        "description": "Only rows flagged by post-run hooks",
                    },
                    "tag": {"type": "string", "description": "Only rows with this hook tag"},
                    "limit": {
                        "type": "integer",
                        "description": f"Max rows (<= {MAX_SEARCH_LIMIT})",
                    },
                    "offset": {"type": "integer", "description": "Skip this many rows (paging)"},
                },
                "required": ["run_id"],
            },
            search_rows,
        ),
        ToolSpec(
            "get_rows",
            f"Read specific rows by citation key (max {MAX_GET_ROWS}).",
            {
                "type": "object",
                "properties": {
                    "keys": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": 'Row keys, e.g. ["R12:3", "R12:7"]',
                    }
                },
                "required": ["keys"],
            },
            get_rows,
        ),
        ToolSpec(
            "get_findings",
            "Hook findings (automated heuristics) for one run, or for all runs if run_id is "
            "omitted.",
            {"type": "object", "properties": {"run_id": _RUN_ID}},
            get_findings,
        ),
    )
}


def run_tool(session: Session, evidence_id: int, name: str, args: Any) -> ToolOutput:
    """Execute one tool call; mistakes come back as an ERROR output the model can fix."""
    spec = TOOLS.get(name)
    if spec is None:
        return ToolOutput(
            f"ERROR: unknown tool {name!r}. Tools: {', '.join(TOOLS)}", f"unknown tool {name}"
        )
    if not isinstance(args, dict):
        return ToolOutput("ERROR: arguments must be a JSON object", "invalid arguments")
    try:
        return spec.fn(session, evidence_id, args)
    except ToolError as exc:
        return ToolOutput(f"ERROR: {exc}", f"error: {exc}")


def describe_tools_for_text_protocol(extra: tuple[ToolSpec, ...] = ()) -> str:
    """Tool list for models without native tool calling (see prompts.AGENT_TEXT_PROTOCOL)."""
    lines = []
    for spec in (*TOOLS.values(), *extra):
        params = spec.parameters.get("properties", {})
        required = set(spec.parameters.get("required", []))
        args = ", ".join(
            f"{name}{'' if name in required else '?'}: {p.get('type')}"
            for name, p in params.items()
        )
        lines.append(f"- {spec.name}({args}): {spec.description}")
    return "\n".join(lines)
