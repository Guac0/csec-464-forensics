"""Result rows at scale: column inference, optional full-text index, querying and exports.

Querying (:func:`query_rows`) takes a :class:`RowView`:

- ``q``        substring search over a row's values. Uses the FTS5 trigram index when the run
               was indexed (FT_SEARCH_INDEX) and ``q`` has 3+ characters; otherwise a scan of
               the row JSON (fine up to ~1M rows, see scripts/bench_rows.py).
- ``filters``  per-column expressions: ``text`` (contains), ``=x``, ``!=x``, ``>n``, ``>=n``,
               ``<n``, ``<=n``. Numbers compare numerically.
- ``sort``     a column name (``desc`` for descending); ties and the default use row order.
- ``annotated`` / ``tag``  hook annotations (see app/tools/hooks.py).

Exports (:func:`export_rows`) stream the whole current view as CSV or JSON Lines; the raw
tool output is served as-is by the API.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import (
    ColumnElement,
    Float,
    Text,
    cast,
    exists,
    func,
    insert,
    literal_column,
    select,
    text,
)
from sqlalchemy.orm import Session

from app.models import ResultRow, Run

logger = logging.getLogger(__name__)

FTS_TABLE = "result_rows_fts"
FTS_MIN_QUERY = 3  # trigram index needs at least 3 characters
OPERATORS = (">=", "<=", "!=", ">", "<", "=")  # longest first
NUMERIC_TYPES = ("int", "float")


# --------------------------------------------------------------------------------- columns


def type_name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    return "json"


class ColumnTracker:
    """Collects column names in first-seen order and a merged type per column."""

    def __init__(self) -> None:
        self._types: dict[str, set[str]] = {}

    def add(self, data: dict[str, Any]) -> None:
        for key, value in data.items():
            self._types.setdefault(key, set()).add(type_name(value))

    def columns(self) -> list[dict[str, str]]:
        out = []
        for name, types in self._types.items():
            types = types - {"null"}
            if not types:
                merged = "null"
            elif types <= set(NUMERIC_TYPES):
                merged = "float" if "float" in types else "int"
            else:
                merged = next(iter(types)) if len(types) == 1 else "mixed"
            out.append({"name": name, "type": merged})
        return out


def column_names(run: Run) -> list[str]:
    return [c["name"] for c in run.columns or []]


def column_type(run: Run, name: str) -> str | None:
    return next((c["type"] for c in run.columns or [] if c["name"] == name), None)


# --------------------------------------------------------------------------------- index


def fts_text(data: dict[str, Any]) -> str:
    """Searchable text of a row: its values (not keys), nested values as JSON."""
    parts = []
    for value in data.values():
        if value is None:
            continue
        parts.append(value if isinstance(value, str) else json.dumps(value, ensure_ascii=False))
    return " | ".join(parts)


def index_rows(session: Session, rows: Iterable[tuple[int, dict[str, Any]]]) -> None:
    """Add (result_rows.id, data) pairs to the full-text index (caller's transaction)."""
    params = [{"rowid": row_id, "text": fts_text(data)} for row_id, data in rows]
    if params:
        session.execute(
            text(f"INSERT INTO {FTS_TABLE} (rowid, text) VALUES (:rowid, :text)"),  # noqa: S608
            params,
        )


def index_run(session: Session, run_id: int, batch: int = 5000) -> int:
    """(Re)build the full-text index for one run, e.g. a run stored before the index was enabled.
    Returns the number of rows indexed. Commits."""
    run = session.get(Run, run_id)
    if run is None:
        raise LookupError(f"run {run_id} not found")
    session.execute(
        text(
            f"DELETE FROM {FTS_TABLE} "  # noqa: S608 - constant table name
            "WHERE rowid IN (SELECT id FROM result_rows WHERE run_id = :r)"
        ),
        {"r": run_id},
    )
    count, last = 0, -1
    while True:
        chunk = session.execute(
            select(ResultRow.id, ResultRow.row_idx, ResultRow.data)
            .where(ResultRow.run_id == run_id, ResultRow.row_idx > last)
            .order_by(ResultRow.row_idx)
            .limit(batch)
        ).all()
        if not chunk:
            break
        index_rows(session, ((r.id, r.data or {}) for r in chunk))
        count += len(chunk)
        last = chunk[-1].row_idx
    run.search_indexed = True
    session.commit()
    return count


def store_rows(
    session: Session,
    run_id: int,
    parsed: Iterable[Any],
    *,
    search_index: bool,
    batch_size: int = 1000,
) -> int:
    """Insert parsed rows (objects with .data/.depth/.parent_idx) in batches, record the run's
    columns, and optionally index them. Runs in the caller's (uncommitted) transaction."""
    tracker = ColumnTracker()
    batch: list[dict[str, Any]] = []
    count = 0

    def flush() -> None:
        if not batch:
            return
        if search_index:
            ids = session.scalars(
                insert(ResultRow).returning(ResultRow.id, sort_by_parameter_order=True), batch
            ).all()
            index_rows(session, zip(ids, (b["data"] for b in batch), strict=True))
        else:
            session.execute(insert(ResultRow), batch)
        batch.clear()

    for idx, row in enumerate(parsed):
        tracker.add(row.data)
        batch.append(
            {
                "run_id": run_id,
                "row_idx": idx,
                "depth": row.depth,
                "parent_idx": row.parent_idx,
                "data": row.data,
            }
        )
        count += 1
        if len(batch) >= batch_size:
            flush()
    flush()
    run = session.get(Run, run_id)
    if run is not None:
        run.columns = tracker.columns()
        run.search_indexed = search_index
    return count


# --------------------------------------------------------------------------------- querying


@dataclass
class RowView:
    """What the user is looking at: search, filters, sort. Also drives exports."""

    q: str = ""
    annotated: bool = False
    tag: str = ""
    filters: dict[str, str] = field(default_factory=dict)
    sort: str = ""
    desc: bool = False

    @property
    def active(self) -> bool:
        return bool(self.q or self.annotated or self.tag or self.filters or self.sort)

    # URL/query-string form shared by the API, the UI and export links:
    #   q, tag ("*" = any annotated row), annotated=1, sort, desc=1, f.<column>=<expression>
    FILTER_PREFIX = "f."

    @classmethod
    def from_params(cls, params: Any) -> RowView:
        """Build from a mapping like request.query_params (unknown keys are ignored)."""

        def flag(name: str) -> bool:
            return str(params.get(name) or "").lower() in ("1", "true", "yes", "on")

        tag = (params.get("tag") or "").strip()
        return cls(
            q=(params.get("q") or "").strip(),
            annotated=flag("annotated") or tag == "*",
            tag="" if tag == "*" else tag,
            filters={
                k[len(cls.FILTER_PREFIX) :]: str(v).strip()
                for k, v in params.items()
                if k.startswith(cls.FILTER_PREFIX) and str(v).strip()
            },
            sort=(params.get("sort") or "").strip(),
            desc=flag("desc"),
        )

    def to_params(self, **overrides: Any) -> dict[str, Any]:
        """Inverse of from_params (only non-empty values), with overrides applied."""
        params: dict[str, Any] = {}
        if self.q:
            params["q"] = self.q
        if self.tag:
            params["tag"] = self.tag
        elif self.annotated:
            params["tag"] = "*"
        for column, expr in self.filters.items():
            params[self.FILTER_PREFIX + column] = expr
        if self.sort:
            params["sort"] = self.sort
        if self.desc:
            params["desc"] = 1
        for key, value in overrides.items():
            if value in (None, "", False):
                params.pop(key, None)
            else:
                params[key] = value
        return params

    def describe(self) -> dict[str, Any]:
        return {
            k: v
            for k, v in {
                "q": self.q,
                "annotated": self.annotated,
                "tag": self.tag,
                "filters": self.filters,
                "sort": self.sort,
                "desc": self.desc,
            }.items()
            if v
        }


def parse_filter(expr: str) -> tuple[str, str]:
    """``">=10"`` -> (">=", "10"); ``"svchost"`` -> ("contains", "svchost")."""
    expr = expr.strip()
    for op in OPERATORS:
        if expr.startswith(op):
            return op, expr[len(op) :].strip()
    return "contains", expr


def _json_path(column: str) -> str:
    if '"' in column:
        raise ValueError(f"unsupported column name {column!r}")
    return f'$."{column}"'


def _number(value: str) -> float | None:
    try:
        return float(value)
    except ValueError:
        return None


def _escape_like(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _filter_clause(run: Run, column: str, expr: str) -> ColumnElement[bool] | None:
    op, value = parse_filter(expr)
    if not value and op == "contains":
        return None
    field_ = func.json_extract(ResultRow.data, _json_path(column))
    number = _number(value)
    numeric = number is not None and (
        column_type(run, column) in NUMERIC_TYPES or op not in ("contains", "=", "!=")
    )
    if op == "contains":
        return cast(field_, Text).ilike(f"%{_escape_like(value)}%", escape="\\")
    target: Any = number if numeric else value
    lhs: Any = cast(field_, Float) if numeric else cast(field_, Text)
    return {
        "=": lhs == target,
        "!=": lhs != target,
        ">": lhs > target,
        ">=": lhs >= target,
        "<": lhs < target,
        "<=": lhs <= target,
    }[op]


def _where(run: Run, view: RowView) -> list[ColumnElement[bool]]:
    where: list[ColumnElement[bool]] = [ResultRow.run_id == run.id]
    if view.annotated or view.tag:
        where.append(ResultRow.annotations.is_not(None))
    if view.tag:
        where.append(
            exists(
                select(literal_column("1"))
                .select_from(func.json_each(ResultRow.annotations).table_valued("value"))
                .where(func.json_extract(literal_column("value"), "$.tag") == view.tag)
            )
        )
    q = view.q.strip()
    if q:
        if run.search_indexed and len(q) >= FTS_MIN_QUERY:
            phrase = '"' + q.replace('"', '""') + '"'
            where.append(
                ResultRow.id.in_(
                    select(literal_column("rowid"))
                    .select_from(text(FTS_TABLE))
                    .where(text(f"{FTS_TABLE} MATCH :fts_q").bindparams(fts_q=phrase))
                )
            )
        else:
            # The row is stored as JSON text, where e.g. a backslash is written as "\\".
            # Search for the JSON-escaped form so Windows paths match.
            escaped = json.dumps(q)[1:-1]
            pattern = f"%{_escape_like(escaped)}%"
            where.append(cast(ResultRow.data, Text).ilike(pattern, escape="\\"))
    known = set(column_names(run))
    for column, expr in view.filters.items():
        if column in known and expr.strip():
            clause = _filter_clause(run, column, expr)
            if clause is not None:
                where.append(clause)
    return where


def _order_by(run: Run, view: RowView) -> list[Any]:
    if view.sort and view.sort in column_names(run):
        key: Any = func.json_extract(ResultRow.data, _json_path(view.sort))
        if column_type(run, view.sort) in NUMERIC_TYPES:
            key = cast(key, Float)
        else:
            key = key.collate("NOCASE")  # analysts expect "smss.exe" before "System"
        key = key.desc() if view.desc else key.asc()
        return [key.nulls_last(), ResultRow.row_idx]
    return [ResultRow.row_idx.desc() if view.desc else ResultRow.row_idx]


def query_rows(
    session: Session, run: Run, view: RowView, offset: int = 0, limit: int = 100
) -> tuple[list[ResultRow], int]:
    """One page of the view and the total number of matching rows."""
    where = _where(run, view)
    total = session.scalar(select(func.count()).select_from(ResultRow).where(*where)) or 0
    rows = session.scalars(
        select(ResultRow)
        .where(*where)
        .order_by(*_order_by(run, view))
        .offset(max(offset, 0))
        .limit(max(limit, 0))
    )
    return list(rows), total


def iter_view(session: Session, run: Run, view: RowView, batch: int = 2000) -> Iterator[ResultRow]:
    """All rows of the view in order, streamed in batches (for exports)."""
    stmt = select(ResultRow).where(*_where(run, view)).order_by(*_order_by(run, view))
    yield from session.scalars(stmt.execution_options(yield_per=batch))


# --------------------------------------------------------------------------------- exports

# Cells starting with these are treated as formulas by Excel/LibreOffice ("CSV injection").
# Evidence strings are attacker-controlled, so such cells are prefixed with an apostrophe.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        text_value = "true" if value else "false"
    elif isinstance(value, int | float):
        return str(value)  # numbers (including negative ones) are safe and stay numeric
    elif isinstance(value, str):
        text_value = value
    else:
        text_value = json.dumps(value, ensure_ascii=False)
    if text_value.startswith(_FORMULA_PREFIXES):
        return "'" + text_value
    return text_value


def _flags(row: ResultRow) -> str:
    return "; ".join(
        f"{a.get('tag')} ({a.get('severity')})" + (f": {a['note']}" if a.get("note") else "")
        for a in row.annotations or []
    )


def export_rows(session: Session, run: Run, view: RowView, fmt: str) -> Iterator[str]:
    """Stream the view as ``csv`` or ``jsonl`` text chunks."""
    columns = column_names(run)
    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["citation", "row_idx", "depth", "parent_idx", *columns, "flags"])
        for i, row in enumerate(iter_view(session, run, view)):
            writer.writerow(
                [
                    f"R{run.id}:{row.row_idx}",
                    row.row_idx,
                    row.depth,
                    "" if row.parent_idx is None else row.parent_idx,
                    *(_csv_cell((row.data or {}).get(c)) for c in columns),
                    _csv_cell(_flags(row)),
                ]
            )
            if i % 500 == 499:
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate()
        yield buf.getvalue()
    elif fmt == "jsonl":
        for row in iter_view(session, run, view):
            yield (
                json.dumps(
                    {
                        "citation": f"R{run.id}:{row.row_idx}",
                        "row_idx": row.row_idx,
                        "depth": row.depth,
                        "parent_idx": row.parent_idx,
                        "data": row.data,
                        "annotations": row.annotations,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
    else:
        raise ValueError("format must be csv or jsonl")
