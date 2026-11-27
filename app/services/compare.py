"""Before/after comparison of the same plugin's results on two images of a case.

Rows have no shared identity across captures (PIDs, offsets and times change), so rows are
paired by KEY columns: the catalog's ``compare_keys`` for the plugin by default, or what the
analyst picks; without catalog keys, every common column that is not volatile. Rows with the
same key values are "the same thing"; within such a group:

- rows whose other compared columns are identical in both images are **same**,
- remaining rows are paired up in order as **changed** (with the columns that differ),
- what is left over is **only in A** / **only in B**.

Volatile columns (built-in list + the catalog's ``compare_ignore``) are ignored both as keys and
when deciding whether a row changed. The analyst can override keys and ignored columns.

Nothing is stored or written to either image: a comparison reads both runs' rows. Saving it to
the case (``save``) stores only its settings and counts.
"""

from __future__ import annotations

import csv
import io
import json
from collections import defaultdict, deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.models import CaseEvidence, Evidence, ResultRow, Run, RunStatus, SavedComparison
from app.services import audit, results

# Column names (case-insensitive) that change between captures of the same system.
VOLATILE = frozenset(
    {
        "pid", "ppid", "tid", "offset", "offset(v)", "offset(p)", "base", "createtime",
        "exittime", "threads", "handles", "sessionid", "file output", "physical", "virtual",
        "created", "lastwritetime",
    }
)  # fmt: skip
DISPLAY_LIMIT = 200


class CompareError(ValueError):
    """The comparison cannot be made (wrong runs, images not in the case, no key columns)."""


@dataclass
class Comparison:
    run_a: Run
    run_b: Run
    keys: list[str]
    compared: list[str]
    ignored: list[str]
    only_a: list[int] = field(default_factory=list)  # row_idx in run A
    only_b: list[int] = field(default_factory=list)
    changed: list[tuple[int, int, list[str]]] = field(default_factory=list)  # (a, b, columns)
    same: int = 0
    warnings: list[str] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        return {
            "only_a": len(self.only_a),
            "only_b": len(self.only_b),
            "changed": len(self.changed),
            "same": self.same,
        }


# --------------------------------------------------------------------------------- choosing


def runs_for(session: Session, evidence_id: int, plugin: str) -> list[Run]:
    """Succeeded, not deleted runs of ``plugin`` on an image, newest first."""
    return list(
        session.scalars(
            select(Run)
            .where(
                Run.evidence_id == evidence_id,
                Run.plugin == plugin,
                Run.status == RunStatus.SUCCEEDED,
                Run.deleted_at.is_(None),
            )
            .order_by(Run.id.desc())
        )
    )


def comparable_plugins(session: Session, evidence_a: int, evidence_b: int) -> list[str]:
    """Plugins with at least one usable run on both images."""

    def plugins(ev: int) -> set[str]:
        return set(
            session.scalars(
                select(Run.plugin).where(
                    Run.evidence_id == ev,
                    Run.status == RunStatus.SUCCEEDED,
                    Run.deleted_at.is_(None),
                )
            )
        )

    return sorted(plugins(evidence_a) & plugins(evidence_b))


def _spec(plugin: str, tool: str = "volatility3") -> Any:
    from app.tools import registry

    try:
        return registry.get_runner(tool).get_plugin(plugin)
    except Exception:
        return None


def common_columns(run_a: Run, run_b: Run) -> list[str]:
    b = set(results.column_names(run_b))
    return [c for c in results.column_names(run_a) if c in b]


def default_settings(run_a: Run, run_b: Run) -> tuple[list[str], list[str]]:
    """(keys, ignored) from the catalog and the built-in volatile list."""
    spec = _spec(run_a.plugin, run_a.tool)
    common = common_columns(run_a, run_b)
    extra_ignore = set(spec.compare_ignore) if spec else set()
    ignored = [c for c in common if c.casefold() in VOLATILE or c in extra_ignore]
    catalog_keys = [k for k in (spec.compare_keys if spec else ()) if k in common]
    keys = catalog_keys or [c for c in common if c not in ignored]
    return keys, [c for c in ignored if c not in keys]


# --------------------------------------------------------------------------------- compute


def _json_path(column: str) -> str:
    return '$."' + column.replace('"', '\\"') + '"'


def _signatures(
    session: Session, run_id: int, keys: list[str], compared: list[str]
) -> Iterator[tuple[int, str, str]]:
    """(row_idx, key JSON, compared-values JSON) for every row, computed in SQLite so big runs
    don't have to be loaded as Python dicts."""
    params: dict[str, Any] = {"run": run_id}

    def array(cols: list[str], prefix: str) -> str:
        if not cols:
            return "'[]'"
        parts = []
        for i, c in enumerate(cols):
            params[f"{prefix}{i}"] = _json_path(c)
            parts.append(f"json_extract(data, :{prefix}{i})")
        return f"json_array({', '.join(parts)})"

    sql = (
        f"SELECT row_idx, {array(keys, 'k')} AS k, {array(compared, 'c')} AS c "  # noqa: S608
        "FROM result_rows WHERE run_id = :run ORDER BY row_idx"
    )
    yield from session.execute(text(sql), params)


def compare(
    session: Session,
    run_a: Run,
    run_b: Run,
    keys: list[str] | None = None,
    ignore: list[str] | None = None,
) -> Comparison:
    if run_a.plugin != run_b.plugin:
        raise CompareError("both runs must be of the same plugin")
    for run in (run_a, run_b):
        if run.status != RunStatus.SUCCEEDED or run.deleted_at is not None:
            raise CompareError(f"run {run.id} has no results to compare (not succeeded or deleted)")
    default_keys, default_ignore = default_settings(run_a, run_b)
    common = common_columns(run_a, run_b)
    keys = [k for k in (keys if keys else default_keys) if k in common]
    ignored = [c for c in (ignore if ignore is not None else default_ignore) if c in common]
    ignored = [c for c in ignored if c not in keys]
    if not keys:
        raise CompareError("choose at least one column that identifies a row")
    compared = [c for c in common if c not in keys and c not in ignored]
    cmp = Comparison(run_a, run_b, keys, compared, ignored)
    if run_a.args != run_b.args:
        cmp.warnings.append(
            f"the runs used different arguments ({json.dumps(run_a.args)} vs "
            f"{json.dumps(run_b.args)}): differences may come from that"
        )
    if run_a.tool_version != run_b.tool_version:
        cmp.warnings.append(
            f"different tool versions ({run_a.tool_version} vs {run_b.tool_version})"
        )
    only_cols = sorted(set(results.column_names(run_a)) ^ set(results.column_names(run_b)))
    if only_cols:
        cmp.warnings.append(f"columns present in only one run are not compared: {only_cols}")

    groups: dict[str, tuple[list[tuple[int, str]], list[tuple[int, str]]]] = {}
    for side, run in ((0, run_a), (1, run_b)):
        for row_idx, k, c in _signatures(session, run.id, keys, compared):
            groups.setdefault(k, ([], []))[side].append((row_idx, c))

    for rows_a, rows_b in groups.values():
        b_by_sig: dict[str, deque[int]] = defaultdict(deque)
        for idx_b, sig_b in rows_b:
            b_by_sig[sig_b].append(idx_b)
        matched_b: set[int] = set()
        left_a: list[tuple[int, str]] = []
        for idx_a, sig_a in rows_a:
            queue = b_by_sig.get(sig_a)
            if queue:
                matched_b.add(queue.popleft())
                cmp.same += 1
            else:
                left_a.append((idx_a, sig_a))
        remaining_b = [(i, s) for i, s in rows_b if i not in matched_b]
        for (idx_a, sig_a), (idx_b, sig_b) in zip(left_a, remaining_b, strict=False):
            va, vb = json.loads(sig_a), json.loads(sig_b)
            diff = [col for col, x, y in zip(compared, va, vb, strict=True) if x != y]
            cmp.changed.append((idx_a, idx_b, diff))
        n = min(len(left_a), len(remaining_b))
        cmp.only_a += [i for i, _ in left_a[n:]]
        cmp.only_b += [i for i, _ in remaining_b[n:]]
    cmp.only_a.sort()
    cmp.only_b.sort()
    cmp.changed.sort()
    return cmp


def rows(session: Session, run_id: int, idxs: list[int]) -> dict[int, dict[str, Any]]:
    """Full data of some rows (for display), {row_idx: data}."""
    if not idxs:
        return {}
    return {
        r.row_idx: r.data
        for r in session.scalars(
            select(ResultRow).where(ResultRow.run_id == run_id, ResultRow.row_idx.in_(idxs))
        )
    }


# --------------------------------------------------------------------------------- scope


def check_scope(session: Session, case_id: int, run_a: Run, run_b: Run) -> None:
    """Both runs must belong to (different or same) images of this case."""
    for run in (run_a, run_b):
        if session.get(CaseEvidence, (case_id, run.evidence_id)) is None:
            raise CompareError(f"the image of run {run.id} is not in this case")


def get_run(session: Session, run_id: int | None) -> Run:
    run = session.get(Run, run_id) if run_id else None
    if run is None:
        raise LookupError(f"run {run_id} not found")
    return run


# --------------------------------------------------------------------------------- export


def to_csv(session: Session, cmp: Comparison) -> str:
    """Every difference as CSV: category, image, row, key values, differing columns."""
    ev_a = session.get(Evidence, cmp.run_a.evidence_id)
    ev_b = session.get(Evidence, cmp.run_b.evidence_id)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["category", "image", "row", *cmp.keys, "differences"])

    def cell(v: Any) -> str:
        return results._csv_cell(v)  # same formula-injection escaping as run exports

    data_a = rows(session, cmp.run_a.id, cmp.only_a + [a for a, _, _ in cmp.changed])
    data_b = rows(session, cmp.run_b.id, cmp.only_b + [b for _, b, _ in cmp.changed])
    for idx in cmp.only_a:
        d = data_a.get(idx, {})
        w.writerow(
            [
                "only_a",
                ev_a.rel_path,
                f"R{cmp.run_a.id}:{idx}",
                *[cell(d.get(k)) for k in cmp.keys],
                "",
            ]
        )
    for idx in cmp.only_b:
        d = data_b.get(idx, {})
        w.writerow(
            [
                "only_b",
                ev_b.rel_path,
                f"R{cmp.run_b.id}:{idx}",
                *[cell(d.get(k)) for k in cmp.keys],
                "",
            ]
        )
    for a, b, cols in cmp.changed:
        da, db = data_a.get(a, {}), data_b.get(b, {})
        diffs = "; ".join(f"{c}: {da.get(c)} -> {db.get(c)}" for c in cols)
        w.writerow(
            [
                "changed",
                f"{ev_a.rel_path} / {ev_b.rel_path}",
                f"R{cmp.run_a.id}:{a} / R{cmp.run_b.id}:{b}",
                *[cell(da.get(k)) for k in cmp.keys],
                cell(diffs),
            ]
        )
    return buf.getvalue()


# --------------------------------------------------------------------------------- saved


def save(
    session: Session,
    case_id: int,
    cmp: Comparison,
    title: str = "",
    comment: str = "",
) -> SavedComparison:
    check_scope(session, case_id, cmp.run_a, cmp.run_b)
    ev_a = session.get(Evidence, cmp.run_a.evidence_id)
    ev_b = session.get(Evidence, cmp.run_b.evidence_id)
    title = (title or "").strip() or (
        f"{cmp.run_a.plugin.rsplit('.', 1)[-1]}: {ev_a.rel_path} vs {ev_b.rel_path}"
    )
    saved = SavedComparison(
        case_id=case_id,
        title=title[:200],
        plugin=cmp.run_a.plugin,
        evidence_a_id=cmp.run_a.evidence_id,
        evidence_b_id=cmp.run_b.evidence_id,
        run_a_id=cmp.run_a.id,
        run_b_id=cmp.run_b.id,
        keys=list(cmp.keys),
        ignore=list(cmp.ignored),
        counts=cmp.counts,
        comment=(comment or "").strip()[:2000],
        created_by=audit.current_context().actor,
    )
    session.add(saved)
    session.flush()
    audit.record(
        session,
        "comparison.save",
        object_type="case",
        object_id=case_id,
        summary=f"Saved comparison {saved.id} to case {case_id}: {title}",
        details={
            "comparison_id": saved.id,
            "run_a": cmp.run_a.id,
            "run_b": cmp.run_b.id,
            "keys": cmp.keys,
            "ignore": cmp.ignored,
            "counts": cmp.counts,
        },
    )
    session.commit()
    return saved


def list_saved(session: Session, case_id: int) -> list[SavedComparison]:
    return list(
        session.scalars(
            select(SavedComparison)
            .where(SavedComparison.case_id == case_id)
            .order_by(SavedComparison.id)
        )
    )


def delete_saved(session: Session, comparison_id: int) -> int:
    saved = session.get(SavedComparison, comparison_id)
    if saved is None:
        raise LookupError(f"comparison {comparison_id} not found")
    case_id = saved.case_id
    audit.record(
        session,
        "comparison.delete",
        object_type="case",
        object_id=case_id,
        summary=f"Deleted saved comparison {comparison_id}: {saved.title}",
    )
    session.delete(saved)
    session.commit()
    return case_id


def recompute(session: Session, saved: SavedComparison) -> Comparison | str:
    """The saved comparison with current data, or why it can't be recomputed."""
    try:
        run_a, run_b = get_run(session, saved.run_a_id), get_run(session, saved.run_b_id)
        return compare(session, run_a, run_b, saved.keys, saved.ignore)
    except (LookupError, CompareError) as exc:
        return str(exc)


def url(case_id: int, cmp_or_saved: Any) -> str:
    """Comparison page URL with all settings (bookmarkable)."""
    from urllib.parse import urlencode

    if isinstance(cmp_or_saved, SavedComparison):
        s = cmp_or_saved
        run_a, run_b, keys, ignore = s.run_a_id, s.run_b_id, s.keys, s.ignore
    else:
        c = cmp_or_saved
        run_a, run_b, keys, ignore = c.run_a.id, c.run_b.id, c.keys, c.ignored
    params: list[tuple[str, Any]] = [("run_a", run_a), ("run_b", run_b), ("custom", 1)]
    params += [("keys", k) for k in keys] + [("ignore", i) for i in ignore]
    return f"/cases/{case_id}/compare?{urlencode(params)}"
