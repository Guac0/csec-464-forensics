"""Evaluation case files (YAML) and their validation.

A case describes a small investigation: recorded tool output (fixtures), optional analyst notes,
one question (or "summarize run N"), and what a good answer must contain. Row references in
expectations use ``"<run index>:<row index>"``, where the run index is the position in ``runs``
(0-based); they are turned into real citation keys (``R<run id>:<row>``) when the case is loaded
into a scratch database.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
CASES_DIR = Path(__file__).resolve().parent / "cases"


class CaseError(ValueError):
    """A case file is malformed."""


@dataclass(frozen=True)
class CaseRun:
    plugin: str
    fixture: Path  # recorded `vol -r jsonl` output
    args: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Expectations:
    cite_rows: tuple[tuple[int, int], ...] = ()  # (run index, row index)
    must_mention: tuple[str, ...] = ()  # case-insensitive substrings
    must_not_mention: tuple[str, ...] = ()
    suggest_plugins: tuple[str, ...] = ()  # at least one valid suggestion uses one of these
    min_citations: int = 0


@dataclass(frozen=True)
class Case:
    id: str
    path: Path
    description: str
    runs: tuple[CaseRun, ...]
    question: str | None
    summarize_run: int | None
    expect: Expectations
    notes: tuple[str, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)  # rel_path, description, os_info
    rubric: str | None = None  # for the optional AI judge
    tags: tuple[str, ...] = ()


_TOP_KEYS = {
    "id", "description", "runs", "question", "summarize_run", "expect", "notes", "evidence",
    "judge", "tags",
}  # fmt: skip
_EXPECT_KEYS = {"cite_rows", "must_mention", "must_not_mention", "suggest_plugins", "min_citations"}


def _strs(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise CaseError(f"{where} must be a list of strings")
    return tuple(value)


def _row_ref(value: Any, n_runs: int, where: str) -> tuple[int, int]:
    try:
        run_s, row_s = str(value).split(":")
        ref = (int(run_s), int(row_s))
    except ValueError as exc:
        raise CaseError(f"{where}: row reference {value!r} must look like '0:12'") from exc
    if not 0 <= ref[0] < n_runs or ref[1] < 0:
        raise CaseError(f"{where}: row reference {value!r} is out of range")
    return ref


def parse_case(data: Any, path: Path) -> Case:
    where = path.name
    if not isinstance(data, dict):
        raise CaseError(f"{where}: top level must be a mapping")
    unknown = set(data) - _TOP_KEYS
    if unknown:
        raise CaseError(f"{where}: unknown keys {sorted(unknown)}")
    case_id = data.get("id") or path.stem
    raw_runs = data.get("runs")
    if not isinstance(raw_runs, list) or not raw_runs:
        raise CaseError(f"{where}: 'runs' must be a non-empty list")
    runs = []
    for i, r in enumerate(raw_runs):
        if not isinstance(r, dict) or "plugin" not in r or "fixture" not in r:
            raise CaseError(f"{where}: runs[{i}] needs 'plugin' and 'fixture'")
        fixture = (REPO_ROOT / r["fixture"]).resolve()
        if not fixture.is_file():
            raise CaseError(f"{where}: runs[{i}] fixture not found: {r['fixture']}")
        runs.append(CaseRun(str(r["plugin"]), fixture, dict(r.get("args") or {})))
    question, summarize = data.get("question"), data.get("summarize_run")
    if (question is None) == (summarize is None):
        raise CaseError(f"{where}: give exactly one of 'question' or 'summarize_run'")
    if summarize is not None and not (isinstance(summarize, int) and 0 <= summarize < len(runs)):
        raise CaseError(f"{where}: 'summarize_run' must be a run index")
    raw_expect = data.get("expect") or {}
    if not isinstance(raw_expect, dict) or set(raw_expect) - _EXPECT_KEYS:
        raise CaseError(f"{where}: 'expect' may only contain {sorted(_EXPECT_KEYS)}")
    expect = Expectations(
        cite_rows=tuple(
            _row_ref(v, len(runs), f"{where} expect.cite_rows")
            for v in raw_expect.get("cite_rows") or []
        ),
        must_mention=_strs(raw_expect.get("must_mention"), f"{where} expect.must_mention"),
        must_not_mention=_strs(
            raw_expect.get("must_not_mention"), f"{where} expect.must_not_mention"
        ),
        suggest_plugins=_strs(raw_expect.get("suggest_plugins"), f"{where} expect.suggest_plugins"),
        min_citations=int(raw_expect.get("min_citations") or 0),
    )
    judge = data.get("judge") or {}
    return Case(
        id=str(case_id),
        path=path,
        description=str(data.get("description") or ""),
        runs=tuple(runs),
        question=str(question) if question is not None else None,
        summarize_run=summarize,
        expect=expect,
        notes=_strs(data.get("notes"), f"{where} notes"),
        evidence=dict(data.get("evidence") or {}),
        rubric=str(judge["rubric"]) if isinstance(judge, dict) and judge.get("rubric") else None,
        tags=_strs(data.get("tags"), f"{where} tags"),
    )


def load_cases(selectors: list[str] | None = None, cases_dir: Path = CASES_DIR) -> list[Case]:
    """All *.yaml cases (sorted by id), optionally filtered by id or tag."""
    cases = []
    ids: set[str] = set()
    for path in sorted(cases_dir.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise CaseError(f"{path.name}: invalid YAML: {exc}") from exc
        case = parse_case(data, path)
        if case.id in ids:
            raise CaseError(f"duplicate case id {case.id!r} ({path.name})")
        ids.add(case.id)
        cases.append(case)
    if selectors:
        wanted = set(selectors)
        cases = [c for c in cases if c.id in wanted or wanted & set(c.tags)]
    return sorted(cases, key=lambda c: c.id)
