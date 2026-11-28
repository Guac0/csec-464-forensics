"""Recommended next plugins for one image, from the tool's investigation guide.

Deterministic and offline: no AI. The guide content lives in app/tools/volatility/guide.py;
this module applies it to an image's runs:

- BASELINE steps not yet queued/running/succeeded, in guide order;
- NEXT steps of every succeeded run whose condition holds (merged when several runs suggest the
  same step; ranked by priority, then number of suggesting runs);
- minus steps the analyst dismissed for this image, and steps for another OS.

A step is identified by tool + plugin + normalised args (``step_key``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import DismissedRecommendation, Evidence, ResultRow, Run, RunOrigin, RunStatus
from app.services import audit
from app.services import runs as runs_svc
from app.services.evidence import get_evidence
from app.tools import registry
from app.tools.base import (
    WHEN_HAS_FLAGS,
    WHEN_HAS_ROWS,
    WHEN_SUCCEEDED,
    WHEN_TAG_PREFIX,
    GuideStep,
    ToolRequest,
)
from app.tools.guide import args_key, check_guide

DEFAULT_SHOWN = 5
# A step is "done" while one of these runs exists; failed/cancelled/interrupted ones keep it.
_DONE_STATUSES = (RunStatus.QUEUED, RunStatus.RUNNING, RunStatus.SUCCEEDED)
_OS_PREFIXES = ("windows", "linux", "mac")


def step_key(tool: str, plugin: str, args: dict[str, Any]) -> str:
    return f"{tool}|{plugin}|{args_key(args)}"


@dataclass
class Recommendation:
    tool: str
    plugin: str
    args: dict[str, Any]
    key: str
    baseline_pos: int | None = None  # 1-based position in the baseline, if a baseline step
    reasons: list[str] = field(default_factory=list)
    # Runs that suggested it: [{"run_id", "plugin", "when"}]
    sources: list[dict[str, Any]] = field(default_factory=list)
    priority: int = 0
    last_failed_run_id: int | None = None  # a previous attempt failed/cancelled/interrupted
    writes_files: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "plugin": self.plugin,
            "args": self.args,
            "key": self.key,
            "kind": "baseline" if self.baseline_pos else "next",
            "baseline_pos": self.baseline_pos,
            "reasons": self.reasons,
            "sources": self.sources,
            "priority": self.priority,
            "last_failed_run_id": self.last_failed_run_id,
            "writes_files": self.writes_files,
        }


@dataclass
class Recommendations:
    evidence_id: int
    tool: str
    items: list[Recommendation]  # active recommendations, best first
    dismissed: list[Recommendation]
    baseline_total: int  # baseline steps for this image's OS
    baseline_done: int  # ... of which queued/running/succeeded
    identified: bool  # an auto-enumerate plugin succeeded, or the OS is known
    guide_problems: int  # invalid guide steps (skipped)

    def as_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "tool": self.tool,
            "items": [r.as_dict() for r in self.items],
            "dismissed": [r.as_dict() for r in self.dismissed],
            "baseline_total": self.baseline_total,
            "baseline_done": self.baseline_done,
            "identified": self.identified,
            "guide_problems": self.guide_problems,
        }


def _image_os(ev: Evidence) -> str | None:
    os_name = str((ev.os_info or {}).get("os") or "").lower()
    return os_name if os_name in _OS_PREFIXES else None


def _other_os(plugin: str, image_os: str | None) -> bool:
    prefix = plugin.split(".", 1)[0].lower()
    return image_os is not None and prefix in _OS_PREFIXES and prefix != image_os


class _Conditions:
    """Evaluates NEXT-step conditions on a run, querying rows only when needed (cached)."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self._flags: dict[int, bool] = {}
        self._tags: dict[int, set[str]] = {}

    def holds(self, run: Run, when: str) -> bool:
        if when == WHEN_SUCCEEDED:
            return True
        if when == WHEN_HAS_ROWS:
            return (run.row_count or 0) > 0
        if when == WHEN_HAS_FLAGS:
            if run.id not in self._flags:
                self._flags[run.id] = (
                    self.session.scalar(
                        select(ResultRow.id)
                        .where(ResultRow.run_id == run.id, ResultRow.annotations.is_not(None))
                        .limit(1)
                    )
                    is not None
                )
            return self._flags[run.id]
        if when.startswith(WHEN_TAG_PREFIX):
            if run.id not in self._tags:
                self._tags[run.id] = {t for t, _ in runs_svc.annotation_tags(self.session, run.id)}
            return when[len(WHEN_TAG_PREFIX) :] in self._tags[run.id]
        return False


def recommend(session: Session, evidence_id: int, tool: str = "volatility3") -> Recommendations:
    ev = get_evidence(session, evidence_id)
    runner = registry.get_runner(tool)
    guide, problems = check_guide(runner)
    specs = {p.name: p for p in runner.plugins()}
    image_os = _image_os(ev)
    runs = list(
        session.scalars(
            select(Run)
            .where(Run.evidence_id == evidence_id, Run.tool == tool, Run.deleted_at.is_(None))
            .order_by(Run.id)
        )
    )
    done: set[str] = set()
    failed: dict[str, int] = {}
    for run in runs:
        key = step_key(tool, run.plugin, run.args or {})
        if run.status in _DONE_STATUSES:
            done.add(key)
        else:
            failed[key] = run.id  # latest failed attempt (runs are in id order)
    dismissed_keys = set(
        session.scalars(
            select(DismissedRecommendation.key).where(
                DismissedRecommendation.evidence_id == evidence_id
            )
        )
    )
    auto = {name for name, spec in specs.items() if spec.auto_enumerate}
    identified = image_os is not None or any(
        r.plugin in auto and r.status == RunStatus.SUCCEEDED for r in runs
    )

    found: dict[str, Recommendation] = {}

    def add(step: GuideStep) -> Recommendation:
        key = step_key(tool, step.plugin, step.args)
        rec = found.get(key)
        if rec is None:
            spec = specs.get(step.plugin)
            writes = bool(spec and spec.writes_files) or any(
                a.writes_files and step.args.get(a.name) for a in (spec.args if spec else ())
            )
            rec = found[key] = Recommendation(
                tool, step.plugin, step.args, key, writes_files=writes
            )
        if step.reason not in rec.reasons:
            rec.reasons.append(step.reason)
        rec.priority = max(rec.priority, step.priority)
        return rec

    baseline = [s for s in guide.baseline if not _other_os(s.plugin, image_os)]
    baseline_done = 0
    for pos, step in enumerate(baseline, start=1):
        key = step_key(tool, step.plugin, step.args)
        if key in done:
            baseline_done += 1
            continue
        add(step).baseline_pos = pos

    conditions = _Conditions(session)
    for run in runs:
        if run.status != RunStatus.SUCCEEDED:
            continue
        for step in guide.next.get(run.plugin, ()):
            if _other_os(step.plugin, image_os) or not conditions.holds(run, step.when):
                continue
            if step_key(tool, step.plugin, step.args) in done:
                continue
            add(step).sources.append({"run_id": run.id, "plugin": run.plugin, "when": step.when})

    for key, rec in found.items():
        rec.last_failed_run_id = failed.get(key)

    def rank(rec: Recommendation) -> tuple[Any, ...]:
        if rec.baseline_pos is not None:  # baseline first, in guide order
            return (0, rec.baseline_pos, 0, 0, "")
        return (1, -rec.priority, -len(rec.sources), -max(s["run_id"] for s in rec.sources), "")

    ordered = sorted(found.values(), key=rank)
    return Recommendations(
        evidence_id=evidence_id,
        tool=tool,
        items=[r for r in ordered if r.key not in dismissed_keys],
        dismissed=[r for r in ordered if r.key in dismissed_keys],
        baseline_total=len(baseline),
        baseline_done=baseline_done,
        identified=identified,
        guide_problems=len(problems),
    )


def _normalise(tool: str, plugin: str, args: dict[str, Any]) -> dict[str, Any]:
    """Validated args (ArgValidationError for anything not allowlisted)."""
    return registry.get_runner(tool).validate(ToolRequest(plugin=plugin, args=args))


def dismiss(
    session: Session, evidence_id: int, plugin: str, args: dict[str, Any], tool: str = "volatility3"
) -> bool:
    """Hide a recommendation on this image. False if it was already dismissed."""
    get_evidence(session, evidence_id)
    args = _normalise(tool, plugin, args)
    key = step_key(tool, plugin, args)
    row = DismissedRecommendation(
        evidence_id=evidence_id,
        key=key,
        tool=tool,
        plugin=plugin,
        args=args,
        created_by=audit.current_context().actor,
    )
    session.add(row)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        return False
    audit.record(
        session,
        "recommendation.dismiss",
        object_type="evidence",
        object_id=evidence_id,
        evidence_id=evidence_id,
        summary=f"Dismissed recommendation {plugin} {args_key(args)}",
        details={"tool": tool, "plugin": plugin, "args": args},
    )
    session.commit()
    return True


def restore(
    session: Session, evidence_id: int, plugin: str, args: dict[str, Any], tool: str = "volatility3"
) -> bool:
    """Show a dismissed recommendation again. False if it was not dismissed."""
    args = _normalise(tool, plugin, args)
    row = session.scalar(
        select(DismissedRecommendation).where(
            DismissedRecommendation.evidence_id == evidence_id,
            DismissedRecommendation.key == step_key(tool, plugin, args),
        )
    )
    if row is None:
        return False
    session.delete(row)
    audit.record(
        session,
        "recommendation.restore",
        object_type="evidence",
        object_id=evidence_id,
        evidence_id=evidence_id,
        summary=f"Restored recommendation {plugin} {args_key(args)}",
        details={"tool": tool, "plugin": plugin, "args": args},
    )
    session.commit()
    return True


def run_recommendation(
    session: Session, evidence_id: int, plugin: str, args: dict[str, Any], tool: str = "volatility3"
) -> Run:
    """Queue one recommendation (origin 'recommended'). Same errors as runs.create_run."""
    return runs_svc.create_run(
        session, evidence_id, ToolRequest(plugin=plugin, args=args), RunOrigin.RECOMMENDED, tool
    )


def run_baseline(session: Session, evidence_id: int, tool: str = "volatility3") -> list[Run]:
    """Queue every remaining (not dismissed) baseline step, in order."""
    from app.services import resources

    resources.check_can_start_run()  # all or nothing: don't queue half a baseline
    recs = recommend(session, evidence_id, tool)
    created = [
        run_recommendation(session, evidence_id, r.plugin, r.args, tool)
        for r in recs.items
        if r.baseline_pos is not None
    ]
    audit.record(
        session,
        "evidence.run_baseline",
        object_type="evidence",
        object_id=evidence_id,
        evidence_id=evidence_id,
        summary=f"Queued {len(created)} remaining baseline step(s)",
        details={"run_ids": [r.id for r in created]},
    )
    session.commit()
    return created
