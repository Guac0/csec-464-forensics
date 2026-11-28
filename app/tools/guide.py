"""Checking and printing a tool's investigation guide (content: ``baseline`` / ``next`` in the
plugin files under forensics/plugins/, loaded by app/tools/content.py). CLI:
``python -m app.tools.guide``.

Tool-agnostic: works on ``ToolRunner.guide()``. The recommendations themselves (which steps to
show for an image) are computed in app/services/recommendations.py.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, replace
from typing import Any

from app.tools.base import (
    WHEN_CONDITIONS,
    WHEN_SUCCEEDED,
    WHEN_TAG_PREFIX,
    ArgValidationError,
    GuideStep,
    InvestigationGuide,
    ToolRequest,
    ToolRunner,
)

MAX_REASON = 200

WHEN_TEXT = {
    "succeeded": "succeeded",
    "has_rows": "returned rows",
    "has_flags": "has rows flagged by a hook",
}


@dataclass(frozen=True)
class GuideProblem:
    where: str  # e.g. "BASELINE #2 (forensics/plugins/windows/pslist.py)"
    plugin: str
    problem: str

    def __str__(self) -> str:
        return f"{self.where} ({self.plugin}): {self.problem}"


def describe_when(when: str) -> str:
    """Human-readable condition, e.g. 'has rows tagged suspicious-parent'."""
    if when.startswith(WHEN_TAG_PREFIX):
        return f"has rows tagged {when[len(WHEN_TAG_PREFIX) :]!r}"
    return WHEN_TEXT.get(when, when)


def args_key(args: dict[str, Any]) -> str:
    return json.dumps(args, sort_keys=True, separators=(",", ":"))


def _check_step(
    runner: ToolRunner, plugins: set[str], step: Any, baseline: bool
) -> tuple[list[str], GuideStep | None]:
    """(problems, step with normalised args or None if invalid)."""
    if not isinstance(step, GuideStep):
        return [f"not a Step(...): {step!r}"], None
    errs: list[str] = []
    if step.plugin not in plugins:
        errs.append("unknown plugin: not in the catalog (or skipped there as invalid)")
    if not isinstance(step.reason, str) or not step.reason.strip():
        errs.append("reason is required (one short sentence for the analyst)")
    elif len(step.reason) > MAX_REASON:
        errs.append(f"reason is too long ({len(step.reason)} > {MAX_REASON} characters)")
    if not isinstance(step.priority, int) or isinstance(step.priority, bool):
        errs.append("priority must be an integer")
    when = step.when
    if baseline:
        if when != WHEN_SUCCEEDED:
            errs.append("'when' only applies to NEXT steps")
        if step.priority != 0:
            errs.append("'priority' only applies to NEXT steps (the baseline keeps its order)")
    elif not isinstance(when, str) or not (
        when in WHEN_CONDITIONS
        or (when.startswith(WHEN_TAG_PREFIX) and when[len(WHEN_TAG_PREFIX) :].strip())
    ):
        errs.append(f"unknown 'when' {when!r}: use {', '.join(WHEN_CONDITIONS)} or 'tag:<tag>'")
    normalized: dict[str, Any] | None = None
    if not isinstance(step.args, dict):
        errs.append("args must be a dict, e.g. {'pid': [4]}")
    elif step.plugin in plugins:
        try:
            normalized = runner.validate(ToolRequest(plugin=step.plugin, args=step.args))
        except ArgValidationError as exc:
            errs.append(f"args: {exc}")
    if errs or normalized is None:
        return errs, None
    return [], replace(step, args=normalized)


def _file_of(plugin: str) -> str:
    """`` (forensics/plugins/windows/pslist.py)`` for a plugin loaded from a content file."""
    from app.tools import content

    loaded = content.current()
    module = loaded.modules.get(plugin)
    return f" ({content.module_file(f'{loaded.root}.plugins.{module}')})" if module else ""


def check_guide(runner: ToolRunner) -> tuple[InvestigationGuide, list[GuideProblem]]:
    """The guide with invalid steps removed (args normalised), and the problems found."""
    raw = runner.guide()
    plugins = {p.name for p in runner.plugins()}
    problems: list[GuideProblem] = []

    def collect(steps: Any, label: str, baseline: bool, source: str = "") -> list[GuideStep]:
        out: list[GuideStep] = []
        seen: set[tuple[str, str]] = set()
        for n, step in enumerate(steps, start=1):
            where = f"{label} #{n}{_file_of(getattr(step, 'plugin', '') if baseline else source)}"
            errs, ok = _check_step(runner, plugins, step, baseline)
            if ok is not None:
                key = (ok.plugin, args_key(ok.args))
                if key in seen:
                    errs, ok = ["same plugin and args listed twice"], None
                else:
                    seen.add(key)
                    out.append(ok)
            plugin = getattr(step, "plugin", "?")
            problems.extend(GuideProblem(where, str(plugin), e) for e in errs)
        return out

    baseline = collect(raw.baseline, "BASELINE", baseline=True)
    next_steps: dict[str, tuple[GuideStep, ...]] = {}
    for source, steps in raw.next.items():
        label = f"NEXT[{source!r}]{_file_of(source)}"
        if source not in plugins:
            problems.append(
                GuideProblem(label, str(source), "source plugin not in the catalog: never fires")
            )
            continue
        valid = collect(steps, f"NEXT[{source!r}]", baseline=False, source=source)
        if valid:
            next_steps[source] = tuple(valid)
    return InvestigationGuide(baseline=tuple(baseline), next=next_steps), problems


def _args_text(args: dict[str, Any]) -> str:
    return " ".join(f"{k}={json.dumps(v)}" for k, v in args.items()) or "—"


def to_markdown(runner: ToolRunner) -> str:
    """The whole guide as Markdown (for reviews/docs), including problems."""
    guide, problems = check_guide(runner)
    lines = [f"# Investigation guide ({runner.name})", "", "## Baseline (in order)", ""]
    lines += ["| # | Plugin | Args | Why |", "|---|---|---|---|"]
    for n, s in enumerate(guide.baseline, start=1):
        lines.append(f"| {n} | `{s.plugin}` | {_args_text(s.args)} | {s.reason} |")
    lines += ["", "## Next steps (after a run of ...)", ""]
    lines += ["| After | When it | Suggest | Args | Priority | Why |", "|---|---|---|---|---|---|"]
    for source, steps in guide.next.items():
        for s in steps:
            lines.append(
                f"| `{source}` | {describe_when(s.when)} | `{s.plugin}` | {_args_text(s.args)} "
                f"| {s.priority} | {s.reason} |"
            )
    lines += ["", f"## Problems ({len(problems)})", ""]
    lines += [f"- {p}" for p in problems] or ["None."]
    return "\n".join(lines) + "\n"


def main(tool: str = "volatility3") -> int:
    """Print the guide; exit code 1 if it has problems (usable in scripts/pre-commit)."""
    from app.tools import registry

    runner = registry.get_runner(tool)
    sys.stdout.write(to_markdown(runner))
    return 1 if check_guide(runner)[1] else 0


if __name__ == "__main__":  # python -m app.tools.guide -> print the guide + problems
    raise SystemExit(main())
