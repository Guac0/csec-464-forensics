"""Run the AI evaluation cases against the configured provider and write a report.

    python -m evals.run                         # all cases, 3 repeats, model from FT_AI_MODEL
    python -m evals.run --cases pstree-example --repeat 5
    python -m evals.run --judge                 # also grade answers with an AI judge
    python -m evals.run --save-baseline         # store results as evals/baselines/<model>.json
    python -m evals.run --fail-on-regression    # exit 1 if a metric dropped vs the baseline

Exit codes: 0 ok, 1 regression (with --fail-on-regression), 2 no matching cases, 3 every attempt
failed with a provider error.

The provider comes from the usual FT_AI_* environment variables (or .env). Each case runs in a
throwaway database built from its recorded fixtures through the real parser, context builder and
AI service, so the answers are produced exactly as in the app. Reports go to evals/reports/
(git-ignored).
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import json
import os
import re
import shutil
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from evals import scoring
from evals.cases import CASES_DIR, Case, load_cases

EVALS_DIR = Path(__file__).resolve().parent
BASELINES_DIR = EVALS_DIR / "baselines"
REPORTS_DIR = EVALS_DIR / "reports"

ClientFactory = Callable[[Any], Any]  # settings -> AIClient


@contextlib.contextmanager
def scratch_environment() -> Iterator[Path]:
    """Point the app at a temporary data dir (fresh SQLite DB) for one attempt."""
    from app import db
    from app.config import get_settings

    tmp = Path(tempfile.mkdtemp(prefix="ft-eval-"))
    keys = ("FT_EVIDENCE_DIR", "FT_DATA_DIR", "FT_SYMBOLS_DIR", "FT_AUDIT_LEVEL", "FT_SEARCH_INDEX")
    saved = {k: os.environ.get(k) for k in keys}
    try:
        for sub in ("evidence", "data", "symbols"):
            (tmp / sub).mkdir()
        os.environ.update(
            FT_EVIDENCE_DIR=str(tmp / "evidence"),
            FT_DATA_DIR=str(tmp / "data"),
            FT_SYMBOLS_DIR=str(tmp / "symbols"),
            FT_AUDIT_LEVEL="changes",
            FT_SEARCH_INDEX="false",
        )
        get_settings.cache_clear()
        db.init_engine()
        db.migrate()
        yield tmp
    finally:
        db.get_engine().dispose()
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        get_settings.cache_clear()
        shutil.rmtree(tmp, ignore_errors=True)


def _load_case_into_db(session: Any, case: Case, evidence_dir: Path) -> tuple[Any, list[int]]:
    """Evidence + notes + succeeded runs with rows parsed from the fixtures."""
    from app.models import Run, RunStatus
    from app.services import evidence as evidence_service
    from app.services import notes as notes_service
    from app.services import results
    from app.tools import registry

    rel_path = str(case.evidence.get("rel_path") or "case.raw")
    (evidence_dir / rel_path).parent.mkdir(parents=True, exist_ok=True)
    (evidence_dir / rel_path).write_bytes(b"\0" * 1024)  # content is irrelevant to the AI
    (ev,) = [e for e in evidence_service.scan_evidence(session) if e.rel_path == rel_path]
    ev.description = str(case.evidence.get("description") or "")
    ev.os_info = case.evidence.get("os_info")
    session.commit()
    for note in case.notes:
        notes_service.create_note(session, note, evidence_id=ev.id)
    runner = registry.get_runner("volatility3")
    run_ids = []
    for spec in case.runs:
        run = Run(
            evidence_id=ev.id,
            plugin=spec.plugin,
            args=spec.args,
            status=RunStatus.SUCCEEDED,
            tool_version="eval-fixture",
        )
        session.add(run)
        session.flush()
        run.row_count = results.store_rows(
            session, run.id, runner.parse_output(spec.fixture), search_index=False
        )
        session.commit()
        run_ids.append(run.id)
    return ev, run_ids


@dataclasses.dataclass
class _AgentAnswer:
    """The agent's answer message, or a stand-in when the task ended without one."""

    content: str = ""
    citations: list[dict[str, Any]] | None = None
    suggestions: list[dict[str, Any]] | None = None
    error: str | None = None
    usage: dict[str, Any] | None = None
    model_returned: str | None = None


def _fill_run_from_fixture(session: Any, run: Any, case: Case) -> None:
    """Act as the worker for a run the agent queued: load the case's recorded output for that
    plugin (args must match the fixture's, if it gives any), or fail it."""
    from app.models import RunStatus, utcnow
    from app.services import results
    from app.tools import registry

    spec = next(
        (
            r
            for r in case.available_runs
            if r.plugin == run.plugin
            and all((run.args or {}).get(k) == v for k, v in r.args.items())
        ),
        None,
    )
    run.started_at = utcnow()
    if spec is None:
        run.status = RunStatus.FAILED
        run.error = "not available in this evaluation case (no recorded output)"
    else:
        parsed = registry.get_runner("volatility3").parse_output(spec.fixture)
        run.row_count = results.store_rows(session, run.id, parsed, search_index=False)
        run.status = RunStatus.SUCCEEDED
        run.tool_version = "eval-fixture"
    run.finished_at = utcnow()
    session.commit()


def _run_agent_case(session: Any, case: Case, ev: Any, client: Any) -> tuple[Any, list[str], int]:
    """Run an AI agent task with "yes to all"; queued runs complete from the case's fixtures."""
    import threading

    from app.ai import agent
    from app.models import AIMessage, AITask, Run, RunStatus

    opts = case.agent
    saved = agent._launch, agent.POLL_SECONDS
    agent._launch, agent.POLL_SECONDS = (lambda task_id: None), 0.05
    try:
        task = agent.start_task(
            session,
            ev.id,
            case.goal or "",
            max_steps=opts.get("max_steps", 8),
            max_seconds=opts.get("max_seconds", 600),
            max_runs=opts.get("max_runs", 3),
            approve_all=True,
        )
        worker = threading.Thread(target=agent.run_task, args=(task.id,), kwargs={"client": client})
        worker.start()
        while worker.is_alive():
            session.expire_all()
            for run in session.query(Run).filter_by(ai_task_id=task.id, status=RunStatus.QUEUED):
                _fill_run_from_fixture(session, run, case)
            worker.join(timeout=0.05)
    finally:
        agent._launch, agent.POLL_SECONDS = saved
    session.expire_all()
    task = session.get(AITask, task.id)
    queued = [r.plugin for r in task.run_requests if r.status in ("approved", "edited", "auto")]
    msg = session.get(AIMessage, task.answer_message_id) if task.answer_message_id else None
    if msg is None:
        msg = _AgentAnswer(error=task.error or f"the task ended {task.status.value}")
    return msg, queued, task.steps_used


def _resolve(case: Case, run_ids: list[int], session: Any) -> scoring.ResolvedExpectations:
    from app.models import ResultRow

    keys = []
    for run_index, row_idx in case.expect.cite_rows:
        exists = (
            session.query(ResultRow).filter_by(run_id=run_ids[run_index], row_idx=row_idx).first()
        )
        if exists is None:
            raise ValueError(
                f"case {case.id}: expected row {run_index}:{row_idx} not in the fixture"
            )
        keys.append(f"R{run_ids[run_index]}:{row_idx}")
    return scoring.ResolvedExpectations(
        cite_keys=tuple(keys),
        must_mention=case.expect.must_mention,
        must_not_mention=case.expect.must_not_mention,
        suggest_plugins=case.expect.suggest_plugins,
        suggest_queries=case.expect.suggest_queries,
        queue_plugins=case.expect.queue_plugins,
        forbid_plugins=case.expect.forbid_plugins,
        max_queued=case.expect.max_queued,
        min_citations=case.expect.min_citations,
    )


def run_attempt(
    case: Case,
    attempt: int,
    client_factory: ClientFactory,
    judge_factory: ClientFactory | None = None,
    judge_model: str | None = None,
) -> dict[str, Any]:
    """Ask the case's question once in a fresh database and score the answer."""
    from app.ai import service as ai_service
    from app.config import get_settings
    from app.db import SessionLocal
    from app.models import ResultRow

    with scratch_environment() as tmp, SessionLocal() as session:
        ev, run_ids = _load_case_into_db(session, case, tmp / "evidence")
        expect = _resolve(case, run_ids, session)
        client = client_factory(get_settings())
        started = time.perf_counter()
        if case.summarize_run is not None:
            from app.ai.prompts import SUMMARIZE_RUN_QUESTION

            target = run_ids[case.summarize_run]
            question = SUMMARIZE_RUN_QUESTION.format(
                run_id=target, plugin=case.runs[case.summarize_run].plugin
            )
            msg = ai_service.summarize_run(session, target, client=client)
        elif case.recommend is not None:
            from app.ai.prompts import RECOMMEND_DISPLAY

            question = RECOMMEND_DISPLAY + (f" Focus: {case.recommend}" if case.recommend else "")
            msg = ai_service.recommend_next(session, ev.id, case.recommend, client=client)
        elif case.goal is not None:
            question = f"Goal: {case.goal}"
            msg, queued, steps = _run_agent_case(session, case, ev, client)
        else:
            question = case.question or ""
            msg = ai_service.ask(session, ev.id, question, client=client)
        latency = time.perf_counter() - started
        agent_case = case.goal is not None
        scored = scoring.score_answer(
            msg.content,
            msg.citations,
            msg.suggestions,
            expect,
            msg.error,
            queued=queued if agent_case else None,
        )
        if agent_case:
            scored["metrics"]["agent_steps"] = float(steps)
        usage = msg.usage or {}
        result: dict[str, Any] = {
            "case": case.id,
            "attempt": attempt,
            "metrics": scored["metrics"],
            "failed_checks": scored["failed_checks"],
            "latency_s": round(latency, 3),
            "total_tokens": usage.get("total_tokens"),
            "model_returned": msg.model_returned,
            "error": msg.error,
            "answer": msg.content,
            "expected_rows": list(expect.cite_keys),
        }
        if agent_case:
            result["queued_runs"] = queued
        result["metrics"]["latency_s"] = result["latency_s"]
        if result["total_tokens"] is not None:
            result["metrics"]["total_tokens"] = result["total_tokens"]
        if judge_factory and case.rubric and not msg.error:
            from evals import judge as judge_mod

            cited = {}
            for c in msg.citations or []:
                if c.get("valid"):
                    row = (
                        session.query(ResultRow)
                        .filter_by(run_id=c["run_id"], row_idx=c["row_idx"])
                        .first()
                    )
                    if row is not None:
                        cited[c["key"]] = row.data
            verdict = judge_mod.judge(
                judge_factory(get_settings()),
                question,
                case.rubric,
                msg.content,
                cited,
                judge_model,
            )
            result["judge"] = verdict
            if verdict["score"] is not None:
                result["metrics"]["judge_score"] = verdict["score"]
        return result


# --------------------------------------------------------------------------------- reports


def _model_slug(model: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", model).strip("_") or "model"


def _fmt(value: Any, pct: bool = True) -> str:
    if value is None:
        return "–"
    return f"{value * 100:.0f}%" if pct else f"{value:g}"


def render_markdown(report: dict[str, Any]) -> str:
    meta = report["meta"]
    lines = [
        f"# AI evaluation: {meta['model']}",
        "",
        f"- Prompt version: `{meta['prompt_version']}` · provider: `{meta['provider_base_url']}`",
        f"- {meta['cases']} case(s) × {meta['repeat']} repeat(s) · judge: "
        f"{meta['judge_model'] or ('on' if meta['judge'] else 'off')} · {meta['created_at']}",
        f"- Baseline: {meta['baseline'] or 'none'}",
        "",
        "| Case | Pass | Citations valid | Citations supported | Expected rows cited "
        "| Sentences cited | Terms | Suggestions valid | Judge (1-5) | Latency s | Tokens "
        "| Δ pass vs baseline |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for case_id, agg in report["aggregate"].items():

        def m(name: str, agg: dict[str, Any] = agg) -> Any:
            return (agg.get(name) or {}).get("mean")

        delta = report["comparison"]["cases"].get(case_id, {}).get("pass", {}).get("delta")
        lines.append(
            f"| {case_id} | {_fmt(m('pass'))} | {_fmt(m('citation_validity'))} "
            f"| {_fmt(m('citation_support'))} "
            f"| {_fmt(m('expected_row_recall'))} | {_fmt(m('cited_sentence_ratio'))} "
            f"| {_fmt(m('mention_recall'))} | {_fmt(m('suggestion_validity'))} "
            f"| {_fmt(m('judge_score'), pct=False)} | {_fmt(m('latency_s'), pct=False)} "
            f"| {_fmt(m('total_tokens'), pct=False)} "
            f"| {'–' if delta is None else f'{delta * 100:+.0f} pts'} |"
        )
    regressions = report["comparison"]["regressions"]
    lines += ["", f"## Regressions vs baseline ({len(regressions)})", ""]
    lines += [
        f"- **{r['case']}** {r['metric']}: {r['baseline']} -> {r['current']}" for r in regressions
    ] or ["None."]
    failures = Counter(
        f"{a['case']}: {check}" for a in report["attempts"] for check in a["failed_checks"]
    )
    lines += ["", "## Failed checks (count over repeats)", ""]
    lines += [f"- {text} (×{n})" for text, n in failures.most_common(30)] or ["None."]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None, client_factory: ClientFactory | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run AI evaluation cases (see evals/README.md).")
    parser.add_argument("--cases", nargs="*", help="case ids or tags (default: all)")
    parser.add_argument("--cases-dir", type=Path, default=CASES_DIR)
    parser.add_argument("--repeat", type=int, default=3, help="attempts per case (default 3)")
    parser.add_argument("--model", help="override FT_AI_MODEL for this evaluation")
    parser.add_argument("--judge", action="store_true", help="grade answers with an AI judge")
    parser.add_argument("--judge-model", help="model for the judge (default: same as --model)")
    parser.add_argument("--baseline", type=Path, help="baseline file (default: per model)")
    parser.add_argument("--save-baseline", action="store_true")
    parser.add_argument("--threshold", type=float, default=0.1, help="regression threshold")
    parser.add_argument("--fail-on-regression", action="store_true")
    parser.add_argument("--out", type=Path, default=REPORTS_DIR)
    args = parser.parse_args(argv)

    from app.ai.client import AIClient
    from app.ai.prompts import PROMPT_VERSION
    from app.config import get_settings

    if args.model:
        os.environ["FT_AI_MODEL"] = args.model
    get_settings.cache_clear()
    settings = get_settings()
    model = settings.ai_model
    factory = client_factory or (lambda s: AIClient(s))
    cases = load_cases(args.cases, args.cases_dir)
    if not cases:
        print("no matching cases", file=sys.stderr)
        return 2

    attempts = []
    for case in cases:
        for attempt in range(1, args.repeat + 1):
            print(f"[{case.id}] attempt {attempt}/{args.repeat} ...", file=sys.stderr, flush=True)
            attempts.append(
                run_attempt(
                    case,
                    attempt,
                    factory,
                    judge_factory=factory if args.judge else None,
                    judge_model=args.judge_model,
                )
            )
    by_case = {c.id: [a for a in attempts if a["case"] == c.id] for c in cases}
    aggregate = {case_id: scoring.aggregate(items) for case_id, items in by_case.items()}

    baseline_path = args.baseline or BASELINES_DIR / f"{_model_slug(model)}.json"
    baseline = (
        json.loads(baseline_path.read_text(encoding="utf-8")) if baseline_path.is_file() else None
    )
    comparison = scoring.compare(aggregate, (baseline or {}).get("cases"), threshold=args.threshold)
    created = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    report = {
        "meta": {
            "model": model,
            "prompt_version": PROMPT_VERSION,
            "provider_base_url": settings.ai_base_url,
            "repeat": args.repeat,
            "cases": len(cases),
            "judge": args.judge,
            "judge_model": args.judge_model,
            "threshold": args.threshold,
            "baseline": str(baseline_path.relative_to(EVALS_DIR.parent))
            if baseline and baseline_path.is_relative_to(EVALS_DIR.parent)
            else (str(baseline_path) if baseline else None),
            "baseline_prompt_version": (baseline or {}).get("prompt_version"),
            "created_at": created,
        },
        "aggregate": aggregate,
        "comparison": comparison,
        "attempts": attempts,
    }
    args.out.mkdir(parents=True, exist_ok=True)
    stem = f"{created.replace(':', '').replace('-', '')}-{_model_slug(model)}"
    (args.out / f"{stem}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    markdown = render_markdown(report)
    (args.out / f"{stem}.md").write_text(markdown, encoding="utf-8")
    print(markdown)
    print(f"report: {args.out / stem}.{{json,md}}", file=sys.stderr)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(markdown)

    if args.save_baseline:
        BASELINES_DIR.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(
            json.dumps(
                {
                    "model": model,
                    "prompt_version": PROMPT_VERSION,
                    "created_at": created,
                    "repeat": args.repeat,
                    "cases": aggregate,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"baseline saved: {baseline_path}", file=sys.stderr)
    if all(a["error"] for a in attempts):
        print("every attempt failed with a provider error; check FT_AI_* settings", file=sys.stderr)
        return 3
    if args.fail_on_regression and comparison["regressions"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
