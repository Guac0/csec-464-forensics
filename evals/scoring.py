"""Deterministic scoring of one AI answer, aggregation over repeats, and baseline comparison.

Pure functions (no database, no network) so they are unit-tested in normal CI.
"""

from __future__ import annotations

import re
import statistics
from dataclasses import dataclass
from typing import Any

from app.ai.citations import extract_citations

# Metrics where higher is better, with a short description (used in reports).
METRICS: dict[str, str] = {
    "pass": "all checks passed (share of repeats)",
    "citation_validity": "cited row keys that exist / all citations",
    "citation_support": "cited rows containing the values stated next to them / checked citations",
    "expected_row_recall": "expected rows that were cited / expected rows",
    "cited_sentence_ratio": "sentences with at least one citation / sentences",
    "mention_recall": "required terms present / required terms",
    "suggestion_validity": "valid suggestions / suggestions",
    "judge_score": "AI judge score 1-5 (only with --judge; noisy)",
}
# Lower is better.
COST_METRICS = ("latency_s", "total_tokens")

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")
_BULLET = re.compile(r"^\s*(?:[-*•]|\d+[.)])\s*")


@dataclass(frozen=True)
class ResolvedExpectations:
    """Case expectations with row references resolved to citation keys (R<run>:<row>)."""

    cite_keys: tuple[str, ...] = ()
    must_mention: tuple[str, ...] = ()
    must_not_mention: tuple[str, ...] = ()
    suggest_plugins: tuple[str, ...] = ()
    min_citations: int = 0


def sentences(text: str) -> list[str]:
    """Rough sentence/bullet split; headings and very short fragments are ignored."""
    out = []
    for part in _SENTENCE_SPLIT.split(text or ""):
        part = _BULLET.sub("", part).strip()
        if len(part) >= 20 and not part.endswith(":") and not part.startswith("#"):
            out.append(part)
    return out


def _ratio(num: int, den: int) -> float | None:
    return None if den == 0 else num / den


def score_answer(
    content: str,
    citations: list[dict[str, Any]] | None,
    suggestions: list[dict[str, Any]] | None,
    expect: ResolvedExpectations,
    error: str | None = None,
) -> dict[str, Any]:
    """Score one answer. ``citations``/``suggestions`` are the validated lists stored on the
    AIMessage. Returns metrics (None = not applicable) and the list of failed checks."""
    if error:
        return {
            "metrics": {"pass": 0.0},
            "failed_checks": [f"provider error: {error}"],
            "citation_count": 0,
        }
    citations = citations or []
    suggestions = suggestions or []
    cited = {c["key"] for c in citations}
    valid_cited = {c["key"] for c in citations if c.get("valid")}
    lower = (content or "").lower()
    sents = sentences(content)
    with_cite = [s for s in sents if extract_citations(s)]
    mentioned = [t for t in expect.must_mention if t.lower() in lower]
    forbidden = [t for t in expect.must_not_mention if t.lower() in lower]
    valid_suggestions = [s for s in suggestions if s.get("valid")]
    checked = {c["key"] for c in citations if c.get("support") in ("supported", "unsupported")}
    unsupported = sorted(c["key"] for c in citations if c.get("support") == "unsupported")

    metrics = {
        "citation_validity": _ratio(len(valid_cited), len(cited)),
        "citation_support": _ratio(len(checked) - len(unsupported), len(checked)),
        "expected_row_recall": _ratio(
            len(set(expect.cite_keys) & valid_cited), len(expect.cite_keys)
        ),
        "cited_sentence_ratio": _ratio(len(with_cite), len(sents)),
        "mention_recall": _ratio(len(mentioned), len(expect.must_mention)),
        "suggestion_validity": _ratio(len(valid_suggestions), len(suggestions)),
    }
    failed = []
    if cited - valid_cited:
        failed.append(f"cites rows that do not exist: {sorted(cited - valid_cited)}")
    if unsupported:
        detail = {
            c["key"]: c.get("unsupported_values") for c in citations if c["key"] in unsupported
        }
        failed.append(f"cited rows don't support the stated values: {detail}")
    missing_rows = sorted(set(expect.cite_keys) - valid_cited)
    if missing_rows:
        failed.append(f"did not cite expected rows: {missing_rows}")
    if len(valid_cited) < expect.min_citations:
        failed.append(f"fewer than {expect.min_citations} valid citations ({len(valid_cited)})")
    missing_terms = [t for t in expect.must_mention if t not in mentioned]
    if missing_terms:
        failed.append(f"did not mention: {missing_terms}")
    if forbidden:
        failed.append(f"mentioned forbidden terms: {forbidden}")
    if expect.suggest_plugins and not any(
        s.get("plugin") in expect.suggest_plugins for s in valid_suggestions
    ):
        failed.append(f"no valid suggestion using {list(expect.suggest_plugins)}")
    if len(suggestions) > len(valid_suggestions):
        failed.append(f"{len(suggestions) - len(valid_suggestions)} invalid suggestion(s)")
    metrics["pass"] = 0.0 if failed else 1.0
    return {"metrics": metrics, "failed_checks": failed, "citation_count": len(cited)}


def aggregate(attempts: list[dict[str, Any]]) -> dict[str, Any]:
    """Mean/min/max/stdev of every metric over a case's repeats (None values are skipped)."""
    names = sorted({k for a in attempts for k in a["metrics"]})
    out: dict[str, Any] = {}
    for name in names:
        values = [a["metrics"][name] for a in attempts if a["metrics"].get(name) is not None]
        if not values:
            out[name] = None
            continue
        out[name] = {
            "mean": round(statistics.fmean(values), 4),
            "min": round(min(values), 4),
            "max": round(max(values), 4),
            "stdev": round(statistics.pstdev(values), 4) if len(values) > 1 else 0.0,
            "n": len(values),
        }
    return out


def compare(
    current: dict[str, dict[str, Any]],
    baseline: dict[str, dict[str, Any]] | None,
    threshold: float = 0.1,
) -> dict[str, Any]:
    """Per case and metric: current mean, baseline mean, delta; a *regression* is a quality
    metric whose mean dropped by more than ``threshold`` (absolute; judge_score scaled /4)."""
    report: dict[str, Any] = {"cases": {}, "regressions": [], "new_cases": [], "missing_cases": []}
    baseline = baseline or {}
    for case_id, metrics in current.items():
        if case_id not in baseline:
            report["new_cases"].append(case_id)
        rows = {}
        for name, stats in metrics.items():
            cur = stats["mean"] if stats else None
            base_stats = (baseline.get(case_id) or {}).get(name)
            base = base_stats["mean"] if base_stats else None
            delta = None if cur is None or base is None else round(cur - base, 4)
            rows[name] = {"current": cur, "baseline": base, "delta": delta}
            if delta is not None and name in METRICS:
                scale = 4.0 if name == "judge_score" else 1.0
                if -delta / scale > threshold:
                    report["regressions"].append(
                        {"case": case_id, "metric": name, "baseline": base, "current": cur}
                    )
        report["cases"][case_id] = rows
    report["missing_cases"] = sorted(set(baseline) - set(current))
    return report
