"""AI evaluation harness: scoring, case files, judge parsing, baseline comparison, and an
end-to-end run against a mocked provider (no network)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from app.ai.client import AIClient
from app.ai.prompts import PROMPT_VERSION
from app.config import Settings
from evals import judge, run, scoring
from evals.cases import CaseError, load_cases, parse_case

EXPECT = scoring.ResolvedExpectations(
    cite_keys=("R1:5",),
    must_mention=("explorer.exe", "1900"),
    must_not_mention=("mimikatz",),
    suggest_plugins=("windows.pslist.PsList",),
    min_citations=1,
)


def cite(key: str, valid: bool = True) -> dict:
    run_id, row = key[1:].split(":")
    return {"key": key, "run_id": int(run_id), "row_idx": int(row), "valid": valid}


# ------------------------------------------------------------------------------- scoring


def test_perfect_answer_passes() -> None:
    content = (
        "explorer.exe (PID 2000) has parent PID 1900, which is not in the list [R1:5].\n"
        "This may be benign if the parent exited."
    )
    out = scoring.score_answer(
        content,
        [cite("R1:5")],
        [{"plugin": "windows.pslist.PsList", "valid": True}],
        EXPECT,
    )
    assert out["failed_checks"] == []
    m = out["metrics"]
    assert m["pass"] == 1.0 and m["citation_validity"] == 1.0 and m["expected_row_recall"] == 1.0
    assert m["mention_recall"] == 1.0 and m["suggestion_validity"] == 1.0
    assert m["cited_sentence_ratio"] == 0.5  # 1 of 2 sentences carries a citation


def test_bad_answer_fails_each_check() -> None:
    out = scoring.score_answer(
        "mimikatz was found running as PID 666 [R1:99]. Nothing else to report here.",
        [cite("R1:99", valid=False)],
        [{"plugin": "windows.malfind.Malfind", "valid": False}],
        EXPECT,
    )
    checks = " | ".join(out["failed_checks"])
    for text in (
        "do not exist",
        "did not cite expected rows",
        "fewer than 1",
        "did not mention",
        "forbidden",
        "no valid suggestion",
        "invalid suggestion",
    ):
        assert text in checks
    assert out["metrics"]["pass"] == 0.0 and out["metrics"]["citation_validity"] == 0.0


def test_unsupported_citation_fails_and_scores_support() -> None:
    cites = [
        {**cite("R1:5"), "support": "supported"},
        {**cite("R1:6"), "support": "unsupported", "unsupported_values": ["PID/port 2001"]},
        {**cite("R1:7"), "support": "unchecked"},
    ]
    out = scoring.score_answer(
        "explorer.exe [R1:5]. PID 2001 [R1:6]. Fine [R1:7].",
        cites,
        [{"plugin": "windows.pslist.PsList", "valid": True}],
        EXPECT,
    )
    assert out["metrics"]["citation_support"] == 0.5  # unchecked citations are not counted
    assert any("don't support the stated values" in c and "R1:6" in c for c in out["failed_checks"])
    assert out["metrics"]["pass"] == 0.0
    # Citations stored before support checking existed: metric not applicable.
    old = scoring.score_answer("x [R1:5].", [cite("R1:5")], [], EXPECT)
    assert old["metrics"]["citation_support"] is None


def test_provider_error_scores_zero() -> None:
    out = scoring.score_answer("", None, None, EXPECT, error="timeout")
    assert out["metrics"] == {"pass": 0.0} and "provider error" in out["failed_checks"][0]


def test_sentences_ignore_headings_and_fragments() -> None:
    text = "## Findings\n- explorer.exe has no listed parent [R1:5].\nOk.\nSummary:\n"
    assert scoring.sentences(text) == ["explorer.exe has no listed parent [R1:5]."]


def test_aggregate_and_compare() -> None:
    attempts = [
        {"metrics": {"pass": 1.0, "citation_validity": 1.0, "judge_score": 5}},
        {"metrics": {"pass": 0.0, "citation_validity": None, "judge_score": 3}},
    ]
    agg = scoring.aggregate(attempts)
    assert agg["pass"] == {"mean": 0.5, "min": 0.0, "max": 1.0, "stdev": 0.5, "n": 2}
    assert agg["citation_validity"]["n"] == 1
    baseline = {"a": {"pass": {"mean": 1.0}, "judge_score": {"mean": 4.2}}, "gone": {}}
    report = scoring.compare({"a": agg, "new": agg}, baseline, threshold=0.1)
    regressed = {(r["case"], r["metric"]) for r in report["regressions"]}
    assert regressed == {("a", "pass")}  # judge 4.2 -> 4.0 is 0.2/4 = 0.05 < threshold
    assert report["new_cases"] == ["new"] and report["missing_cases"] == ["gone"]
    assert report["cases"]["a"]["pass"]["delta"] == -0.5


def test_judge_verdict_parsing() -> None:
    assert judge.parse_verdict('Sure: {"score": 4, "reasons": "ok"}') == (4.0, "ok")
    assert judge.parse_verdict("no json")[0] is None
    assert judge.parse_verdict('{"score": 9}')[0] is None
    assert judge.parse_verdict('{"reasons": "x"}')[0] is None


# ------------------------------------------------------------------------------- cases


def test_example_cases_load() -> None:
    cases = {c.id: c for c in load_cases()}
    assert {"pstree-parent-example", "pstree-summary-example"} <= set(cases)
    parent = cases["pstree-parent-example"]
    assert parent.expect.cite_rows == ((0, 5),) and parent.rubric
    assert [c.id for c in load_cases(["summary"])] == ["pstree-summary-example"]  # by tag


FIXTURE = "tests/fixtures/sample_pstree.jsonl"


@pytest.mark.parametrize(
    ("data", "error"),
    [
        ([], "mapping"),
        ({"runs": [], "question": "q"}, "non-empty"),
        ({"runs": [{"plugin": "p"}], "question": "q"}, "fixture"),
        ({"runs": [{"plugin": "p", "fixture": "nope.jsonl"}], "question": "q"}, "not found"),
        ({"runs": [{"plugin": "p", "fixture": FIXTURE}]}, "exactly one"),
        ({"runs": [{"plugin": "p", "fixture": FIXTURE}], "summarize_run": 3}, "run index"),
        (
            {"runs": [{"plugin": "p", "fixture": FIXTURE}], "question": "q",
             "expect": {"cite_rows": ["1:0"]}},
            "out of range",
        ),
        (
            {"runs": [{"plugin": "p", "fixture": FIXTURE}], "question": "q",
             "expect": {"cite_rows": ["R1:0"]}},
            "look like",
        ),
        ({"runs": [{"plugin": "p", "fixture": FIXTURE}], "question": "q", "typo": 1}, "unknown"),
    ],
)  # fmt: skip
def test_case_validation(data: object, error: str) -> None:
    with pytest.raises(CaseError, match=error):
        parse_case(data, Path("x.yaml"))


def test_bad_yaml_and_duplicate_ids(tmp_path: Path) -> None:
    (tmp_path / "a.yaml").write_text("id: [unclosed\n")
    with pytest.raises(CaseError, match="invalid YAML"):
        load_cases(cases_dir=tmp_path)
    body = f"id: same\nruns: [{{plugin: p, fixture: {FIXTURE}}}]\nquestion: q\n"
    (tmp_path / "a.yaml").write_text(body)
    (tmp_path / "b.yaml").write_text(body)
    with pytest.raises(CaseError, match="duplicate"):
        load_cases(cases_dir=tmp_path)


# ------------------------------------------------------------------------------- end to end

GOOD = (
    "explorer.exe (PID 2000) reports parent PID 1900, which is not in the process list "
    "[R1:5]. The tree starts at System [R1:0] and services.exe is under wininit.exe [R1:4].\n\n"
    '```suggestions\n[{"plugin": "windows.pslist.PsList", "args": {"pid": [2000]}, '
    '"reason": "look closer"}]\n```'
)
BAD = "mimikatz is running [R1:42]."


def mocked_factory(answer: str, seen: list[dict]):
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body)
        is_judge = "You are grading" in body["messages"][0]["content"]
        content = '{"score": 5, "reasons": "fine"}' if is_judge else answer
        return httpx.Response(
            200,
            json={
                "model": body["model"],
                "choices": [{"message": {"role": "assistant", "content": content}}],
                "usage": {"total_tokens": 123},
            },
        )

    return lambda settings: AIClient(settings, transport=httpx.MockTransport(handler))


def test_end_to_end_run_baseline_and_regression(
    settings: Settings, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    seen: list[dict] = []
    out, baseline = tmp_path / "reports", tmp_path / "baseline.json"
    common = ["--repeat", "2", "--out", str(out), "--baseline", str(baseline)]

    code = run.main([*common, "--judge", "--save-baseline"], mocked_factory(GOOD, seen))
    assert code == 0
    report = json.loads(next(out.glob("*.json")).read_text())
    assert report["meta"]["prompt_version"] == PROMPT_VERSION
    assert report["meta"]["model"] == "test-model" and len(report["attempts"]) == 4
    parent = report["aggregate"]["pstree-parent-example"]
    assert parent["pass"]["mean"] == 1.0 and parent["judge_score"]["mean"] == 5.0
    assert parent["total_tokens"]["mean"] == 123
    summary = report["aggregate"]["pstree-summary-example"]
    assert summary["pass"]["mean"] == 1.0, report["attempts"][2]["failed_checks"]
    # The real pipeline ran: allowlist in the system prompt, context rows with citation keys.
    asks = [b for b in seen if "You are grading" not in b["messages"][0]["content"]]
    assert "windows.pslist.PsList" in asks[0]["messages"][0]["content"]
    assert "[R1:5]" in asks[0]["messages"][1]["content"]
    assert json.loads(baseline.read_text())["prompt_version"] == PROMPT_VERSION
    assert "| pstree-parent-example | 100% |" in capsys.readouterr().out

    code = run.main(
        [*common, "--cases", "pstree-parent-example", "--fail-on-regression"],
        mocked_factory(BAD, []),
    )
    assert code == 1
    latest = sorted(out.glob("*.md"))[-1].read_text()
    assert "Regressions vs baseline" in latest and "pstree-parent-example" in latest
    assert "did not cite expected rows" in latest


def test_unknown_case_selector(settings: Settings) -> None:
    assert run.main(["--cases", "nope"], mocked_factory(GOOD, [])) == 2
