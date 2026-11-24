from __future__ import annotations

import json

import pytest

from app.ai.prompts import build_system_prompt, render_allowlist
from app.ai.suggestions import (
    MAX_SUGGESTIONS,
    parse_suggestions,
    strip_suggestions_block,
    validate_suggestions,
)
from tests.test_ai_helpers import MALFIND, PSLIST, install_fake_runner


@pytest.fixture(autouse=True)
def fake_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    install_fake_runner(monkeypatch)


def _block(items: object) -> str:
    return f"```suggestions\n{json.dumps(items)}\n```"


ANSWER = "Suspicious process [R1:2].\n\n"


def test_parse_last_block() -> None:
    text = ANSWER + _block([{"plugin": "a"}]) + "\nmore\n" + _block([{"plugin": "b", "args": {}}])
    assert parse_suggestions(text) == [{"plugin": "b", "args": {}}]


def test_parse_malformed_or_missing() -> None:
    assert parse_suggestions(ANSWER) == []
    assert parse_suggestions(ANSWER + "```suggestions\n[{oops\n```") == []
    assert parse_suggestions(ANSWER + _block("string")) == []
    assert parse_suggestions(ANSWER + _block([1, {"plugin": "x"}])) == [{"plugin": "x"}]


def test_parse_unterminated_block_and_single_object() -> None:
    assert parse_suggestions(ANSWER + '```suggestions\n{"plugin": "x"}') == [{"plugin": "x"}]


def test_parse_caps_count() -> None:
    items = [{"plugin": PSLIST}] * 10
    assert len(parse_suggestions(_block(items))) == MAX_SUGGESTIONS


def test_strip_block() -> None:
    text = ANSWER + _block([{"plugin": PSLIST}]) + "\n"
    assert strip_suggestions_block(text) == ANSWER.rstrip()
    assert strip_suggestions_block("plain ```python\nx\n```") == "plain ```python\nx\n```"


def test_validate_suggestions() -> None:
    items = [
        {"plugin": PSLIST, "args": {"pid": ["4", 8]}, "reason": "check pid 4"},
        {"plugin": MALFIND},
        {"plugin": "windows.evil.Rm", "args": {}},
        {"plugin": PSLIST, "args": {"dump": True}},
        {"plugin": PSLIST, "args": {"pid": ["x"]}},
        {"args": {}},
        {"plugin": PSLIST, "args": "bad"},
    ]
    out = validate_suggestions(items)
    assert len(out) == MAX_SUGGESTIONS
    assert out[0] == {
        "tool": "volatility3",
        "plugin": PSLIST,
        "args": {"pid": ["4", 8]},
        "reason": "check pid 4",
        "valid": True,
        "normalized_args": {"pid": [4, 8]},
    }
    assert out[1]["valid"] is True and out[1]["normalized_args"] == {}
    assert out[2]["valid"] is False and "not allowed" in out[2]["error"]
    assert out[3]["valid"] is False and "unknown arg" in out[3]["error"]
    assert out[4]["valid"] is False
    assert validate_suggestions([{"args": {}}])[0]["error"] == "missing plugin name"
    assert validate_suggestions([{"plugin": PSLIST, "args": "x"}])[0]["valid"] is False


def test_prompt_renders_allowlist() -> None:
    rendered = render_allowlist()
    assert f"- {PSLIST}: List processes" in rendered
    assert "pid (list of int)" in rendered
    assert f"- {MALFIND}" in rendered
    prompt = build_system_prompt()
    assert "```suggestions" in prompt and "[R<run>:<row>]" in prompt and rendered in prompt
