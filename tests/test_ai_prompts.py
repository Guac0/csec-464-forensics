"""Prompt guidance files + fixed rules (app/ai/prompts.py)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from app.ai import prompts
from app.tools import content


@pytest.fixture
def prompt_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[Path]:
    """Guidance files read from a temp folder instead of tests/content/prompts/."""
    monkeypatch.setattr(content, "root_dir", lambda name=None: tmp_path)
    (tmp_path / "prompts").mkdir()
    yield tmp_path / "prompts"


def test_comment_is_stripped_and_placeholders_filled(prompt_dir: Path) -> None:
    (prompt_dir / "run_summary.md").write_text(
        '<!-- for humans {run_id} -->\nSummarize R{run_id} ({plugin}); JSON {"a": 1} is fine.'
    )
    assert prompts.run_summary_question(7, "windows.x.X") == (
        'Summarize R7 (windows.x.X); JSON {"a": 1} is fine.'
    )


def test_missing_files_fall_back_and_rules_are_always_added(prompt_dir: Path) -> None:
    assert prompts.run_summary_question(1, "p") == "Summarize the output of run R1 (p)."
    system = prompts.build_system_prompt()
    assert system.startswith("Rules") and "[R<run>:<row>]" in system
    assert "```suggestions" in system and "Allowlisted volatility3 plugins" in system
    agent = prompts.agent_system_prompt(max_runs=3, max_steps=9)
    assert "most 3 runs per task" in agent and "at most 9 steps" in agent
    assert '{"plugin": "<plugin name>"' in agent  # braces survive formatting
    question = prompts.recommend_question("lateral movement")
    assert "lateral movement" in question and question.endswith("1 to 5 queries.")


def test_guidance_comes_first(prompt_dir: Path) -> None:
    (prompt_dir / "analysis.md").write_text("Focus on persistence.")
    (prompt_dir / "agent.md").write_text("Work fast.")
    assert prompts.build_system_prompt().startswith("Focus on persistence.\n\nRules")
    assert prompts.agent_system_prompt(1, 2).startswith("Work fast.\n\nRules")


def test_prompt_version_follows_guidance(prompt_dir: Path) -> None:
    before = prompts.prompt_version()
    assert before.startswith("p-") and len(before) == 10
    (prompt_dir / "agent.md").write_text("changed")
    assert prompts.prompt_version() != before


def test_test_content_prompts_load() -> None:
    assert "memory forensics analyst" in prompts.build_system_prompt()
    assert "R5 (windows.pslist.PsList)" in prompts.run_summary_question(5, "windows.pslist.PsList")
