"""Checks of the forensics team's content in forensics/ (the only test that loads it).

Infrastructure tests use the frozen copy in tests/content/. If this file fails, the problem is in
forensics/: the message names the file and what is wrong.
"""

from __future__ import annotations

import importlib
from collections.abc import Iterator
from pathlib import Path

import pytest

from app.tools import content, hooks
from app.tools.content import Plugin, expected_module
from app.tools.guide import check_guide
from app.tools.volatility.runner import VolatilityRunner, catalog_problems
from tests.conftest import TEST_CONTENT_ROOT

FORENSICS = Path(__file__).resolve().parents[1] / "forensics"


@pytest.fixture(scope="module")
def loaded() -> Iterator[content.Content]:
    try:
        yield content.use_root("forensics")
    finally:
        content.use_root(TEST_CONTENT_ROOT)


def test_every_plugin_file_loads(loaded: content.Content) -> None:
    assert loaded.problems == {}
    assert loaded.plugins, "no plugins found in forensics/plugins/"


def test_catalog_entries_are_valid(loaded: content.Content) -> None:
    assert catalog_problems(loaded.plugins) == {}


def test_guide_is_valid(loaded: content.Content) -> None:
    _, problems = check_guide(VolatilityRunner())
    assert [str(p) for p in problems] == []


def test_hooks_load(loaded: content.Content) -> None:
    assert hooks.load_errors() == {}


def test_files_are_named_after_their_plugin(loaded: content.Content) -> None:
    wrong = {
        name: f"forensics/plugins/{module.replace('.', '/')}.py should be "
        f"forensics/plugins/{expected_module(name).replace('.', '/')}.py"
        for name, module in loaded.modules.items()
        if module != expected_module(name)
    }
    assert wrong == {}


def test_template_is_valid(loaded: content.Content) -> None:
    """forensics/plugins/_template.py must stay a working example (it is never loaded)."""
    module = importlib.import_module("forensics.plugins._template")
    try:
        assert isinstance(module.PLUGIN, Plugin)
        assert catalog_problems([module.PLUGIN.spec]) == {}
        assert module.PLUGIN.baseline_entries() and list(module.PLUGIN.next)
    finally:
        hooks.unregister("_template.flag_interesting_rows")


def test_no_stray_files() -> None:
    """Every .py file in forensics/plugins/ is in an OS folder (or starts with "_")."""
    stray = [
        str(p.relative_to(FORENSICS))
        for p in (FORENSICS / "plugins").glob("*.py")
        if not p.name.startswith("_")
    ]
    assert stray == []


# --- prompts, citations, fixtures, eval cases ----------------------------------------------


def test_prompt_files_exist_and_have_text(loaded: content.Content) -> None:
    from app.ai import prompts

    missing = [n for n in prompts.GUIDANCE_FILES if not prompts.guidance(n)]
    assert missing == [], f"empty or missing forensics/prompts/<name>.md: {missing}"
    question = prompts.run_summary_question(5, "windows.x.X")
    assert "R5" in question and "windows.x.X" in question, "run_summary.md lost {run_id}/{plugin}"


def test_citation_settings_are_valid(loaded: content.Content) -> None:
    settings = loaded.citations
    assert settings is not None, "forensics/citations.py is missing"
    assert all(isinstance(e, str) and e for e in settings.FILE_EXTENSIONS)
    assert all(isinstance(w, str) and w for w in settings.NUMBER_LABELS)
    assert isinstance(settings.TRUNCATED_NAME_LENGTH, int) and settings.TRUNCATED_NAME_LENGTH > 0


def _fixture_columns(path: Path) -> set[str]:
    rows = list(VolatilityRunner().parse_output(path))
    assert rows, f"{path} has no rows"
    return {k for r in rows for k in r.data}


def test_fixtures_parse_and_match_their_plugin(loaded: content.Content) -> None:
    by_module = {module: name for name, module in loaded.modules.items()}
    specs = {p.name: p for p in loaded.plugins}
    problems = []
    for path in sorted((FORENSICS / "fixtures").rglob("*.jsonl")):
        rel = path.relative_to(FORENSICS / "fixtures").with_suffix("")
        name = by_module.get(".".join(rel.parts))
        if name is None:
            problems.append(f"{path.name}: no plugin file plugins/{rel.as_posix()}.py")
            continue
        columns = _fixture_columns(path)
        rules = loaded.ai.get(name)
        wanted = {
            "compare_keys": set(specs[name].compare_keys),
            "compare_ignore": set(specs[name].compare_ignore),
            "ai_context columns": set(rules.settings.columns) if rules else set(),
        }
        for field, cols in wanted.items():
            if cols - columns:
                problems.append(f"{name}: {field} {sorted(cols - columns)} not in its output")
    assert problems == []


def test_eval_cases_load() -> None:
    from evals.cases import CASES_DIR, load_cases

    assert CASES_DIR == FORENSICS / "evals" / "cases"
    assert load_cases(cases_dir=CASES_DIR), "no eval cases in forensics/evals/cases/"
