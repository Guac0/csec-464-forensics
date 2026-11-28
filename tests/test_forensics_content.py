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
