"""The forensics content loader (app/tools/content.py), with throwaway content packages."""

from __future__ import annotations

import sys
import textwrap
from collections.abc import Iterator
from pathlib import Path

import pytest

from app.tools import content, hooks
from app.tools.content import Baseline, Plugin, Preset, expected_module
from app.tools.volatility.runner import VolatilityRunner
from tests.conftest import TEST_CONTENT_ROOT

HEADER = "from app.tools.content import Baseline, Plugin\nfrom app.tools.base import GuideStep\n"


@pytest.fixture
def make_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator:
    """make_root({"windows/a.py": "..."}) -> loaded Content of a temporary root package."""
    monkeypatch.syspath_prepend(str(tmp_path))
    roots: list[str] = []

    def make(files: dict[str, str], name: str = "tmpcontent") -> content.Content:
        base = tmp_path / name
        for d in (base, base / "plugins", base / "hooks"):
            d.mkdir(exist_ok=True)
            (d / "__init__.py").write_text("")
        for rel, body in files.items():
            path = base / "plugins" / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.parent != base / "plugins":
                (path.parent / "__init__.py").write_text("")
            path.write_text(HEADER + textwrap.dedent(body))
        roots.append(name)
        return content.use_root(name)

    yield make
    for name in roots:
        for mod in [m for m in sys.modules if m == name or m.startswith(f"{name}.")]:
            del sys.modules[mod]
    content.use_root(TEST_CONTENT_ROOT)


def test_loads_plugins_guide_and_hooks(make_root) -> None:
    loaded = make_root(
        {
            "windows/b.py": """
                PLUGIN = Plugin(
                    "windows.b.B",
                    baseline=Baseline(5, "first"),
                    next=[GuideStep("windows.a.A", "then a", when="has_rows")],
                )

                @PLUGIN.post_run(version="2")
                def check(ctx): pass
            """,
            "windows/a.py": 'PLUGIN = Plugin("windows.a.A", baseline=Baseline(5, "tie: by name"))',
            "windows/c.py": 'PLUGIN = Plugin("windows.c.C", baseline=Baseline(1, "lowest"))',
        }
    )
    assert loaded.problems == {}
    assert [p.name for p in loaded.plugins] == ["windows.a.A", "windows.b.B", "windows.c.C"]
    assert [s.plugin for s in loaded.baseline] == ["windows.c.C", "windows.a.A", "windows.b.B"]
    assert [s.plugin for s in loaded.next["windows.b.B"]] == ["windows.a.A"]
    assert loaded.modules["windows.a.A"] == "windows.a"
    hook = {h.name: h for h in hooks.registered_hooks()}["windows.b.check"]
    assert hook.plugins == ("windows.b.B",) and hook.version == "2"
    guide = VolatilityRunner().guide()
    assert [s.plugin for s in guide.baseline] == ["windows.c.C", "windows.a.A", "windows.b.B"]


def test_bad_files_are_skipped_and_reported(make_root) -> None:
    loaded = make_root(
        {
            "windows/good.py": 'PLUGIN = Plugin("windows.good.Good")',
            "windows/broken.py": "raise RuntimeError('boom')",
            "windows/empty.py": "x = 1",
            "windows/wrong.py": "PLUGIN = {'name': 'windows.wrong.Wrong'}",
            "windows/zdup.py": 'PLUGIN = Plugin("windows.good.Good")',
            "windows/_skipped.py": "raise RuntimeError('never imported')",
        }
    )
    assert [p.name for p in loaded.plugins] == ["windows.good.Good"]
    root = "tmpcontent/plugins/windows"
    assert set(loaded.problems) == {
        f"{root}/broken.py",
        f"{root}/empty.py",
        f"{root}/wrong.py",
        f"{root}/zdup.py",
    }
    assert "boom" in loaded.problems[f"{root}/broken.py"][0]
    assert "already defined in" in loaded.problems[f"{root}/zdup.py"][0]
    problems = VolatilityRunner().catalog_problems()  # shown on the System page
    assert f"{root}/broken.py" in problems
    assert [p.name for p in VolatilityRunner().plugins()] == ["windows.good.Good"]


def test_missing_package_is_a_problem() -> None:
    try:
        loaded = content.use_root("no_such_content_root")
        assert loaded.plugins == [] and list(loaded.problems) == ["no_such_content_root/plugins/"]
    finally:
        content.use_root(TEST_CONTENT_ROOT)


def test_plugin_spec_and_helpers() -> None:
    plugin = Plugin(
        "windows.x.X",
        presets=[Preset("PID 4", pid=[4])],
        compare_keys=["Name"],
        baseline=[Baseline(1, "a"), Baseline(2, "b", args={"pid": [4]})],
    )
    assert plugin.spec.presets == (("PID 4", {"pid": [4]}),)
    assert plugin.spec.compare_keys == ("Name",)
    assert [b.order for b in plugin.baseline_entries()] == [1, 2]
    assert expected_module("windows.malware.malfind.Malfind") == "windows.malware_malfind"
    assert expected_module("windows.pslist.PsList") == "windows.pslist"
    assert expected_module("bad") == ""


def test_guide_problems_name_the_file(make_root) -> None:
    from app.tools.guide import check_guide

    make_root(
        {
            "windows/a.py": """
                PLUGIN = Plugin(
                    "windows.a.A",
                    baseline=Baseline(1, "ok"),
                    next=[GuideStep("windows.nope.Nope", "unknown")],
                )
            """
        }
    )
    _, problems = check_guide(VolatilityRunner())
    assert [p.where for p in problems] == [
        "NEXT['windows.a.A'] #1 (tmpcontent/plugins/windows/a.py)"
    ]
