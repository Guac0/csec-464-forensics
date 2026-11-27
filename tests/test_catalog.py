"""Plugin catalog validation: invalid entries are skipped and reported, never run."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.services import health
from app.tools.base import ArgSpec, ArgValidationError, PluginSpec, ToolRequest
from app.tools.volatility import plugins as plugin_catalog
from app.tools.volatility.runner import VolatilityRunner, catalog_problems


def test_shipped_catalog_is_valid() -> None:
    """Fails CI when someone adds an invalid entry to app/tools/volatility/plugins.py."""
    assert catalog_problems(plugin_catalog.PLUGINS) == {}


@pytest.mark.parametrize(
    ("spec", "fragment"),
    [
        (PluginSpec("windows.pslist"), "full volatility3 plugin name"),
        (PluginSpec("pslist.PsList", args=(ArgSpec("x", "-p", "str"),)), "invalid flag"),
        (PluginSpec("a.B", args=(ArgSpec("x", "--plugin-dirs", "str"),)), "global vol flag"),
        (PluginSpec("a.B", args=(ArgSpec("x", "--x", "float"),)), "unknown arg type"),  # type: ignore[arg-type]
        (PluginSpec("a.B", args=(ArgSpec("Bad-Name", "--x", "str"),)), "snake_case"),
        (
            PluginSpec("a.B", args=(ArgSpec("x", "--x", "str"), ArgSpec("y", "--x", "str"))),
            "declared twice",
        ),
        (PluginSpec("a.B", args=(ArgSpec("dump", "--dump", "bool"),)), "writes_files=True"),
        (PluginSpec("windows.dumpfiles.DumpFiles"), "this plugin writes files"),
        (PluginSpec("a.B", timeout_seconds=0), "timeout_seconds"),
        (PluginSpec("a.B", presets=(("p", {"nope": 1}),)), "preset 'p'"),
    ],
)
def test_problems_detected(spec: PluginSpec, fragment: str) -> None:
    problems = catalog_problems([spec])
    assert fragment in " ".join(problems[spec.name])


def test_valid_entries_pass() -> None:
    ok = [
        PluginSpec("windows.dumpfiles.DumpFiles", writes_files=True),
        PluginSpec(
            "windows.pslist.PsList",
            args=(ArgSpec("dump", "--dump", "bool", writes_files=True),),
            presets=(("dump", {"dump": True}),),
            timeout_seconds=60,
        ),
    ]
    assert catalog_problems(ok) == {}
    assert ok[0].may_write_files and ok[1].may_write_files
    assert not PluginSpec("a.B").may_write_files


def test_duplicates_are_both_skipped() -> None:
    assert (
        "listed more than once" in catalog_problems([PluginSpec("a.B"), PluginSpec("a.B")])["a.B"]
    )


def test_invalid_entries_are_skipped_not_fatal(monkeypatch: pytest.MonkeyPatch) -> None:
    good = PluginSpec("good.Good")
    bad = PluginSpec("bad", args=(ArgSpec("x", "--x", "str"),))
    monkeypatch.setattr(plugin_catalog, "PLUGINS", [good, bad])
    runner = VolatilityRunner()
    assert [p.name for p in runner.plugins()] == ["good.Good"]
    assert list(runner.catalog_problems()) == ["bad"]
    with pytest.raises(ArgValidationError, match="not allowed"):
        runner.validate(ToolRequest("bad", {"x": "v"}))


def test_system_page_and_form_show_catalog_state(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    check = health.check_catalog()
    assert (
        check.status == "ok" and "windows.pslist.PsList" in dict(check.details)["May write files"]
    )

    client.post("/api/evidence/scan")
    ev_id = client.get("/api/evidence").json()[0]["id"]
    form = client.get(
        f"/ui/evidence/{ev_id}/plugin-form", params={"plugin": "windows.pslist.PsList"}
    ).text
    assert "writes files" in form

    monkeypatch.setattr(
        plugin_catalog, "PLUGINS", [*plugin_catalog.PLUGINS, PluginSpec("windows.broken")]
    )
    check = health.check_catalog()
    assert check.status == "fail" and "Skipped: windows.broken" in dict(check.details)
    assert "Plugin catalog" in client.get("/system").text
