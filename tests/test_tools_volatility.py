"""VolatilityRunner: validation, argv building, jsonl parsing; registry."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.config import Settings
from app.tools import content, registry
from app.tools.base import ArgSpec, ArgValidationError, ParsedRow, PluginSpec, ToolRequest
from app.tools.volatility.runner import VolatilityRunner, check_argspec, vol_command

FIXTURES = Path(__file__).parent / "fixtures"

TEST_PLUGIN = PluginSpec(
    name="test.plugin.Test",
    args=(
        ArgSpec(name="pid", flag="--pid", type="int_list"),
        ArgSpec(name="offset", flag="--offset", type="int"),
        ArgSpec(name="dump", flag="--dump", type="bool", writes_files=True),
        ArgSpec(name="name", flag="--name", type="str"),
    ),
)
REQUIRED_PLUGIN = PluginSpec(
    name="test.required.Req",
    args=(ArgSpec(name="key", flag="--key", type="str", required=True),),
)


@pytest.fixture
def runner(monkeypatch: pytest.MonkeyPatch) -> VolatilityRunner:
    monkeypatch.setattr(
        content.current(), "plugins", [*content.current().plugins, TEST_PLUGIN, REQUIRED_PLUGIN]
    )
    return VolatilityRunner()


def req(args: dict, plugin: str = TEST_PLUGIN.name) -> ToolRequest:
    return ToolRequest(plugin=plugin, args=args)


# --- catalog -------------------------------------------------------------------------------


def test_catalog_is_well_formed() -> None:
    names = [p.name for p in content.current().plugins]
    assert len(names) == len(set(names))
    runner = VolatilityRunner()
    for p in content.current().plugins:
        for a in p.args:
            check_argspec(a)
        for _label, args in p.presets:
            runner.validate(ToolRequest(plugin=p.name, args=args))


# --- validation ----------------------------------------------------------------------------


def test_unknown_plugin(runner: VolatilityRunner) -> None:
    with pytest.raises(ArgValidationError, match="not allowed"):
        runner.validate(ToolRequest(plugin="windows.malfind", args={}))


def test_unknown_arg(runner: VolatilityRunner) -> None:
    with pytest.raises(ArgValidationError, match="unknown argument"):
        runner.validate(req({"plugin_dirs": "plugins"}))


def test_valid_args_normalized(runner: VolatilityRunner) -> None:
    out = runner.validate(req({"pid": "1, 2 3", "offset": "16", "dump": "true", "name": "x.exe"}))
    assert out == {"pid": [1, 2, 3], "offset": 16, "dump": True, "name": "x.exe"}


def test_blank_values_treated_as_missing(runner: VolatilityRunner) -> None:
    assert runner.validate(req({"pid": "", "offset": None, "name": "  "})) == {}


@pytest.mark.parametrize(
    "value, expected",
    [([1, 2], [1, 2]), ("4", [4]), ("1,2,,3", [1, 2, 3]), (7, [7]), (("8", 9), [8, 9])],
)
def test_int_list_parsing(runner: VolatilityRunner, value, expected) -> None:
    assert runner.validate(req({"pid": value}))["pid"] == expected


@pytest.mark.parametrize(
    "args",
    [
        {"pid": "1;2"},
        {"pid": [-1]},
        {"pid": [True]},
        {"pid": ["0x10"]},
        {"pid": ",,"},
        {"offset": -5},
        {"offset": "abc"},
        {"offset": 1.5},
        {"offset": True},
        {"offset": "１２"},  # non-ASCII digits
        {"dump": "maybe"},
        {"dump": 1},
        {"name": "--plugin-dirs=/tmp"},
        {"name": "-x"},
        {"name": "a\nb"},
        {"name": "a\x00b"},
        {"name": "a" * 1025},
        {"name": 5},
    ],
)
def test_bad_values_rejected(runner: VolatilityRunner, args) -> None:
    with pytest.raises(ArgValidationError):
        runner.validate(req(args))


def test_required_arg(runner: VolatilityRunner) -> None:
    with pytest.raises(ArgValidationError, match="missing required"):
        runner.validate(req({}, plugin=REQUIRED_PLUGIN.name))
    assert runner.validate(req({"key": "v"}, plugin=REQUIRED_PLUGIN.name)) == {"key": "v"}


@pytest.mark.parametrize("flag", ["--plugin-dirs", "-p", "--symbol-dirs", "--pid x", "pid"])
def test_catalog_flag_guard(monkeypatch: pytest.MonkeyPatch, flag: str) -> None:
    bad = PluginSpec(name="bad.Bad", args=(ArgSpec(name="x", flag=flag, type="str"),))
    monkeypatch.setattr(content.current(), "plugins", [bad])
    with pytest.raises(ArgValidationError):
        VolatilityRunner().validate(ToolRequest(plugin="bad.Bad", args={"x": "v"}))


# --- argv ----------------------------------------------------------------------------------


def test_build_argv_exact(runner: VolatilityRunner, settings: Settings, tmp_path: Path) -> None:
    ev = settings.evidence_dir / "sample.raw"
    out = tmp_path / "out"
    argv = runner.build_argv(
        ev, req({"name": "lsass.exe", "dump": True, "pid": "1 2", "offset": 0}), out
    )
    assert argv == [
        vol_command(settings.vol_executable)[0],
        "-q",
        "-r", "jsonl",
        "-s", str(settings.symbols_dir),
        "--cache-path", str(settings.data_dir / "vol_cache"),
        "-o", str(out),
        "-f", str(ev),
        "test.plugin.Test",
        "--pid", "1", "2",
        "--offset", "0",
        "--dump",
        "--name", "lsass.exe",
    ]  # fmt: skip
    assert (settings.data_dir / "vol_cache").is_dir()


def test_build_argv_bool_false_and_offline(settings: Settings, tmp_path: Path) -> None:
    r = VolatilityRunner(offline=True)
    argv = r.build_argv(Path("/e/x.raw"), ToolRequest("windows.info.Info"), tmp_path)
    assert "--offline" in argv
    assert argv.index("--offline") < argv.index("windows.info.Info")
    assert argv[-1] == "windows.info.Info"


def test_build_argv_resolves_paths_before_executor_changes_directory(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(settings, "data_dir", Path("data"))
    monkeypatch.setattr(settings, "symbols_dir", Path("symbols"))
    monkeypatch.setattr(settings, "vol_executable", "./bin/vol.exe")

    argv = VolatilityRunner().build_argv(
        Path("evidence/sample.raw"),
        ToolRequest("windows.pstree.PsTree"),
        Path("data/runs/1/output"),
    )

    assert argv[0] == str(tmp_path / "bin" / "vol.exe")
    for flag, path in (
        ("-s", "symbols"),
        ("--cache-path", "data/vol_cache"),
        ("-o", "data/runs/1/output"),
        ("-f", "evidence/sample.raw"),
    ):
        assert argv[argv.index(flag) + 1] == str(tmp_path / path)
    assert (tmp_path / "data" / "vol_cache").is_dir()


def test_build_argv_omits_false_bool(
    runner: VolatilityRunner, settings: Settings, tmp_path: Path
) -> None:
    argv = runner.build_argv(Path("/e/x.raw"), req({"dump": False}), tmp_path)
    assert "--dump" not in argv
    assert argv[-1] == "test.plugin.Test"


def test_build_argv_uses_vol_executable(
    runner: VolatilityRunner, settings: Settings, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from app.config import get_settings

    executable = str(tmp_path / "bin" / "vol")
    monkeypatch.setenv("FT_VOL_EXECUTABLE", executable)
    get_settings.cache_clear()
    argv = runner.build_argv(Path("/e/x.raw"), ToolRequest("windows.info.Info"), tmp_path)
    assert argv[0] == executable


def test_python_script_runs_via_interpreter(tmp_path: Path) -> None:
    import sys

    script = str(tmp_path / "fake_vol.PY")
    assert vol_command("vol") == ["vol"]
    assert vol_command(script) == [sys.executable, script]


def test_build_argv_validates(runner: VolatilityRunner, settings: Settings, tmp_path: Path) -> None:
    with pytest.raises(ArgValidationError):
        runner.build_argv(Path("/e/x.raw"), req({"plugin-dirs": "evil"}), tmp_path)
    with pytest.raises(ArgValidationError):
        runner.build_argv(Path("/e/x.raw"), req({"name": "-pevil"}), tmp_path)


def test_no_plugin_dirs_anywhere(settings: Settings, tmp_path: Path) -> None:
    runner = VolatilityRunner()
    for p in runner.plugins():
        argv = runner.build_argv(Path("/e/x.raw"), ToolRequest(p.name), tmp_path)
        assert "-p" not in argv and "--plugin-dirs" not in argv


# --- parser --------------------------------------------------------------------------------


def test_parse_nested_fixture(runner: VolatilityRunner) -> None:
    rows = list(runner.parse_output(FIXTURES / "sample_pstree.jsonl"))
    got = [(r.data["PID"], r.depth, r.parent_idx) for r in rows]
    assert got == [
        (4, 0, None),
        (300, 1, 0),
        (400, 2, 1),
        (480, 2, 1),
        (600, 3, 3),
        (2000, 0, None),
    ]
    assert all("__children" not in r.data for r in rows)
    assert rows[0].data == {"ImageFileName": "System", "PID": 4, "PPID": 0}


def test_parse_flat(runner: VolatilityRunner, tmp_path: Path) -> None:
    p = tmp_path / "o.jsonl"
    p.write_text('\n{"A": 1, "__children": []}\n\n{"A": 2}\n')
    assert list(runner.parse_output(p)) == [ParsedRow({"A": 1}), ParsedRow({"A": 2})]


def test_parse_empty(runner: VolatilityRunner, tmp_path: Path) -> None:
    p = tmp_path / "o.jsonl"
    p.write_text("\n")
    assert list(runner.parse_output(p)) == []


def test_parse_bad_json_reports_line(runner: VolatilityRunner, tmp_path: Path) -> None:
    p = tmp_path / "o.jsonl"
    p.write_text('\n{"A": 1}\n{not json\n')
    with pytest.raises(ValueError, match="line 3"):
        list(runner.parse_output(p))


def test_parse_non_object(runner: VolatilityRunner, tmp_path: Path) -> None:
    p = tmp_path / "o.jsonl"
    p.write_text("[1, 2]\n")
    with pytest.raises(ValueError, match="line 1"):
        list(runner.parse_output(p))


def test_parse_deep_tree(runner: VolatilityRunner, tmp_path: Path) -> None:
    import json

    depth = 300
    node: dict = {"N": depth, "__children": []}
    for i in range(depth - 1, -1, -1):
        node = {"N": i, "__children": [node]}
    p = tmp_path / "o.jsonl"
    p.write_text(json.dumps(node) + "\n")
    rows = list(runner.parse_output(p))
    assert len(rows) == depth + 1
    assert [r.data["N"] for r in rows] == list(range(depth + 1))
    assert rows[-1].depth == depth and rows[-1].parent_idx == depth - 1


# --- registry ------------------------------------------------------------------------------


def test_registry() -> None:
    assert "volatility3" in registry.available_tools()
    r = registry.get_runner()
    assert isinstance(r, VolatilityRunner)
    assert registry.get_runner("volatility3") is r
    with pytest.raises(KeyError, match="unknown tool"):
        registry.get_runner("nope")


def test_version_returns_str_or_none() -> None:
    v = VolatilityRunner().version()
    assert v is None or isinstance(v, str)
