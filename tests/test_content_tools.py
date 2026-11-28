"""Developer tools for forensics content: report, `python -m forensics`, /content page."""

from __future__ import annotations

import sys
import textwrap
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.tools import content, content_cli
from app.tools.content_report import build_report, to_text
from tests.conftest import TEST_CONTENT_ROOT

# --- report on the frozen test content -----------------------------------------------------


def test_report_on_test_content() -> None:
    report = build_report()
    assert report.ok, report.errors
    plugins = {p.name: p for p in report.plugins}
    pslist = plugins["windows.pslist.PsList"]
    assert pslist.baseline == [1] and pslist.next_steps == 3 and pslist.writes_files
    assert pslist.example and pslist.args == ["pid", "dump"]
    assert plugins["windows.info.Info"].hooks == ["windows.info.record_os_info"]
    assert "pstree-parent-example" in pslist.eval_cases
    assert any("still an EXAMPLE" in t for t in report.todo)
    text = to_text(report)
    assert "Errors (0)" in text and "windows.pslist.PsList" in text


@pytest.fixture
def bad_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """A content root with a fixture missing a compare key column and an orphan fixture."""
    base = tmp_path / "badcontent"
    for d in (base, base / "plugins", base / "plugins" / "windows", base / "hooks"):
        d.mkdir()
        (d / "__init__.py").write_text("")
    (base / "plugins" / "windows" / "a.py").write_text(
        textwrap.dedent(
            """
            from app.tools.content import Plugin
            PLUGIN = Plugin("windows.a.A", compare_keys=["Name", "Missing"])
            """
        )
    )
    fixtures = base / "fixtures" / "windows"
    fixtures.mkdir(parents=True)
    (fixtures / "a.jsonl").write_text('\n{"Name": "x", "PID": 1, "__children": []}\n')
    (fixtures / "orphan.jsonl").write_text('\n{"Name": "y", "__children": []}\n')
    monkeypatch.syspath_prepend(str(tmp_path))
    content.use_root("badcontent")
    yield base
    for mod in [m for m in sys.modules if m.startswith("badcontent")]:
        del sys.modules[mod]
    content.use_root(TEST_CONTENT_ROOT)


def test_report_finds_problems(bad_root: Path) -> None:
    report = build_report()
    text = "\n".join(report.errors)
    assert "compare_keys ['Missing'] not in its fixture output" in text
    assert "orphan.jsonl: no plugin file plugins/windows/orphan.py" in text
    assert "prompts/analysis.md: missing or empty" in text
    assert "citations.py: missing" in text
    assert content_cli.cmd_check() == 1


# --- python -m forensics new ----------------------------------------------------------------

FAKE_HELP = """\
import sys
if sys.argv[1] == "windows.bad.Bad":
    print("unknown plugin", file=sys.stderr)
    sys.exit(2)
print("Volatility 3 Framework 9.9.9")
print("usage: vol windows.x.X [-h] [--pid [PID ...]]")
print("")
print("Lists things.")
print("")
print("options:")
print("  -h, --help       show this help message and exit")
print("  --pid [PID ...]  Process IDs to include")
"""


@pytest.fixture
def fake_vol(settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    script = tmp_path / "fake_vol_help.py"
    script.write_text(FAKE_HELP)
    monkeypatch.setattr(settings, "vol_executable", str(script))
    return tmp_path / "root"


def test_new_plugin_file_with_vol_options(fake_vol: Path) -> None:
    assert content_cli.cmd_new("windows.malware.thing.Thing", root=fake_vol) == 0
    path = fake_vol / "plugins" / "windows" / "malware_thing.py"
    text = path.read_text()
    assert "volatility3 9.9.9" in text and "--pid [PID ...]  Process IDs to include" in text
    assert "--help" not in text and 'name="windows.malware.thing.Thing"' in text
    assert (path.parent / "__init__.py").exists()
    compile(text, str(path), "exec")
    assert content_cli.cmd_new("windows.malware.thing.Thing", root=fake_vol) == 1  # exists


def test_new_plugin_without_vol_and_bad_names(fake_vol: Path, capsys) -> None:
    assert content_cli.cmd_new("windows.bad.Bad", root=fake_vol) == 0
    assert (
        "Options not filled in automatically"
        in (fake_vol / "plugins" / "windows" / "bad.py").read_text()
    )
    assert "failed: unknown plugin" in capsys.readouterr().out
    assert content_cli.cmd_new("windows.pslist", root=fake_vol) == 2
    assert content_cli.cmd_new("windows.pslist.PsList", root=fake_vol) == 1  # already defined


def test_main_dispatch(capsys) -> None:
    assert content_cli.main(["check"]) == 0
    assert "Forensics content check (tests.content)" in capsys.readouterr().out
    assert content_cli.main(["guide"]) == 0
    assert "# Investigation guide" in capsys.readouterr().out


# --- /content page --------------------------------------------------------------------------


def test_content_page(client: TestClient) -> None:
    resp = client.get("/content")
    assert resp.status_code == 200
    assert "windows.pslist.PsList" in resp.text and "0 error(s)" in resp.text
    assert 'href="/content"' in client.get("/guide").text
