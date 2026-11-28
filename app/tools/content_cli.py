"""``python -m forensics`` (forensics/__main__.py calls ``main``):

python -m forensics check                       # every content check; exit 1 on errors
python -m forensics guide                       # the investigation guide as Markdown
python -m forensics new windows.dlllist.DllList # new plugin file (+ real options from vol -h)
"""

from __future__ import annotations

import argparse
import re
import subprocess  # noqa: S404  (argv list, no shell)
import sys
from pathlib import Path

from app.tools import content

PLUGIN_NAME = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+\.[A-Z][A-Za-z0-9]*$")
VOL_HELP_TIMEOUT = 60


def vol_help(plugin: str) -> tuple[str | None, str]:
    """(``vol <plugin> -h`` text without usage/help lines, volatility version) or (None, why)."""
    from app.config import get_settings
    from app.tools.volatility.runner import vol_command

    argv = [*vol_command(get_settings().vol_executable), plugin, "-h"]
    try:
        proc = subprocess.run(  # noqa: S603
            argv, capture_output=True, text=True, timeout=VOL_HELP_TIMEOUT, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"could not run `{' '.join(argv)}`: {exc}"
    lines = (proc.stdout or "").splitlines()
    version = ""
    if lines and lines[0].startswith("Volatility 3 Framework"):
        version = lines.pop(0).split()[-1]
    if proc.returncode != 0 or not any(line.startswith("usage:") for line in lines):
        err = (proc.stderr or proc.stdout or "").strip().splitlines()[-1:] or ["no output"]
        return None, f"`vol {plugin} -h` failed: {err[0]}"
    # Drop the usage block (up to the first blank line) and argparse's own -h line.
    try:
        start = lines.index("") + 1
    except ValueError:
        start = 0
    body = [ln for ln in lines[start:] if not ln.strip().startswith("-h, --help")]
    return "\n".join(body).strip(), version


def plugin_file(plugin: str, root: Path | None = None) -> Path:
    module = content.expected_module(plugin)
    return (root or content.root_dir()) / "plugins" / (module.replace(".", "/") + ".py")


def render_new_plugin(plugin: str, help_text: str | None, version: str, why: str) -> str:
    if help_text is not None:
        options = "\n".join(f"    {ln}" if ln else "" for ln in help_text.splitlines())
        source = f"From `vol {plugin} -h` (volatility3 {version or 'unknown version'}):"
        body = f"{source}\n\n{options}\n"
    else:
        body = (
            f"Options not filled in automatically ({why}).\n"
            f"Run `vol {plugin} -h` on the volatility version the tool uses and copy them here.\n"
        )
    return f'''"""{plugin}: TODO(forensics) one-line description.

{body}
TODO(forensics): choose the options analysts may use (args=[...]), check the output columns
against real captured output, then delete these TODO notes.
"""

from forensics.sdk import Plugin

PLUGIN = Plugin(
    name="{plugin}",
    description="TODO(forensics): one line for the run form.",
    # Add args, presets, compare_keys, baseline, next, ai_context or a hook as needed.
    # plugins/_template.py shows every field with an explanation. Example option:
    #   args=[Arg(name="pid", flag="--pid", type="int_list", help="Only these process IDs")],
    # (import Arg from forensics.sdk, or use PID_FILTER from forensics.common).
)
'''


def cmd_new(plugin: str, root: Path | None = None, use_vol: bool = True) -> int:
    if not PLUGIN_NAME.match(plugin):
        print(
            f"error: {plugin!r} is not a full volatility3 plugin name like windows.pslist.PsList",
            file=sys.stderr,
        )
        return 2
    path = plugin_file(plugin, root)
    if path.exists():
        print(f"error: {path} already exists", file=sys.stderr)
        return 1
    loaded = content.current()
    if plugin in loaded.modules:
        print(f"error: {plugin} is already defined in {loaded.modules[plugin]}", file=sys.stderr)
        return 1
    help_text, info = vol_help(plugin) if use_vol else (None, "--no-vol given")
    version, why = (info, "") if help_text is not None else ("", info)
    path.parent.mkdir(parents=True, exist_ok=True)
    init = path.parent / "__init__.py"
    if not init.exists():
        init.write_text(f'"""{path.parent.name} plugins. One file per plugin."""\n')
    path.write_text(render_new_plugin(plugin, help_text, version, why), encoding="utf-8")
    print(f"created {path}")
    if help_text is None:
        print(f"note: {why}")
    print("next: fill in the TODOs, then run `python -m forensics check`")
    return 0


def cmd_check() -> int:
    from app.tools.content_report import build_report, to_text

    report = build_report()
    sys.stdout.write(to_text(report))
    return 0 if report.ok else 1


def cmd_guide() -> int:
    from app.tools.guide import main as guide_main

    return guide_main()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m forensics", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check", help="run every content check (exit 1 on errors)")
    sub.add_parser("guide", help="print the investigation guide as Markdown")
    new = sub.add_parser("new", help="create a plugin file")
    new.add_argument("plugin", help="full plugin name, e.g. windows.dlllist.DllList")
    new.add_argument("--no-vol", action="store_true", help="don't run vol -h for the options")
    args = parser.parse_args(argv)
    if args.cmd == "new":
        return cmd_new(args.plugin, use_vol=not args.no_vol)
    if args.cmd == "guide":
        return cmd_guide()
    return cmd_check()
