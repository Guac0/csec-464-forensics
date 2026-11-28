"""VolatilityRunner: allowlist validation, argv building and generic jsonl parsing for volatility3.

Verified against volatility3 2.28.2 (volatility3/cli/__init__.py, cli/text_renderer.py,
cli/volargparse.py):
  - Global options must come BEFORE the plugin name (plugins are argparse subparsers);
    plugin options come after it.
  - ``-q/--quiet``: suppress progress output.
  - ``-r/--renderer``: choices are renderer class names lower-cased: quick, none, csv, pretty,
    json, jsonl, mermaid. With a structured renderer (json/jsonl) the banner goes to stderr.
  - ``-s/--symbol-dirs``: ';'-separated; PREPENDED to the built-in symbol paths. Generated
    Windows ISF files (from PDB downloads) are written to the first writable symbol dir, i.e.
    settings.symbols_dir.
  - ``--cache-path``: must already exist (vol crashes with FileNotFoundError on
    identifier.cache otherwise), so build_argv creates it.
  - ``-o/--output-dir``: must already exist (argparse error otherwise); the executor creates it.
  - ``-f/--file``: shorthand for --single-location=file://...
  - ``--offline``: blocks ALL http(s) fetches, including Microsoft PDB symbol downloads and the
    remote ISF server. Not emitted by default (see ``VolatilityRunner(offline=...)``).
  - ``-p/--plugin-dirs`` loads arbitrary Python: never emitted, and ArgSpec flags colliding with
    any global option are refused.
"""

from __future__ import annotations

import importlib.metadata
import json
import logging
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from app.config import get_settings
from app.tools import content
from app.tools.base import (
    ArgSpec,
    ArgValidationError,
    InvestigationGuide,
    ParsedRow,
    PluginSpec,
    ToolRequest,
    ToolRunner,
)

logger = logging.getLogger(__name__)

MAX_STR_LEN = 1024
CHILDREN_KEY = "__children"

# Global `vol` options (2.28.2). Plugin ArgSpecs may never use these, so a catalog mistake
# cannot smuggle in e.g. --plugin-dirs. Abbreviations are irrelevant here: plugin options are
# parsed by the plugin's own subparser, which only knows the plugin's options.
_GLOBAL_FLAGS = frozenset(
    {
        "-h", "--help", "-c", "--config", "--parallelism", "-e", "--extend",
        "-p", "--plugin-dirs", "-s", "--symbol-dirs", "-v", "--verbosity", "-l", "--log",
        "-o", "--output-dir", "-q", "--quiet", "-f", "--file", "--write-config",
        "--save-config", "--clear-cache", "--cache-path", "--offline", "-u",
        "--remote-isf-url", "--filters", "--hide-columns", "-r", "--renderer",
        "--single-location", "--stackers", "--single-swap-locations",
    }
)  # fmt: skip
_FLAG_RE = re.compile(r"^--[a-z0-9][a-z0-9-]*$")
_TRUE = {"true", "1", "yes", "on"}
_FALSE = {"false", "0", "no", "off"}


def _coerce_int(name: str, value: Any) -> int:
    if isinstance(value, bool):
        raise ArgValidationError(f"{name}: expected integer, got boolean")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and value.strip().isdigit() and value.strip().isascii():
        result = int(value.strip())
    else:
        raise ArgValidationError(f"{name}: expected non-negative integer, got {value!r}")
    if result < 0:
        raise ArgValidationError(f"{name}: must be non-negative, got {result}")
    return result


def _coerce_int_list(name: str, value: Any) -> list[int]:
    if isinstance(value, str):
        items: list[Any] = [p for p in re.split(r"[\s,]+", value.strip()) if p]
    elif isinstance(value, list | tuple):
        items = list(value)
    elif isinstance(value, int) and not isinstance(value, bool):
        items = [value]
    else:
        raise ArgValidationError(f"{name}: expected list of integers, got {value!r}")
    if not items:
        raise ArgValidationError(f"{name}: list must not be empty")
    return [_coerce_int(name, v) for v in items]


def _coerce_bool(name: str, value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in _TRUE | _FALSE:
        return value.strip().lower() in _TRUE
    raise ArgValidationError(f"{name}: expected true/false, got {value!r}")


def _coerce_str(name: str, value: Any) -> str:
    if not isinstance(value, str):
        raise ArgValidationError(f"{name}: expected string, got {type(value).__name__}")
    if not value.strip():
        raise ArgValidationError(f"{name}: must not be empty")
    if value.startswith("-"):
        raise ArgValidationError(f"{name}: must not start with '-'")
    if any(c in value for c in ("\x00", "\n", "\r")):
        raise ArgValidationError(f"{name}: must not contain NUL or newline characters")
    if len(value) > MAX_STR_LEN:
        raise ArgValidationError(f"{name}: longer than {MAX_STR_LEN} characters")
    return value


_COERCERS = {
    "int": _coerce_int,
    "int_list": _coerce_int_list,
    "bool": _coerce_bool,
    "str": _coerce_str,
}


# volatility3 options / plugins known to write files into the output dir. A guard against
# undeclared file output, not a complete list: declare writes_files=True on anything that writes.
KNOWN_FILE_WRITING_FLAGS = frozenset({"--dump", "--dump-dir", "--dump-all"})
KNOWN_FILE_WRITING_PLUGINS = frozenset(
    {
        "windows.dumpfiles.DumpFiles",
        "windows.registry.hivelist.HiveList",  # with --dump
        "windows.memmap.Memmap",  # with --dump
        "linux.pagecache.InodePages",
    }
)
_PLUGIN_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*\.[A-Z][A-Za-z0-9_]*$")
_ARG_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")


def catalog_problems(plugins: list[PluginSpec]) -> dict[str, list[str]]:
    """Check catalog entries. Returns {plugin name: [problems]} for invalid ones (empty if all are
    fine). Checked: full dotted plugin name, duplicates, arg names/flags (format, duplicates,
    global vol flags), arg types, file-writing options declared, timeout, and presets."""
    problems: dict[str, list[str]] = {}
    seen: set[str] = set()
    for spec in plugins:
        errs: list[str] = []
        if not _PLUGIN_NAME_RE.match(spec.name):
            errs.append("name must be the full volatility3 plugin name, e.g. windows.pslist.PsList")
        if spec.name in seen:
            errs.append("listed more than once")
        seen.add(spec.name)
        arg_names: set[str] = set()
        flags: set[str] = set()
        for arg in spec.args:
            try:
                check_argspec(arg)
            except ArgValidationError as exc:
                errs.append(f"argument {arg.name!r}: {exc}")
            if not _ARG_NAME_RE.match(arg.name):
                errs.append(f"argument name {arg.name!r} must be snake_case")
            if arg.name in arg_names or arg.flag in flags:
                errs.append(f"argument {arg.name!r} / {arg.flag} declared twice")
            arg_names.add(arg.name)
            flags.add(arg.flag)
            if arg.flag in KNOWN_FILE_WRITING_FLAGS and not arg.writes_files:
                errs.append(f"{arg.flag} writes files: mark it writes_files=True")
        if spec.name in KNOWN_FILE_WRITING_PLUGINS and not spec.may_write_files:
            errs.append("this plugin writes files: mark it (or its dump option) writes_files=True")
        if spec.timeout_seconds is not None and spec.timeout_seconds <= 0:
            errs.append("timeout_seconds must be positive")
        if not errs:
            checker = _CatalogRunner([spec])
            for label, args in spec.presets:
                try:
                    checker.validate(ToolRequest(plugin=spec.name, args=args))
                except ArgValidationError as exc:
                    errs.append(f"preset {label!r}: {exc}")
        if errs:
            problems.setdefault(spec.name, []).extend(errs)
    return problems


_logged_problems: dict[str, list[str]] = {}


def check_argspec(spec: ArgSpec) -> None:
    """Sanity-check a catalog ArgSpec (catches catalog mistakes, not user input)."""
    if not _FLAG_RE.match(spec.flag):
        raise ArgValidationError(f"invalid flag in plugin catalog: {spec.flag!r}")
    if spec.flag in _GLOBAL_FLAGS:
        raise ArgValidationError(f"global vol flag not allowed in plugin catalog: {spec.flag!r}")
    if spec.type not in _COERCERS:
        raise ArgValidationError(f"unknown arg type in plugin catalog: {spec.type!r}")


def vol_command(executable: str) -> list[str]:
    """The command that starts volatility: ``FT_VOL_EXECUTABLE``, except that a ``.py`` script
    is run with the current Python interpreter. (Windows cannot execute scripts directly; this
    is how tests run tests/fixtures/fake_vol.py, and works the same on Linux/macOS.)"""
    path = Path(executable)
    if not path.is_absolute() and ("/" in executable or "\\" in executable):
        executable = str(path.resolve())
    if executable.lower().endswith(".py"):
        return [sys.executable, executable]
    return [executable]


class VolatilityRunner(ToolRunner):
    name = "volatility3"

    def __init__(self, offline: bool = False) -> None:
        # TODO: expose as a Settings field (e.g. FT_VOL_OFFLINE) once config.py is unfrozen.
        self.offline = offline

    def _catalog(self) -> list[PluginSpec]:
        return content.current().plugins

    def guide(self) -> InvestigationGuide:
        """The investigation guide from the plugin files' ``baseline`` / ``next``."""
        loaded = content.current()
        return InvestigationGuide(
            baseline=tuple(loaded.baseline),
            next={source: tuple(steps) for source, steps in loaded.next.items()},
        )

    def catalog_problems(self) -> dict[str, list[str]]:
        """Invalid catalog entries by plugin name, plus content files that failed to load (by
        file path; those plugins are missing from the catalog altogether)."""
        problems = {**content.current().problems, **catalog_problems(self._catalog())}
        global _logged_problems
        if problems != _logged_problems:  # log each new set of problems once
            _logged_problems = problems
            for name, errs in problems.items():
                logger.error("plugin catalog entry %s skipped: %s", name, "; ".join(errs))
        return problems

    def plugins(self) -> list[PluginSpec]:
        """Valid catalog entries only: invalid ones are skipped (see catalog_problems())."""
        bad = self.catalog_problems()
        return [p for p in self._catalog() if p.name not in bad]

    def validate(self, request: ToolRequest) -> dict[str, Any]:
        spec = self.get_plugin(request.plugin)
        if not isinstance(request.args, dict):
            raise ArgValidationError("args must be an object")
        known = {a.name: a for a in spec.args}
        unknown = sorted(set(request.args) - set(known))
        if unknown:
            raise ArgValidationError(
                f"unknown argument(s) for {spec.name}: {', '.join(map(repr, unknown))}"
            )
        normalized: dict[str, Any] = {}
        for arg in spec.args:
            check_argspec(arg)
            value = request.args.get(arg.name)
            # None / blank string (empty HTML form field) means "not given".
            if value is None or (isinstance(value, str) and not value.strip()):
                if arg.required:
                    raise ArgValidationError(f"missing required argument: {arg.name}")
                continue
            normalized[arg.name] = _COERCERS[arg.type](arg.name, value)
        return normalized

    def build_argv(self, evidence_path: Path, request: ToolRequest, output_dir: Path) -> list[str]:
        args = self.validate(request)
        spec = self.get_plugin(request.plugin)
        settings = get_settings()
        cache_dir = settings.data_dir.resolve() / "vol_cache"
        cache_dir.mkdir(parents=True, exist_ok=True)  # vol requires it to exist

        argv = [
            *vol_command(settings.vol_executable),
            "-q",
            "-r", "jsonl",
            "-s", str(settings.symbols_dir.resolve()),
            "--cache-path", str(cache_dir),
            "-o", str(output_dir.resolve()),
        ]  # fmt: skip
        if self.offline:
            argv.append("--offline")
        argv += ["-f", str(evidence_path.resolve()), spec.name]

        for arg in spec.args:  # catalog order => deterministic argv
            if arg.name not in args:
                continue
            value = args[arg.name]
            if arg.type == "bool":
                if value:
                    argv.append(arg.flag)
            elif arg.type == "int_list":
                argv.append(arg.flag)
                argv.extend(str(v) for v in value)
            else:
                argv += [arg.flag, str(value)]
        return argv

    def version(self) -> str | None:
        try:
            return importlib.metadata.version("volatility3")
        except importlib.metadata.PackageNotFoundError:
            return None

    def parse_output(self, stdout_path: Path) -> Iterator[ParsedRow]:
        """Parse volatility3 ``-r jsonl`` output.

        Verified in volatility3 2.28.2 cli/text_renderer.py (JsonRenderer/JsonLinesRenderer):
        stdout starts with an empty line, then one JSON object per TOP-LEVEL tree node
        (``sort_keys=True``). Each object maps column name -> value and has a ``"__children"``
        list holding child nodes of the same shape (nested recursively), so tree plugins such as
        pstree produce one line per root with the whole subtree nested in it. Flat plugins
        produce ``"__children": []``. Absent values are null; datetimes are ISO strings.

        Rows are flattened depth-first (pre-order); ``row_idx`` is the position in this stream,
        ``depth`` is 0 for roots and ``parent_idx`` the index of the parent row.

        TODO(forensics): validate against real captured output for every catalog plugin and add
        per-plugin post-processing (column renames, type fixes, summaries) where needed.
        """
        idx = 0
        with Path(stdout_path).open(encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, start=1):
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{stdout_path}: line {lineno}: invalid JSON: {exc}") from exc
                if not isinstance(obj, dict):
                    raise ValueError(
                        f"{stdout_path}: line {lineno}: expected JSON object, "
                        f"got {type(obj).__name__}"
                    )
                # Iterative DFS (avoid recursion limits on deep trees).
                stack: list[tuple[dict[str, Any], int, int | None]] = [(obj, 0, None)]
                while stack:
                    node, depth, parent = stack.pop()
                    children = node.get(CHILDREN_KEY) or []
                    if not isinstance(children, list):
                        raise ValueError(
                            f"{stdout_path}: line {lineno}: {CHILDREN_KEY} is not a list"
                        )
                    data = {k: v for k, v in node.items() if k != CHILDREN_KEY}
                    yield ParsedRow(data=data, depth=depth, parent_idx=parent)
                    my_idx = idx
                    idx += 1
                    for child in reversed(children):
                        if not isinstance(child, dict):
                            raise ValueError(
                                f"{stdout_path}: line {lineno}: child is not an object"
                            )
                        stack.append((child, depth + 1, my_idx))


class _CatalogRunner(VolatilityRunner):
    """Runner over a fixed plugin list, used to validate presets without recursion."""

    def __init__(self, plugins: list[PluginSpec]) -> None:
        super().__init__()
        self._plugins = plugins

    def plugins(self) -> list[PluginSpec]:
        return self._plugins
