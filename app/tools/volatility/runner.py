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
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from app.config import get_settings
from app.tools.base import (
    ArgSpec,
    ArgValidationError,
    ParsedRow,
    PluginSpec,
    ToolRequest,
    ToolRunner,
)
from app.tools.volatility import plugins as plugin_catalog

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


def check_argspec(spec: ArgSpec) -> None:
    """Sanity-check a catalog ArgSpec (catches catalog mistakes, not user input)."""
    if not _FLAG_RE.match(spec.flag):
        raise ArgValidationError(f"invalid flag in plugin catalog: {spec.flag!r}")
    if spec.flag in _GLOBAL_FLAGS:
        raise ArgValidationError(f"global vol flag not allowed in plugin catalog: {spec.flag!r}")
    if spec.type not in _COERCERS:
        raise ArgValidationError(f"unknown arg type in plugin catalog: {spec.type!r}")


class VolatilityRunner(ToolRunner):
    name = "volatility3"

    def __init__(self, offline: bool = False) -> None:
        # TODO: expose as a Settings field (e.g. FT_VOL_OFFLINE) once config.py is unfrozen.
        self.offline = offline

    def plugins(self) -> list[PluginSpec]:
        return plugin_catalog.PLUGINS

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
        cache_dir = settings.data_dir / "vol_cache"
        cache_dir.mkdir(parents=True, exist_ok=True)  # vol requires it to exist

        argv = [
            settings.vol_executable,
            "-q",
            "-r", "jsonl",
            "-s", str(settings.symbols_dir),
            "--cache-path", str(cache_dir),
            "-o", str(output_dir),
        ]  # fmt: skip
        if self.offline:
            argv.append("--offline")
        argv += ["-f", str(evidence_path), spec.name]

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
