"""Tool-runner contract. Every forensic tool (volatility3 now; others later) implements ToolRunner.

The infrastructure (job worker, API, UI, AI suggestion validation) depends only on this module,
never on tool-specific code.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

ArgType = Literal["str", "int", "bool", "int_list"]


class ArgValidationError(ValueError):
    """Raised when a plugin or argument is not allowlisted or a value is invalid."""


@dataclass(frozen=True)
class ArgSpec:
    name: str  # key used in ToolRequest.args, e.g. "pid"
    flag: str  # CLI flag, e.g. "--pid"
    type: ArgType
    help: str = ""
    required: bool = False
    # True if using this option makes the tool write files (e.g. --dump). Such options must be
    # declared: the catalog check refuses known file-writing flags that are not marked, and the
    # run form warns before using one.
    writes_files: bool = False


@dataclass(frozen=True)
class PluginSpec:
    name: str  # e.g. "windows.pslist.PsList"
    description: str = ""
    args: tuple[ArgSpec, ...] = ()
    auto_enumerate: bool = False  # include in the "auto-enumerate" batch
    # Hardcoded suggested queries shown in the UI: (label, args) pairs.
    presets: tuple[tuple[str, dict[str, Any]], ...] = ()
    # Timeout for this plugin in seconds; None = FT_RUN_TIMEOUT_SECONDS.
    timeout_seconds: int | None = None
    # True if the plugin always writes files (e.g. windows.dumpfiles.DumpFiles), whatever args.
    writes_files: bool = False
    # Comparison view (app/services/compare.py): the columns that identify "the same" row in two
    # images (e.g. process name + path), and extra columns to ignore when deciding whether a
    # row changed. Defaults when empty: all non-volatile columns identify a row.
    compare_keys: tuple[str, ...] = ()
    compare_ignore: tuple[str, ...] = ()

    @property
    def may_write_files(self) -> bool:
        return self.writes_files or any(a.writes_files for a in self.args)


@dataclass(frozen=True)
class ToolRequest:
    plugin: str
    args: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ParsedRow:
    data: dict[str, Any]
    depth: int = 0
    parent_idx: int | None = None


@dataclass
class ExecutionResult:
    argv: list[str]
    returncode: int | None
    stdout_path: Path
    stderr_path: Path
    stdout_sha256: str | None
    tool_version: str | None
    timed_out: bool = False
    cancelled: bool = False
    # True if the files the tool wrote to output_dir exceeded max_output_bytes and it was stopped.
    output_limit_exceeded: bool = False
    # Set if should_stop() asked the executor to stop early (e.g. the disk is nearly full).
    stop_reason: str | None = None


# Conditions a NEXT step can have (see app/tools/volatility/guide.py and docs there).
WHEN_SUCCEEDED = "succeeded"  # the source run succeeded (default)
WHEN_HAS_ROWS = "has_rows"  # ... and returned at least one row
WHEN_HAS_FLAGS = "has_flags"  # ... and a post-run hook flagged at least one row
WHEN_TAG_PREFIX = "tag:"  # "tag:<name>": ... and a hook flagged a row with that tag
WHEN_CONDITIONS = (WHEN_SUCCEEDED, WHEN_HAS_ROWS, WHEN_HAS_FLAGS)


@dataclass(frozen=True)
class GuideStep:
    """One recommendation in a tool's investigation guide.

    ``args`` use the ArgSpec names of the plugin (validated like manual input). ``when`` only
    applies to NEXT steps; ``priority`` ranks NEXT steps (higher first; baseline keeps its order).
    """

    plugin: str
    reason: str
    args: dict[str, Any] = field(default_factory=dict)
    when: str = WHEN_SUCCEEDED
    priority: int = 0


@dataclass(frozen=True)
class InvestigationGuide:
    """Baseline steps (in order) and plugin -> follow-up relationships. Content, not code: the
    volatility guide lives in app/tools/volatility/guide.py."""

    baseline: tuple[GuideStep, ...] = ()
    next: dict[str, tuple[GuideStep, ...]] = field(default_factory=dict)


class ToolRunner(ABC):
    name: str

    @abstractmethod
    def plugins(self) -> list[PluginSpec]:
        """Allowlisted plugins, in display order."""

    def catalog_problems(self) -> dict[str, list[str]]:
        """{plugin name: [problem, ...]} for catalog entries that were skipped as invalid."""
        return {}

    def guide(self) -> InvestigationGuide:
        """The tool's investigation guide (recommended next plugins). Empty by default."""
        return InvestigationGuide()

    def get_plugin(self, name: str) -> PluginSpec:
        for p in self.plugins():
            if p.name == name:
                return p
        raise ArgValidationError(f"plugin not allowed: {name!r}")

    @abstractmethod
    def validate(self, request: ToolRequest) -> dict[str, Any]:
        """Return normalised args or raise ArgValidationError. Must reject unknown args."""

    @abstractmethod
    def build_argv(self, evidence_path: Path, request: ToolRequest, output_dir: Path) -> list[str]:
        """Build the exact argv (no shell). Must call validate() first."""

    @abstractmethod
    def version(self) -> str | None:
        """Installed tool version string, or None if unavailable."""

    @abstractmethod
    def parse_output(self, stdout_path: Path) -> Iterator[ParsedRow]:
        """Yield parsed rows from the raw output file."""
