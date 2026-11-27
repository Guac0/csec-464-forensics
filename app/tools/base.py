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


class ToolRunner(ABC):
    name: str

    @abstractmethod
    def plugins(self) -> list[PluginSpec]:
        """Allowlisted plugins, in display order."""

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
