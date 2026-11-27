"""Fake ToolRunner / executor shared by the backend tests (no volatility, no registry needed).

Named test_backend_* to stay within backend ownership; it contains no tests itself.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from app.tools.base import (
    ArgSpec,
    ArgValidationError,
    ExecutionResult,
    ParsedRow,
    PluginSpec,
    ToolRequest,
    ToolRunner,
)


class FakeRunner(ToolRunner):
    name = "volatility3"

    def __init__(self) -> None:
        self.fail_parse_after: int | None = None

    def plugins(self) -> list[PluginSpec]:
        return [
            PluginSpec("windows.info.Info", auto_enumerate=True),
            PluginSpec(
                "windows.pslist.PsList",
                auto_enumerate=True,
                args=(ArgSpec("pid", "--pid", "int_list"),),
            ),
            PluginSpec("windows.pstree.PsTree"),
        ]

    def validate(self, request: ToolRequest) -> dict[str, Any]:
        spec = self.get_plugin(request.plugin)
        allowed = {a.name: a for a in spec.args}
        out: dict[str, Any] = {}
        for key, value in request.args.items():
            if key not in allowed:
                raise ArgValidationError(f"unknown argument {key!r} for {request.plugin}")
            if not isinstance(value, list) or not all(isinstance(v, int) for v in value):
                raise ArgValidationError(f"{key} must be a list of integers")
            out[key] = value
        return out

    def build_argv(self, evidence_path: Path, request: ToolRequest, output_dir: Path) -> list[str]:
        self.validate(request)
        return ["vol", "-f", str(evidence_path), request.plugin]

    def version(self) -> str | None:
        return "fake-1.0"

    def parse_output(self, stdout_path: Path) -> Iterator[ParsedRow]:
        with stdout_path.open() as f:
            for i, line in enumerate(f):
                if self.fail_parse_after is not None and i >= self.fail_parse_after:
                    raise ValueError("bad line")
                obj = json.loads(line)
                yield ParsedRow(data=obj, depth=obj.get("depth", 0), parent_idx=obj.get("parent"))


def make_fake_execute(
    rows: list[dict[str, Any]],
    returncode: int = 0,
    stderr: str = "",
    block_until_cancel: bool = False,
    timed_out: bool = False,
) -> Callable[..., ExecutionResult]:
    """Build an execute() replacement that writes ``rows`` as JSONL into run_dir."""

    def fake_execute(
        runner: ToolRunner,
        evidence_path: Path,
        request: ToolRequest,
        run_dir: Path,
        timeout: float,
        cancel_event: threading.Event,
        on_heartbeat: Callable[[], None] | None = None,
        **_kwargs: Any,
    ) -> ExecutionResult:
        stdout = run_dir / "stdout.jsonl"
        stderr_path = run_dir / "stderr.txt"
        cancelled = False
        if on_heartbeat:
            on_heartbeat()
        if block_until_cancel:
            cancelled = cancel_event.wait(10)
        stdout.write_text("".join(json.dumps(r) + "\n" for r in rows))
        stderr_path.write_text(stderr)
        return ExecutionResult(
            argv=runner.build_argv(evidence_path, request, run_dir),
            returncode=None if (cancelled or timed_out) else returncode,
            stdout_path=stdout,
            stderr_path=stderr_path,
            stdout_sha256=hashlib.sha256(stdout.read_bytes()).hexdigest(),
            tool_version=runner.version(),
            timed_out=timed_out,
            cancelled=cancelled,
        )

    return fake_execute


def install_fake_runner(monkeypatch: pytest.MonkeyPatch) -> FakeRunner:
    """Patch app.services.runs.get_runner (used by services and worker) with a FakeRunner."""
    from app.services import runs

    runner = FakeRunner()
    monkeypatch.setattr(runs, "get_runner", lambda name="volatility3": runner)
    return runner
