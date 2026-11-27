"""Shared helpers for the AI-layer tests (no tests here; imported by tests/test_ai_*.py)."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy.orm import Session

from app.models import Evidence, Note, ResultRow, Run, RunStatus
from app.tools import registry
from app.tools.base import (
    ArgSpec,
    ArgValidationError,
    ParsedRow,
    PluginSpec,
    ToolRequest,
    ToolRunner,
)

PSLIST = "windows.pslist.PsList"
MALFIND = "windows.malfind.Malfind"


class FakeRunner(ToolRunner):
    name = "volatility3"

    def plugins(self) -> list[PluginSpec]:
        return [
            PluginSpec(
                name=PSLIST,
                description="List processes",
                args=(ArgSpec("pid", "--pid", "int_list", "Filter PIDs"),),
            ),
            PluginSpec(name=MALFIND, description="Find injected code"),
        ]

    def validate(self, request: ToolRequest) -> dict[str, Any]:
        spec = self.get_plugin(request.plugin)
        allowed = {a.name: a for a in spec.args}
        out: dict[str, Any] = {}
        for key, value in request.args.items():
            if key not in allowed:
                raise ArgValidationError(f"unknown arg {key!r} for {spec.name}")
            if allowed[key].type == "int_list":
                values = value if isinstance(value, list) else [value]
                try:
                    out[key] = [int(v) for v in values]
                except (TypeError, ValueError) as exc:
                    raise ArgValidationError(f"{key} must be a list of int") from exc
            else:
                out[key] = value
        return out

    def build_argv(self, evidence_path: Path, request: ToolRequest, output_dir: Path) -> list[str]:
        return ["vol", "-f", str(evidence_path), request.plugin]

    def version(self) -> str | None:
        return "fake"

    def parse_output(self, stdout_path: Path) -> Iterator[ParsedRow]:
        return iter(())


def install_fake_runner(monkeypatch: pytest.MonkeyPatch) -> FakeRunner:
    runner = FakeRunner()
    monkeypatch.setattr(registry, "get_runner", lambda name="volatility3": runner)
    return runner


def _case_id(session: Session) -> int:
    from app.models import Case

    case = Case(name="Seed case")
    session.add(case)
    session.flush()
    return case.id


def seed(session: Session, n_rows: int = 3) -> tuple[Evidence, Run]:
    """One evidence item with one succeeded pslist run (n_rows rows), one failed run, notes."""
    ev = Evidence(
        rel_path="sample.raw",
        size_bytes=4096,
        mtime=0.0,
        sha256="ab" * 32,
        os_info={"os": "windows", "build": "19041"},
        description="Test image",
    )
    session.add(ev)
    session.flush()
    run = Run(
        evidence_id=ev.id, plugin=PSLIST, args={}, status=RunStatus.SUCCEEDED, row_count=n_rows
    )
    failed = Run(evidence_id=ev.id, plugin=MALFIND, status=RunStatus.FAILED, error="boom")
    session.add_all([run, failed])
    session.flush()
    for i in range(n_rows):
        session.add(
            ResultRow(run_id=run.id, row_idx=i, data={"PID": 100 + i, "ImageFileName": f"p{i}.exe"})
        )
    session.add_all(
        [
            Note(evidence_id=ev.id, body="evidence note"),
            Note(evidence_id=None, case_id=_case_id(session), body="case note"),
        ]
    )
    session.commit()
    return ev, run


def chat_response(content: str, model: str = "test-model-2025", **extra: Any) -> dict[str, Any]:
    return {
        "id": "chatcmpl-1",
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        **extra,
    }


def mock_transport(
    handler: Callable[[httpx.Request], httpx.Response], sink: list[dict[str, Any]] | None = None
) -> httpx.MockTransport:
    """MockTransport that records each request (url, headers, json body) into ``sink``."""

    def _wrapped(request: httpx.Request) -> httpx.Response:
        if sink is not None:
            sink.append(
                {
                    "url": str(request.url),
                    "headers": dict(request.headers),
                    "json": json.loads(request.content),
                }
            )
        return handler(request)

    return httpx.MockTransport(_wrapped)


def respond_with(content: str) -> Callable[[httpx.Request], httpx.Response]:
    return lambda request: httpx.Response(200, json=chat_response(content))
