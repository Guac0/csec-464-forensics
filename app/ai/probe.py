"""Check how the configured AI provider behaves with the AI agent, and report a finished task.

Usage (natively, or inside the container: ``docker compose exec app python -m app.ai.probe``)::

    python -m app.ai.probe                 # provider check (needs FT_AI_* settings / .env)
    python -m app.ai.probe task 12         # summary of AI task 12 (needs the app's database)
    python -m app.ai.probe task 12 --with-reasoning

The provider check sends a few tiny, evidence-free requests: a plain answer, a native tool
call (and its round trip), and the text action protocol. It prints a JSON report (also saved
to ``ai_probe_report.json`` in the current folder). The API key is never printed.

The task report prints status, timing, tool protocol, every step (tool, options, result
summary), run requests and decisions, citation checks and the answer. It contains evidence
values from the answer and step summaries: review before sharing. Reasoning text is left out
unless ``--with-reasoning``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

from app.ai.client import AIClient, AIError

PROBE_TOOL = {
    "type": "function",
    "function": {
        "name": "get_time",
        "description": "Returns the current time in a time zone.",
        "parameters": {
            "type": "object",
            "properties": {"timezone": {"type": "string", "description": "e.g. UTC"}},
            "required": ["timezone"],
        },
    },
}
TEXT_PROTOCOL = (
    "You can call one tool by replying with exactly one fenced block and nothing else:\n\n"
    '```action\n{"tool": "get_time", "args": {"timezone": "UTC"}}\n```\n\n'
    "Tools:\n- get_time(timezone: string): Returns the current time in a time zone."
)
_ACTION_RE = re.compile(r"```[ \t]*action[ \t]*\r?\n(.*?)(?:```|\Z)", re.DOTALL | re.IGNORECASE)


def _excerpt(text: str | None, n: int = 300) -> str | None:
    if text is None:
        return None
    text = text.strip()
    return text if len(text) <= n else text[:n] + f"... [{len(text)} chars]"


def _call(client: AIClient, messages: list[dict[str, Any]], **kw: Any) -> dict[str, Any]:
    started = time.perf_counter()
    out: dict[str, Any] = {}
    try:
        result = client.chat(messages, **kw)
    except AIError as exc:
        out.update(ok=False, http_status=exc.status_code, error=_excerpt(str(exc), 500))
    else:
        message = (result.raw.get("choices") or [{}])[0].get("message") or {}
        out.update(
            ok=True,
            model_returned=result.model_returned,
            content=_excerpt(result.content),
            reasoning_chars=len(result.reasoning),
            reasoning_source=(
                "reasoning_content field"
                if message.get("reasoning_content") or message.get("reasoning")
                else ("<think> tags" if result.reasoning else None)
            ),
            tool_calls=[
                {"id": c.id, "name": c.name, "arguments": c.arguments, "raw": c.raw_arguments}
                for c in result.tool_calls
            ],
            finish_reason=(result.raw.get("choices") or [{}])[0].get("finish_reason"),
            usage=result.usage,
        )
        out["_result"] = result
    out["seconds"] = round(time.perf_counter() - started, 2)
    return out


def probe_provider(client: AIClient | None = None) -> dict[str, Any]:
    from app.config import get_settings
    from app.services.app_settings import get_value

    settings = get_settings()
    client = client or AIClient(settings)
    report: dict[str, Any] = {
        "config": {
            "base_url": settings.ai_base_url,
            "model": settings.ai_model,
            "api_key_set": bool(settings.ai_api_key),
            "temperature": settings.ai_temperature,
            "max_tokens": settings.ai_max_tokens,
            "timeout_seconds": settings.ai_timeout_seconds,
            "tool_mode": get_value("ai_tool_mode"),
        }
    }

    plain = _call(client, [{"role": "user", "content": "Reply with exactly the word: OK"}])
    plain.pop("_result", None)
    report["plain_answer"] = plain

    question = [{"role": "user", "content": "What time is it in UTC? Use the get_time tool."}]
    native = _call(client, question, tools=[PROBE_TOOL])
    result = native.pop("_result", None)
    native["action_block_in_content"] = bool(result and _ACTION_RE.search(result.content or ""))
    report["native_tool_call"] = native
    if result is not None and result.tool_calls:
        call = result.tool_calls[0]
        follow = [
            *question,
            {
                "role": "assistant",
                "content": result.content or "",
                "tool_calls": [
                    {
                        "id": call.id,
                        "type": "function",
                        "function": {"name": call.name, "arguments": call.raw_arguments or "{}"},
                    }
                ],
            },
            {"role": "tool", "tool_call_id": call.id, "content": "2026-01-01T12:00:00Z"},
        ]
        round_trip = _call(client, follow, tools=[PROBE_TOOL])
        round_trip.pop("_result", None)
        round_trip["mentions_tool_result"] = "12:00" in (round_trip.get("content") or "")
        report["native_tool_round_trip"] = round_trip

    text = _call(
        client,
        [
            {"role": "system", "content": TEXT_PROTOCOL},
            {"role": "user", "content": "What time is it in UTC?"},
        ],
    )
    result = text.pop("_result", None)
    block = _ACTION_RE.search(result.content or "") if result is not None else None
    parsed = None
    if block:
        try:
            parsed = json.loads(block.group(1).strip())
        except ValueError:
            parsed = "INVALID JSON"
    text["action_block"] = parsed
    report["text_protocol"] = text

    native_ok = bool(report["native_tool_call"].get("tool_calls"))
    text_ok = isinstance(parsed, dict) and parsed.get("tool") == "get_time"
    report["verdict"] = {
        "plain_answer_works": bool(plain.get("ok")),
        "native_tool_calling_works": native_ok,
        "text_protocol_works": text_ok,
        "auto_mode_would_use": "native" if native_ok else ("text" if text_ok else "neither"),
        "reasoning_returned": bool(plain.get("reasoning_chars")),
    }
    return report


def task_report(task_id: int, with_reasoning: bool = False) -> dict[str, Any]:
    from app.ai import agent
    from app.db import SessionLocal, init_engine
    from app.models import AIMessage

    init_engine()
    with SessionLocal() as session:
        task = agent.get_task(session, task_id)
        v = agent.view(task, session)
        answer = session.get(AIMessage, task.answer_message_id) if task.answer_message_id else None
        report: dict[str, Any] = {
            "task": {
                k: v.as_dict()[k]
                for k in (
                    "id",
                    "status",
                    "goal",
                    "limits",
                    "tool_mode",
                    "steps_used",
                    "elapsed_s",
                    "paused_s",
                    "error",
                    "usage",
                    "approve_all",
                )
            },  # fmt: skip
            "resumed_count": task.resumed_count,
            "steps": [
                {
                    "turn": s.turn,
                    "kind": s.kind,
                    "tool": s.tool,
                    "args": s.args,
                    "summary": s.summary,
                    "rows": len(s.row_keys or []),
                    "ms": s.duration_ms,
                }
                for s in task.steps
            ],
            "run_requests": [
                {
                    k: r[k]
                    for k in (
                        "plugin",
                        "args",
                        "final_args",
                        "status",
                        "note",
                        "run_id",
                        "run_status",
                        "run_elapsed_s",
                        "estimate_s",
                    )
                }  # fmt: skip
                for r in v.runs
            ],
        }
        if answer is not None:
            report["answer"] = {
                "content": answer.content,
                "model_returned": answer.model_returned,
                "prompt_version": (answer.params or {}).get("prompt_version"),
                "citations": [
                    {
                        "key": c.get("key"),
                        "valid": c.get("valid"),
                        "support": c.get("support"),
                        "unsupported_values": c.get("unsupported_values"),
                    }  # fmt: skip
                    for c in answer.citations or []
                ],
                "suggestions": [
                    {"plugin": s.get("plugin"), "valid": s.get("valid"), "error": s.get("error")}
                    for s in answer.suggestions or []
                ],
                "reasoning_chars": len(answer.reasoning or ""),
                "model_calls": sum(
                    1 for m in answer.request_messages or [] if m.get("role") == "assistant"
                )
                + 1,
            }
            if with_reasoning:
                report["answer"]["reasoning"] = answer.reasoning
        return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.ai.probe", description=__doc__)
    sub = parser.add_subparsers(dest="command")
    task = sub.add_parser("task", help="summarise a finished AI task")
    task.add_argument("task_id", type=int)
    task.add_argument("--with-reasoning", action="store_true")
    parser.add_argument("--out", default="ai_probe_report.json", help="also save the JSON here")
    args = parser.parse_args(argv)
    if args.command == "task":
        report = task_report(args.task_id, args.with_reasoning)
    else:
        report = probe_provider()
    text = json.dumps(report, indent=2, default=str, ensure_ascii=False)
    sys.stdout.write(text + "\n")
    try:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        sys.stderr.write(f"\nSaved to {args.out}\n")
    except OSError as exc:
        sys.stderr.write(f"\nCould not save {args.out}: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
