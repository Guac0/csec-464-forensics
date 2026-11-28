"""Minimal synchronous client for an OpenAI-compatible chat completions endpoint."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.config import Settings

# Request parameters the caller may override per call (besides messages).
_ALLOWED_OVERRIDES = frozenset({"model", "temperature", "max_tokens", "top_p", "seed", "stop"})


class AIError(Exception):
    """Provider call failed (HTTP error, timeout, network error or malformed response)."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


# Reasoning models (e.g. Qwen3, DeepSeek-R1) may put their chain of thought in <think> tags in
# the content. It is kept in AIResult.reasoning (provenance) but never shown as the answer.
_THINK_RE = re.compile(r"<think>(.*?)(?:</think>|\Z)", re.DOTALL | re.IGNORECASE)


def split_reasoning(content: str) -> tuple[str, str]:
    """(answer without <think> blocks, the reasoning text)."""
    reasoning = "\n".join(m.strip() for m in _THINK_RE.findall(content or ""))
    return _THINK_RE.sub("", content or "").strip(), reasoning


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any] | None  # None if the model sent invalid JSON
    raw_arguments: str = ""


@dataclass
class AIResult:
    content: str
    model_requested: str
    model_returned: str | None
    params: dict[str, Any]  # everything sent in the request body except "messages"
    usage: dict[str, Any] | None
    raw: dict[str, Any] = field(repr=False)
    tool_calls: list[ToolCall] = field(default_factory=list)
    reasoning: str = ""  # <think> text / reasoning_content, if the model returned any


class AIClient:
    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None) -> None:
        self.settings = settings
        self.transport = transport

    @property
    def base_url(self) -> str:
        return self.settings.ai_base_url.rstrip("/")

    def build_params(self, **overrides: Any) -> dict[str, Any]:
        unknown = set(overrides) - _ALLOWED_OVERRIDES
        if unknown:
            raise ValueError(f"unsupported AI parameter override(s): {sorted(unknown)}")
        params: dict[str, Any] = {
            "model": self.settings.ai_model,
            "temperature": self.settings.ai_temperature,
            "max_tokens": self.settings.ai_max_tokens,
        }
        params.update({k: v for k, v in overrides.items() if v is not None})
        return params

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        **overrides: Any,
    ) -> AIResult:
        """One chat completion. ``tools``: OpenAI function-calling tool specs (optional)."""
        params = self.build_params(**overrides)
        body: dict[str, Any] = {**params, "messages": messages}
        if tools:
            body["tools"] = tools
        headers = {"Content-Type": "application/json"}
        if self.settings.ai_api_key:
            headers["Authorization"] = f"Bearer {self.settings.ai_api_key}"
        url = f"{self.base_url}/chat/completions"

        try:
            with httpx.Client(
                transport=self.transport, timeout=self.settings.ai_timeout_seconds
            ) as http:
                resp = http.post(url, json=body, headers=headers)
        except httpx.TimeoutException as exc:
            raise AIError(
                f"AI provider timed out after {self.settings.ai_timeout_seconds}s ({url})"
            ) from exc
        except httpx.HTTPError as exc:
            raise AIError(f"AI provider request failed ({url}): {exc}") from exc

        if resp.status_code >= 400:
            detail = resp.text[:500]
            raise AIError(
                f"AI provider returned HTTP {resp.status_code} ({url}): {detail}",
                status_code=resp.status_code,
            )

        try:
            raw = resp.json()
        except ValueError as exc:
            raise AIError(f"AI provider returned non-JSON response ({url})") from exc
        if not isinstance(raw, dict):
            raise AIError("AI provider response is not a JSON object")

        try:
            message = raw["choices"][0]["message"]
            content = message.get("content")
        except (KeyError, IndexError, TypeError, AttributeError) as exc:
            raise AIError("AI provider response missing choices[0].message.content") from exc
        tool_calls = _parse_tool_calls(message.get("tool_calls"))
        if content is None and tool_calls:
            content = ""
        if not isinstance(content, str):
            raise AIError("AI provider response content is not a string")
        content, reasoning = split_reasoning(content)
        extra = message.get("reasoning_content") or message.get("reasoning")
        if isinstance(extra, str) and extra.strip():
            reasoning = "\n".join(p for p in (extra.strip(), reasoning) if p)

        usage = raw.get("usage")
        model_returned = raw.get("model")
        return AIResult(
            content=content,
            model_requested=str(params["model"]),
            model_returned=model_returned if isinstance(model_returned, str) else None,
            params=params,
            usage=usage if isinstance(usage, dict) else None,
            raw=raw,
            tool_calls=tool_calls,
            reasoning=reasoning,
        )


def _parse_tool_calls(value: Any) -> list[ToolCall]:
    calls: list[ToolCall] = []
    for n, item in enumerate(value if isinstance(value, list) else []):
        fn = item.get("function") if isinstance(item, dict) else None
        if not isinstance(fn, dict) or not isinstance(fn.get("name"), str):
            continue
        raw_args = fn.get("arguments")
        args: dict[str, Any] | None
        if isinstance(raw_args, dict):
            args, raw_args = raw_args, json.dumps(raw_args)
        else:
            try:
                parsed = json.loads(raw_args or "{}")
            except (TypeError, ValueError):
                parsed = None
            args = parsed if isinstance(parsed, dict) else None
        calls.append(
            ToolCall(
                id=str(item.get("id") or f"call_{n}"),
                name=fn["name"],
                arguments=args,
                raw_arguments=str(raw_args or ""),
            )
        )
    return calls
