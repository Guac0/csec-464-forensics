"""Minimal synchronous client for an OpenAI-compatible chat completions endpoint."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

from app.config import Settings

# Request parameters the caller may override per call (besides messages).
_ALLOWED_OVERRIDES = frozenset({"model", "temperature", "max_tokens", "top_p", "seed", "stop"})


class AIError(Exception):
    """Provider call failed (HTTP error, timeout, network error or malformed response)."""


@dataclass
class AIResult:
    content: str
    model_requested: str
    model_returned: str | None
    params: dict[str, Any]  # everything sent in the request body except "messages"
    usage: dict[str, Any] | None
    raw: dict[str, Any] = field(repr=False)


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

    def chat(self, messages: list[dict[str, Any]], **overrides: Any) -> AIResult:
        params = self.build_params(**overrides)
        body = {**params, "messages": messages}
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
            raise AIError(f"AI provider returned HTTP {resp.status_code} ({url}): {detail}")

        try:
            raw = resp.json()
        except ValueError as exc:
            raise AIError(f"AI provider returned non-JSON response ({url})") from exc
        if not isinstance(raw, dict):
            raise AIError("AI provider response is not a JSON object")

        try:
            content = raw["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise AIError("AI provider response missing choices[0].message.content") from exc
        if not isinstance(content, str):
            raise AIError("AI provider response content is not a string")

        usage = raw.get("usage")
        model_returned = raw.get("model")
        return AIResult(
            content=content,
            model_requested=str(params["model"]),
            model_returned=model_returned if isinstance(model_returned, str) else None,
            params=params,
            usage=usage if isinstance(usage, dict) else None,
            raw=raw,
        )
