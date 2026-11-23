"""Parse and validate AI-suggested tool queries.

The model may append a final fenced block::

    ```suggestions
    [{"plugin": "windows.pslist.PsList", "args": {"pid": [4]}, "reason": "..."}]
    ```

Suggestions are never executed here; they are validated against the tool allowlist and shown
to the analyst as "Run" buttons.
"""

from __future__ import annotations

import json
import re
from typing import Any

from app.tools.base import ArgValidationError, ToolRequest

MAX_SUGGESTIONS = 5

_BLOCK_RE = re.compile(r"```[ \t]*suggestions[ \t]*\r?\n(.*?)(?:```|\Z)", re.DOTALL | re.IGNORECASE)


def _last_block(text: str) -> re.Match[str] | None:
    matches = list(_BLOCK_RE.finditer(text or ""))
    return matches[-1] if matches else None


def parse_suggestions(text: str) -> list[dict[str, Any]]:
    """Items from the last ```suggestions block; [] if absent or malformed."""
    m = _last_block(text)
    if m is None:
        return []
    try:
        data = json.loads(m.group(1).strip())
    except ValueError:
        return []
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)][:MAX_SUGGESTIONS]


def strip_suggestions_block(text: str) -> str:
    """Remove all ```suggestions blocks from the text."""
    return _BLOCK_RE.sub("", text or "").rstrip()


def validate_suggestions(
    items: list[dict[str, Any]], tool: str = "volatility3"
) -> list[dict[str, Any]]:
    """Validate each suggestion against the tool allowlist.

    Returns {"plugin", "args", "reason", "tool", "valid", "normalized_args" | "error"} per item.
    """
    from app.tools import registry  # imported lazily so tests can substitute it

    runner = registry.get_runner(tool)
    out: list[dict[str, Any]] = []
    for item in items[:MAX_SUGGESTIONS]:
        plugin = item.get("plugin")
        args = item.get("args") or {}
        reason = item.get("reason")
        result: dict[str, Any] = {
            "tool": tool,
            "plugin": plugin,
            "args": args,
            "reason": str(reason) if reason is not None else "",
        }
        if not isinstance(plugin, str) or not plugin:
            result.update(valid=False, error="missing plugin name")
        elif not isinstance(args, dict):
            result.update(valid=False, error="args must be an object")
        else:
            try:
                normalized = runner.validate(ToolRequest(plugin=plugin, args=dict(args)))
            except ArgValidationError as exc:
                result.update(valid=False, error=str(exc))
            else:
                result.update(valid=True, normalized_args=normalized)
        out.append(result)
    return out
