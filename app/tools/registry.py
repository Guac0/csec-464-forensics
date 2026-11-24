"""Registry of available ToolRunners. Add new tools to ``_FACTORIES``."""

from __future__ import annotations

import threading
from collections.abc import Callable

from app.tools.base import ToolRunner


def _volatility() -> ToolRunner:
    from app.config import get_settings
    from app.tools.volatility.runner import VolatilityRunner

    return VolatilityRunner(offline=get_settings().vol_offline)


# name -> zero-arg factory. Runners must be stateless (settings are read at call time),
# so a single cached instance per name is safe to share across threads.
_FACTORIES: dict[str, Callable[[], ToolRunner]] = {
    "volatility3": _volatility,
}


def available_tools() -> list[str]:
    return list(_FACTORIES)


_instances: dict[str, ToolRunner] = {}
_lock = threading.Lock()


def get_runner(name: str = "volatility3") -> ToolRunner:
    """Return the (cached) runner for ``name``; raise KeyError for unknown tools."""
    with _lock:
        if name not in _instances:
            try:
                factory = _FACTORIES[name]
            except KeyError:
                raise KeyError(
                    f"unknown tool {name!r}; available tools: {', '.join(available_tools())}"
                ) from None
            _instances[name] = factory()
        return _instances[name]
