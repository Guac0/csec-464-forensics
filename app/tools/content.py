"""Forensics content loader: one Python file per plugin under ``<root>/plugins/<os>/``.

The forensics team writes content in the top-level ``forensics/`` package using the names
re-exported by ``forensics/sdk.py``; this module turns those files into the catalog
(``PluginSpec`` list) and the ``InvestigationGuide`` used by the volatility runner.

Layout (root = ``forensics`` in production, ``tests.content`` in infrastructure tests):

- ``<root>/plugins/<os>/<rest>.py``: one module per plugin, defining ``PLUGIN = Plugin(...)``.
  Expected path for ``windows.malware.malfind.Malfind`` is ``plugins/windows/malware_malfind.py``
  (``expected_module``); checked by tests/test_forensics_content.py, not at runtime.
- ``<root>/hooks/``: cross-plugin hook modules (imported by app.tools.hooks).
- Modules/packages whose name starts with ``_`` are skipped (``_template.py``).

Load problems (import errors, missing/invalid ``PLUGIN``, duplicate names) are returned keyed by
module file (``forensics/plugins/windows/x.py``); the runner merges them into
``catalog_problems()`` so they show on the System page, and the file is skipped.

Catalog order: sorted by plugin name. Baseline order: ``Baseline.order`` then plugin name.
Tests replace content with ``use_root()`` or by monkeypatching attributes of ``current()``.
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from app.tools.base import ArgSpec, GuideStep, PluginSpec

logger = logging.getLogger(__name__)

DEFAULT_ROOT = "forensics"


# --------------------------------------------------------------------------------------------
# Authoring types (re-exported by forensics/sdk.py)
# --------------------------------------------------------------------------------------------


def Preset(label: str, **args: Any) -> tuple[str, dict[str, Any]]:  # noqa: N802 (reads as a type)
    """One-click suggested query: ``Preset("PID 4 (System)", pid=[4])``."""
    return (label, dict(args))


@dataclass(frozen=True)
class Baseline:
    """Place in the baseline (standard first pass). Lower ``order`` runs first."""

    order: int
    reason: str
    args: dict[str, Any] = field(default_factory=dict)


@dataclass
class Plugin:
    """Everything about one plugin. ``spec`` is what the runner uses; ``baseline`` / ``next``
    feed the investigation guide (``next`` = steps suggested after THIS plugin ran)."""

    name: str
    description: str = ""
    args: Iterable[ArgSpec] = ()
    presets: Iterable[tuple[str, dict[str, Any]]] = ()
    auto_enumerate: bool = False
    timeout_seconds: int | None = None
    writes_files: bool = False
    compare_keys: Iterable[str] = ()
    compare_ignore: Iterable[str] = ()
    baseline: Baseline | Iterable[Baseline] | None = None
    next: Iterable[GuideStep] = ()

    @property
    def spec(self) -> PluginSpec:
        return PluginSpec(
            name=self.name,
            description=self.description,
            args=tuple(self.args),
            auto_enumerate=self.auto_enumerate,
            presets=tuple((label, dict(args)) for label, args in self.presets),
            timeout_seconds=self.timeout_seconds,
            writes_files=self.writes_files,
            compare_keys=tuple(self.compare_keys),
            compare_ignore=tuple(self.compare_ignore),
        )

    def baseline_entries(self) -> list[Baseline]:
        if self.baseline is None:
            return []
        if isinstance(self.baseline, Baseline):
            return [self.baseline]
        return list(self.baseline)

    def post_run(
        self, version: str = "1", name: str | None = None, description: str | None = None
    ) -> Callable[[Callable[..., None]], Callable[..., None]]:
        """Decorator: register a post-run hook for this plugin (see app/tools/hooks.py)."""
        from app.tools import hooks

        def decorator(func: Callable[..., None]) -> Callable[..., None]:
            hook_name = name or f"{_short_module(func.__module__)}.{func.__name__}"
            return hooks.post_run(
                self.name, name=hook_name, version=version, description=description
            )(func)

        return decorator


def _short_module(module: str) -> str:
    """``forensics.plugins.windows.info`` -> ``windows.info`` (stable hook names)."""
    parts = module.split(".")
    if "plugins" in parts:
        return ".".join(parts[parts.index("plugins") + 1 :])
    return parts[-1]


def expected_module(plugin_name: str) -> str:
    """Module path (below ``plugins``) a plugin's file should have:
    ``windows.malware.malfind.Malfind`` -> ``windows.malware_malfind``."""
    parts = plugin_name.split(".")
    if len(parts) < 3:
        return ""
    return f"{parts[0]}.{'_'.join(parts[1:-1])}"


# --------------------------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------------------------


@dataclass
class Content:
    root: str
    plugins: list[PluginSpec] = field(default_factory=list)
    baseline: list[GuideStep] = field(default_factory=list)
    next: dict[str, list[GuideStep]] = field(default_factory=dict)
    problems: dict[str, list[str]] = field(default_factory=dict)
    modules: dict[str, str] = field(default_factory=dict)  # plugin name -> module (below plugins)


def module_file(module: str) -> str:
    return module.replace(".", "/") + ".py"


def iter_modules(package_name: str) -> Iterable[str]:
    """Import ``package_name`` and yield its module names recursively (skipping ``_*``).
    Raises if the package itself can't be imported."""
    package = importlib.import_module(package_name)
    for mod in sorted(
        pkgutil.walk_packages(package.__path__, prefix=f"{package_name}."), key=lambda m: m.name
    ):
        rel = mod.name[len(package_name) + 1 :]
        if any(part.startswith("_") for part in rel.split(".")) or mod.ispkg:
            continue
        yield mod.name


def load(root: str = DEFAULT_ROOT) -> Content:
    content = Content(root=root)
    package_name = f"{root}.plugins"
    found: list[tuple[str, Plugin]] = []
    try:
        names = list(iter_modules(package_name))
    except Exception as exc:  # noqa: BLE001
        content.problems[package_name.replace(".", "/") + "/"] = [f"{type(exc).__name__}: {exc}"]
        logger.exception("cannot import forensics content package %s", package_name)
        return content
    for module_name in names:
        where = module_file(module_name)
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:  # noqa: BLE001
            content.problems[where] = [f"{type(exc).__name__}: {exc}"]
            logger.exception("forensics content %s failed to import; skipping", where)
            continue
        plugin = getattr(module, "PLUGIN", None)
        if not isinstance(plugin, Plugin):
            content.problems[where] = ["no `PLUGIN = Plugin(...)` in this file"]
            continue
        found.append((module_name, plugin))

    seen: dict[str, str] = {}
    baseline: list[tuple[int, str, GuideStep]] = []
    for module_name, plugin in found:
        where = module_file(module_name)
        if plugin.name in seen:
            content.problems[where] = [f"{plugin.name} is already defined in {seen[plugin.name]}"]
            continue
        try:
            spec = plugin.spec
            entries = plugin.baseline_entries()
            next_steps = list(plugin.next)
        except Exception as exc:  # noqa: BLE001  (e.g. a non-iterable where a list belongs)
            content.problems[where] = [f"{type(exc).__name__}: {exc}"]
            continue
        seen[plugin.name] = where
        content.plugins.append(spec)
        content.modules[plugin.name] = module_name[len(package_name) + 1 :]
        for entry in entries:
            step = GuideStep(plugin.name, entry.reason, dict(entry.args))
            baseline.append((entry.order, plugin.name, step))
        if next_steps:
            content.next[plugin.name] = next_steps
    content.plugins.sort(key=lambda p: p.name)
    content.baseline = [step for _, _, step in sorted(baseline, key=lambda t: (t[0], t[1]))]
    return content


# Content files register hooks when imported, and hook loading imports the same files, so both
# use the hook registry's lock (always taken in this order) to avoid an import deadlock between
# a worker thread and a request thread.
_lock = threading.RLock()
_root = DEFAULT_ROOT
_current: Content | None = None


def current() -> Content:
    """The loaded content (loaded once; ``reload()`` / ``use_root()`` to refresh)."""
    global _current
    from app.tools import hooks

    with hooks.registry_lock(), _lock:
        if _current is None:
            _current = load(_root)
        return _current


def reload() -> Content:
    """Re-import every content file (picks up edits without a restart)."""
    global _current
    from app.tools import hooks

    with hooks.registry_lock(), _lock:
        hooks.load_hooks(force=True)  # re-imports plugin + hook modules
        _current = load(_root)
        return _current


def root() -> str:
    return _root


def use_root(new_root: str) -> Content:
    """Switch the content package (tests). Also points hook loading at ``<root>.plugins`` and
    ``<root>.hooks`` and clears registered hooks so they are re-imported from the new root."""
    global _root, _current
    from app.tools import hooks

    with hooks.registry_lock(), _lock:
        _root = new_root
        hooks.set_packages((f"{new_root}.plugins", f"{new_root}.hooks"))
        hooks.load_hooks(force=True)  # (re-)imports the new root's modules, re-registers hooks
        _current = load(new_root)
        return _current
