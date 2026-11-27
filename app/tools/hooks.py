"""Post-run hooks: plugin-specific post-processing that runs after a run succeeds.

A hook is a plain function decorated with :func:`post_run`. Hooks live in modules under
``app/tools/volatility/hooks/`` and are discovered automatically (one file per hook or per plugin;
files starting with ``_`` are skipped). A hook receives a :class:`HookContext` and *stages*
changes through it:

- ``ctx.annotate(row_idx, tag, severity, note)``  flag/tag individual result rows
- ``ctx.add_finding(title, detail, severity, rows)``  run-level findings (shown + sent to the AI)
- ``ctx.update_evidence_metadata(**fields)``  merge facts into ``Evidence.os_info``
- ``ctx.queue_follow_up(plugin, args, reason)``  queue another run (subject to loop guards)

Staged changes are applied only if the hook returns normally, so a failing hook leaves nothing
half-written. A failing hook never fails the run (the tool output is still valid): the error is
recorded in ``Run.hook_results`` and shown as a warning, and the other hooks still run.

Each hook pass first clears the outputs of the previous pass (annotations, findings, hook
results), so hooks can be re-run safely after a code change (``POST /api/runs/{id}/hooks/rerun``).
Evidence metadata is merged, not cleared, and follow-ups are de-duplicated against existing runs.

Example::

    from app.tools.hooks import HookContext, post_run

    @post_run("windows.pslist.PsList", version="1")
    def flag_orphans(ctx: HookContext) -> None:
        for row in ctx.rows():
            if ...:
                ctx.annotate(row.row_idx, "orphan", severity="medium", note="parent not found")
"""

from __future__ import annotations

import importlib
import json
import logging
import pkgutil
import threading
import time
import traceback
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Evidence, ResultRow, Run, RunOrigin, RunStatus, utcnow
from app.services import audit
from app.tools.base import ArgValidationError, ToolRequest

logger = logging.getLogger(__name__)

SEVERITIES: tuple[str, ...] = ("info", "low", "medium", "high")
WILDCARD = "*"
# Packages scanned for hook modules. Add a package here when a new tool gets hooks.
HOOK_PACKAGES: tuple[str, ...] = ("app.tools.volatility.hooks",)
# Follow-ups are skipped if an identical run (same evidence, plugin, args) is in one of these.
_DEDUPE_STATUSES = (RunStatus.QUEUED, RunStatus.RUNNING, RunStatus.SUCCEEDED)
_MAX_TAG_LEN = 64
_ROW_BATCH = 1000

HookFunc = Callable[["HookContext"], None]


# --------------------------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class HookSpec:
    name: str
    func: HookFunc
    plugins: tuple[str, ...]
    tool: str = "volatility3"
    version: str = "1"
    description: str = ""

    def matches(self, tool: str, plugin: str) -> bool:
        return self.tool == tool and (WILDCARD in self.plugins or plugin in self.plugins)


_registry: dict[str, HookSpec] = {}
_load_errors: dict[str, str] = {}
_loaded = False
_lock = threading.RLock()


def register(spec: HookSpec) -> HookSpec:
    """Add a hook to the registry. Re-registering the same function (module reload) is allowed;
    a different function with an existing name is an error."""
    with _lock:
        existing = _registry.get(spec.name)
        if existing is not None and (
            existing.func.__module__,
            existing.func.__qualname__,
        ) != (spec.func.__module__, spec.func.__qualname__):
            raise ValueError(f"duplicate hook name {spec.name!r}")
        _registry[spec.name] = spec
    return spec


def unregister(name: str) -> None:
    with _lock:
        _registry.pop(name, None)


def post_run(
    *plugins: str,
    tool: str = "volatility3",
    name: str | None = None,
    version: str = "1",
    description: str | None = None,
) -> Callable[[HookFunc], HookFunc]:
    """Register the decorated function as a post-run hook for the given plugin names.

    Use full plugin names as in the catalog (e.g. ``"windows.pslist.PsList"``) or ``"*"`` for
    every plugin of the tool. Bump ``version`` when the hook's logic changes; it is recorded
    with each result for provenance.
    """
    if not plugins:
        raise ValueError("post_run needs at least one plugin name (or '*')")

    def decorator(func: HookFunc) -> HookFunc:
        module_short = func.__module__.rsplit(".", 1)[-1]
        register(
            HookSpec(
                name=name or f"{module_short}.{func.__name__}",
                func=func,
                plugins=tuple(plugins),
                tool=tool,
                version=str(version),
                description=description or (func.__doc__ or "").strip().split("\n")[0],
            )
        )
        return func

    return decorator


def load_hooks(force: bool = False) -> dict[str, str]:
    """Import every hook module (once). Returns {module: error} for modules that failed to
    import; those are logged and skipped so one broken hook cannot stop the app."""
    global _loaded
    with _lock:
        if _loaded and not force:
            return dict(_load_errors)
        _load_errors.clear()
        for package_name in HOOK_PACKAGES:
            try:
                package = importlib.import_module(package_name)
            except Exception as exc:  # noqa: BLE001
                _load_errors[package_name] = f"{type(exc).__name__}: {exc}"
                logger.exception("cannot import hook package %s", package_name)
                continue
            for mod in sorted(pkgutil.iter_modules(package.__path__), key=lambda m: m.name):
                if mod.name.startswith("_"):
                    continue
                module_name = f"{package_name}.{mod.name}"
                try:
                    module = importlib.import_module(module_name)
                    if force:
                        importlib.reload(module)
                except Exception as exc:  # noqa: BLE001
                    _load_errors[module_name] = f"{type(exc).__name__}: {exc}"
                    logger.exception("hook module %s failed to import; skipping", module_name)
        _loaded = True
        if _registry:
            logger.info("post-run hooks loaded: %s", ", ".join(sorted(_registry)))
        return dict(_load_errors)


def registered_hooks() -> list[HookSpec]:
    load_hooks()
    with _lock:
        return sorted(_registry.values(), key=lambda h: h.name)


def load_errors() -> dict[str, str]:
    load_hooks()
    with _lock:
        return dict(_load_errors)


def hooks_for(tool: str, plugin: str) -> list[HookSpec]:
    """Hooks matching a run, in deterministic (name) order."""
    return [h for h in registered_hooks() if h.matches(tool, plugin)]


# --------------------------------------------------------------------------------------------
# Context given to hooks
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class HookRow:
    """Read-only copy of a result row."""

    row_idx: int
    depth: int
    parent_idx: int | None
    data: dict[str, Any]


@dataclass(frozen=True)
class RunInfo:
    """Read-only summary of another run on the same evidence."""

    id: int
    plugin: str
    args: dict[str, Any]
    status: str
    row_count: int


@dataclass(frozen=True)
class ArtifactInfo:
    """Read-only summary of a file the run wrote (see app/services/artifacts.py)."""

    id: int
    filename: str
    size_bytes: int
    sha256: str
    md5: str
    sha1: str
    file_type: str
    source_row_idx: int | None


@dataclass
class _Staged:
    annotations: dict[int, list[dict[str, Any]]] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    follow_ups: list[dict[str, Any]] = field(default_factory=list)


class HookContext:
    """What a hook can see and do. Reads go straight to the DB; writes are staged."""

    def __init__(self, session: Session, run: Run, evidence: Evidence, spec: HookSpec) -> None:
        self._session = session
        self._spec = spec
        self._staged = _Staged()
        self.run_id: int = run.id
        self.tool: str = run.tool
        self.plugin: str = run.plugin
        self.args: dict[str, Any] = dict(run.args or {})
        self.row_count: int = run.row_count
        self.chain_depth: int = run.chain_depth
        self.evidence_id: int = evidence.id
        self.evidence_path: str = evidence.rel_path
        self.evidence_sha256: str | None = evidence.sha256
        self.os_info: dict[str, Any] = dict(evidence.os_info or {})

    # -- reading -----------------------------------------------------------------------------

    def rows(self, run_id: int | None = None) -> Iterator[HookRow]:
        """Iterate rows of this run (or another run on the same evidence) in row order."""
        target = self.run_id if run_id is None else run_id
        if target != self.run_id:
            other = self._session.get(Run, target)
            if other is None or other.evidence_id != self.evidence_id:
                raise ValueError(f"run {target} is not a run on this evidence")
        last = -1
        while True:
            batch = self._session.execute(
                select(ResultRow.row_idx, ResultRow.depth, ResultRow.parent_idx, ResultRow.data)
                .where(ResultRow.run_id == target, ResultRow.row_idx > last)
                .order_by(ResultRow.row_idx)
                .limit(_ROW_BATCH)
            ).all()
            if not batch:
                return
            for r in batch:
                yield HookRow(r.row_idx, r.depth, r.parent_idx, dict(r.data or {}))
            last = batch[-1].row_idx

    def latest_run(self, plugin: str, args: dict[str, Any] | None = None) -> RunInfo | None:
        """Most recent SUCCEEDED run of ``plugin`` on this evidence (optionally with exactly
        these args), e.g. to cross-reference pslist against psscan."""
        stmt = (
            select(Run)
            .where(
                Run.evidence_id == self.evidence_id,
                Run.tool == self.tool,
                Run.plugin == plugin,
                Run.status == RunStatus.SUCCEEDED,
                Run.deleted_at.is_(None),
            )
            .order_by(Run.id.desc())
        )
        for run in self._session.scalars(stmt):
            if args is None or (run.args or {}) == args:
                return RunInfo(run.id, run.plugin, dict(run.args or {}), run.status, run.row_count)
        return None

    def artifacts(self) -> list[ArtifactInfo]:
        """Files this run wrote (e.g. --dump output), with hashes and the row that names them."""
        from app.models import DerivedArtifact

        return [
            ArtifactInfo(
                a.id,
                a.filename,
                a.size_bytes,
                a.sha256,
                a.md5,
                a.sha1,
                a.file_type,
                a.source_row_idx,
            )  # fmt: skip
            for a in self._session.scalars(
                select(DerivedArtifact)
                .where(DerivedArtifact.run_id == self.run_id)
                .order_by(DerivedArtifact.filename)
            )
        ]

    # -- staging -----------------------------------------------------------------------------

    def annotate(self, row_idx: int, tag: str, severity: str = "info", note: str = "") -> None:
        """Tag one row of this run. Shown as a badge in the results table, filterable, and
        included in AI context."""
        if not isinstance(row_idx, int) or not 0 <= row_idx < self.row_count:
            raise ValueError(f"row_idx {row_idx!r} out of range (run has {self.row_count} rows)")
        tag = str(tag).strip()
        if not tag or len(tag) > _MAX_TAG_LEN:
            raise ValueError(f"tag must be 1-{_MAX_TAG_LEN} characters")
        self._staged.annotations.setdefault(row_idx, []).append(
            {
                "hook": self._spec.name,
                "tag": tag,
                "severity": _check_severity(severity),
                "note": str(note),
            }
        )

    def add_finding(
        self,
        title: str,
        detail: str = "",
        severity: str = "info",
        rows: Iterable[int] = (),
    ) -> None:
        """Add a run-level finding. ``rows`` are row indexes of this run supporting it; they
        are rendered as citations (R<run>:<row>)."""
        title = str(title).strip()
        if not title:
            raise ValueError("finding title must not be empty")
        row_list = sorted({int(r) for r in rows})
        bad = [r for r in row_list if not 0 <= r < self.row_count]
        if bad:
            raise ValueError(f"finding references rows outside this run: {bad[:5]}")
        self._staged.findings.append(
            {
                "hook": self._spec.name,
                "title": title,
                "detail": str(detail),
                "severity": _check_severity(severity),
                "rows": row_list,
            }
        )

    def update_evidence_metadata(self, **fields: Any) -> None:
        """Merge JSON-serialisable facts into Evidence.os_info (e.g. os="windows", build=...)."""
        for key, value in fields.items():
            try:
                json.dumps(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"metadata {key!r} is not JSON-serialisable") from exc
        self._staged.metadata.update(fields)

    def queue_follow_up(
        self, plugin: str, args: dict[str, Any] | None = None, reason: str = ""
    ) -> None:
        """Ask for another run on this evidence. Applied subject to the loop guards
        (FT_HOOK_FOLLOWUPS_ENABLED, FT_HOOK_MAX_CHAIN_DEPTH, FT_HOOK_MAX_FOLLOWUPS_PER_RUN), the
        plugin allowlist and de-duplication; skipped requests are recorded, not errors."""
        self._staged.follow_ups.append(
            {"plugin": str(plugin), "args": dict(args or {}), "reason": str(reason)}
        )


def _check_severity(severity: str) -> str:
    if severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {SEVERITIES}, got {severity!r}")
    return severity


# --------------------------------------------------------------------------------------------
# Running hooks
# --------------------------------------------------------------------------------------------


def run_hooks(
    session: Session, run_id: int, on_progress: Callable[[], None] | None = None
) -> list[dict[str, Any]]:
    """Run every matching hook for a SUCCEEDED run and store the results on the run.

    Safe to call again (re-run): previous annotations/findings/results are cleared first.
    Returns the per-hook results. Raises LookupError / ValueError for a missing or unfinished
    run; never raises because of a hook.
    """
    settings = get_settings()
    run = session.get(Run, run_id)
    if run is None:
        raise LookupError(f"run {run_id} not found")
    if run.status != RunStatus.SUCCEEDED:
        raise ValueError(f"run {run_id} has not succeeded (status {run.status.value})")
    if not settings.hooks_enabled:
        return []
    evidence = session.get(Evidence, run.evidence_id)
    if evidence is None:
        raise LookupError(f"evidence {run.evidence_id} not found")

    specs = hooks_for(run.tool, run.plugin)
    _clear_previous(session, run)
    if not specs:
        return []

    results: list[dict[str, Any]] = []
    followup_budget = [settings.hook_max_followups_per_run]
    for spec in specs:
        if on_progress is not None:
            on_progress()  # the worker's stall watchdog: each hook gets a fresh timer
        ctx = HookContext(session, run, evidence, spec)
        started = time.perf_counter()
        result: dict[str, Any] = {"hook": spec.name, "version": spec.version}
        try:
            spec.func(ctx)
        except Exception as exc:  # noqa: BLE001 - a hook must never break the run
            session.rollback()
            logger.warning("hook %s failed on run %s", spec.name, run_id, exc_info=True)
            result.update(status="error", error=_format_error(exc))
        else:
            try:
                result.update(status="ok", **_apply(session, run, evidence, ctx, followup_budget))
                session.commit()
            except Exception as exc:  # noqa: BLE001
                session.rollback()
                logger.exception("applying results of hook %s on run %s failed", spec.name, run_id)
                result.update(status="error", error=f"applying results failed: {exc}")
        result["duration_ms"] = round((time.perf_counter() - started) * 1000, 1)
        result["at"] = utcnow().isoformat()
        results.append(result)

    session.refresh(run)
    run.hook_results = results
    audit.record(
        session,
        "hooks.run",
        object_type="run",
        object_id=run.id,
        evidence_id=run.evidence_id,
        summary=f"Post-processing on run {run.id}: {len(results)} hook(s), "
        f"{sum(r['status'] != 'ok' for r in results)} failed",
        details={
            "hooks": [
                {
                    k: r.get(k)
                    for k in (
                        "hook",
                        "version",
                        "status",
                        "error",
                        "annotated_rows",
                        "findings",
                        "metadata_keys",
                        "follow_ups_queued",
                    )
                    if r.get(k) is not None
                }
                for r in results
            ]
        },
    )
    session.commit()
    failed = [r["hook"] for r in results if r["status"] != "ok"]
    logger.info(
        "run %s: %d hook(s) ran%s",
        run_id,
        len(results),
        f", failed: {', '.join(failed)}" if failed else "",
    )
    return results


def _clear_previous(session: Session, run: Run) -> None:
    session.execute(
        update(ResultRow)
        .where(ResultRow.run_id == run.id, ResultRow.annotations.is_not(None))
        .values(annotations=None)
    )
    run.findings = None
    run.hook_results = None
    session.commit()


def _apply(
    session: Session,
    run: Run,
    evidence: Evidence,
    ctx: HookContext,
    followup_budget: list[int],
) -> dict[str, Any]:
    staged = ctx._staged  # noqa: SLF001 - same module
    summary: dict[str, Any] = {}

    if staged.annotations:
        idxs = sorted(staged.annotations)
        updates: list[dict[str, Any]] = []
        for i in range(0, len(idxs), _ROW_BATCH):
            chunk = idxs[i : i + _ROW_BATCH]
            for row_id, row_idx, annotations in session.execute(
                select(ResultRow.id, ResultRow.row_idx, ResultRow.annotations).where(
                    ResultRow.run_id == run.id, ResultRow.row_idx.in_(chunk)
                )
            ):
                merged = list(annotations or []) + staged.annotations[row_idx]
                updates.append({"id": row_id, "annotations": merged})
        session.execute(update(ResultRow), updates)  # ORM bulk UPDATE by primary key
        summary["annotated_rows"] = len(idxs)

    if staged.findings:
        run.findings = list(run.findings or []) + staged.findings
        summary["findings"] = len(staged.findings)

    if staged.metadata:
        evidence.os_info = {**(evidence.os_info or {}), **staged.metadata}
        summary["metadata_keys"] = sorted(staged.metadata)

    if staged.follow_ups:
        queued, skipped = _queue_follow_ups(session, run, ctx, staged.follow_ups, followup_budget)
        summary["follow_ups_queued"] = queued
        if skipped:
            summary["follow_ups_skipped"] = skipped
    return summary


def _queue_follow_ups(
    session: Session,
    run: Run,
    ctx: HookContext,
    requests: list[dict[str, Any]],
    budget: list[int],
) -> tuple[list[int], list[dict[str, Any]]]:
    from app.services import runs as runs_service

    settings = get_settings()
    queued: list[int] = []
    skipped: list[dict[str, Any]] = []
    depth = run.chain_depth + 1
    for req in requests:

        def skip(reason: str, req: dict[str, Any] = req) -> None:
            skipped.append({"plugin": req["plugin"], "args": req["args"], "skipped": reason})

        if not settings.hook_followups_enabled:
            skip("follow-ups disabled (FT_HOOK_FOLLOWUPS_ENABLED=false)")
            continue
        if depth > settings.hook_max_chain_depth:
            skip(f"max chain depth {settings.hook_max_chain_depth} reached")
            continue
        if budget[0] <= 0:
            skip(f"per-run limit of {settings.hook_max_followups_per_run} follow-ups reached")
            continue
        request = ToolRequest(plugin=req["plugin"], args=req["args"])
        try:
            normalized = runs_service.get_runner(run.tool).validate(request)
        except ArgValidationError as exc:
            skip(f"not allowed: {exc}")
            continue
        duplicate = next(
            (
                r.id
                for r in session.scalars(
                    select(Run).where(
                        Run.evidence_id == run.evidence_id,
                        Run.tool == run.tool,
                        Run.plugin == request.plugin,
                        Run.status.in_(_DEDUPE_STATUSES),
                        Run.deleted_at.is_(None),
                    )
                )
                if (r.args or {}) == normalized
            ),
            None,
        )
        if duplicate is not None:
            skip(f"duplicate of run {duplicate}")
            continue
        try:
            new_run = runs_service.create_run(
                session,
                run.evidence_id,
                request,
                RunOrigin.HOOK,
                run.tool,
                parent_run_id=run.id,
                triggered_by_hook=ctx._spec.name,  # noqa: SLF001
                chain_depth=depth,
            )
        except runs_service.IntegrityError as exc:
            skip(f"evidence integrity: {exc}")
            continue
        budget[0] -= 1
        queued.append(new_run.id)
    return queued, skipped


def _format_error(exc: BaseException) -> str:
    """Exception type, message and the innermost frames (enough to locate the bug)."""
    frames = traceback.extract_tb(exc.__traceback__)[-3:]
    where = "; ".join(f"{f.filename.rsplit('/', 1)[-1]}:{f.lineno} in {f.name}" for f in frames)
    return f"{type(exc).__name__}: {exc}" + (f" (at {where})" if where else "")
