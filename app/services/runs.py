"""Run lifecycle: creation (with allowlist validation), auto-enumeration, cancel, row access."""

from __future__ import annotations

import logging

from sqlalchemy import Text, cast, exists, func, literal_column, select, update
from sqlalchemy.orm import Session

from app.models import ResultRow, Run, RunOrigin, RunStatus, utcnow
from app.services.evidence import get_evidence
from app.tools.base import ArgValidationError, ToolRequest, ToolRunner

logger = logging.getLogger(__name__)

__all__ = [
    "ArgValidationError",
    "cancel_run",
    "create_run",
    "enqueue_auto",
    "get_rows",
    "get_run",
    "annotation_tags",
    "get_runner",
    "list_runs",
]

# Statuses for which an auto-enumeration run is considered already done or in progress.
_AUTO_SKIP_STATUSES = (RunStatus.QUEUED, RunStatus.RUNNING, RunStatus.SUCCEEDED)


def get_runner(name: str = "volatility3") -> ToolRunner:
    """Indirection over app.tools.registry.get_runner.

    Imported lazily so this module does not depend on the registry at import time; the worker
    also resolves runners through this function, so tests monkeypatch it in one place.
    """
    from app.tools import registry

    return registry.get_runner(name)


def get_run(session: Session, run_id: int) -> Run:
    """Return the Run or raise LookupError."""
    run = session.get(Run, run_id)
    if run is None:
        raise LookupError(f"run {run_id} not found")
    return run


def list_runs(session: Session, evidence_id: int | None = None) -> list[Run]:
    stmt = select(Run).order_by(Run.id.desc())
    if evidence_id is not None:
        stmt = stmt.where(Run.evidence_id == evidence_id)
    return list(session.scalars(stmt))


def create_run(
    session: Session,
    evidence_id: int,
    request: ToolRequest,
    origin: RunOrigin = RunOrigin.MANUAL,
    tool: str = "volatility3",
    *,
    parent_run_id: int | None = None,
    triggered_by_hook: str | None = None,
    chain_depth: int = 0,
) -> Run:
    """Validate the request against the tool's allowlist and queue a run.

    The keyword-only arguments record follow-up provenance for runs queued by post-run hooks.
    Raises ArgValidationError for disallowed plugins/args and LookupError for unknown evidence.
    """
    get_evidence(session, evidence_id)
    runner = get_runner(tool)
    args = runner.validate(request)
    run = Run(
        evidence_id=evidence_id,
        tool=tool,
        plugin=request.plugin,
        args=args,
        origin=origin,
        status=RunStatus.QUEUED,
        parent_run_id=parent_run_id,
        triggered_by_hook=triggered_by_hook,
        chain_depth=chain_depth,
    )
    session.add(run)
    session.commit()
    logger.info("queued run %s: %s %s (%s)", run.id, request.plugin, args, origin.value)
    return run


def enqueue_auto(session: Session, evidence_id: int, tool: str = "volatility3") -> list[Run]:
    """Queue one run per auto_enumerate plugin, skipping ones already queued/running/succeeded."""
    get_evidence(session, evidence_id)
    runner = get_runner(tool)
    created: list[Run] = []
    for spec in runner.plugins():
        if not spec.auto_enumerate:
            continue
        request = ToolRequest(plugin=spec.name, args={})
        # Compare against the normalised args so validator-filled defaults still dedupe.
        normalized = runner.validate(request)
        existing = session.scalars(
            select(Run).where(
                Run.evidence_id == evidence_id,
                Run.tool == tool,
                Run.plugin == spec.name,
                Run.status.in_(_AUTO_SKIP_STATUSES),
            )
        )
        if any((r.args or {}) == normalized for r in existing):
            continue
        created.append(create_run(session, evidence_id, request, RunOrigin.AUTO, tool))
    return created


def cancel_run(session: Session, run_id: int) -> Run:
    """Cancel a run. QUEUED runs are cancelled immediately; RUNNING runs are signalled.

    Cancelling a finished run is a no-op. The returned Run reflects the DB state after the call
    (a signalled RUNNING run becomes CANCELLED once the worker notices).
    """
    run = get_run(session, run_id)
    # Atomic: only flip if the worker hasn't claimed it in the meantime.
    res = session.execute(
        update(Run)
        .where(Run.id == run_id, Run.status == RunStatus.QUEUED)
        .values(status=RunStatus.CANCELLED, finished_at=utcnow(), error="cancelled by user")
    )
    session.commit()
    session.refresh(run)
    if res.rowcount == 1:  # type: ignore[attr-defined]
        logger.info("cancelled queued run %s", run_id)
        return run

    if run.status == RunStatus.RUNNING:
        from app.jobs.worker import get_worker

        if get_worker().cancel(run_id):
            logger.info("signalled cancel for running run %s", run_id)
        else:
            # Not owned by this process's worker (e.g. worker not running): nothing will ever
            # finish it, so mark it cancelled directly.
            session.execute(
                update(Run)
                .where(Run.id == run_id, Run.status == RunStatus.RUNNING)
                .values(
                    status=RunStatus.CANCELLED,
                    finished_at=utcnow(),
                    error="cancelled by user (no active worker)",
                )
            )
            session.commit()
            session.refresh(run)
    return run


def _escape_like(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def annotation_tags(session: Session, run_id: int) -> list[tuple[str, int]]:
    """Distinct annotation tags on a run's rows with row counts, most common first."""
    each = func.json_each(ResultRow.annotations).table_valued("value").alias("a")
    tag = func.json_extract(each.c.value, "$.tag")
    stmt = (
        select(tag.label("tag"), func.count(func.distinct(ResultRow.id)).label("n"))
        .select_from(ResultRow)
        .join(each, literal_column("1") == literal_column("1"))
        .where(ResultRow.run_id == run_id, ResultRow.annotations.is_not(None))
        .group_by(tag)
        .order_by(func.count(func.distinct(ResultRow.id)).desc(), tag)
    )
    return [(t, n) for t, n in session.execute(stmt) if t]


def get_rows(
    session: Session,
    run_id: int,
    offset: int = 0,
    limit: int = 100,
    q: str | None = None,
    annotated: bool = False,
    tag: str | None = None,
) -> tuple[list[ResultRow], int]:
    """Page through a run's rows ordered by row_idx. ``q`` is a case-insensitive substring
    match on the JSON-serialised row data; ``annotated`` keeps only rows a hook annotated and
    ``tag`` only rows with that annotation tag. Returns (rows, total matching)."""
    where = [ResultRow.run_id == run_id]
    if annotated or tag:
        where.append(ResultRow.annotations.is_not(None))
    if tag:
        # SQLite JSON1: any annotation object whose "tag" equals the requested tag.
        where.append(
            exists(
                select(literal_column("1"))
                .select_from(func.json_each(ResultRow.annotations).table_valued("value"))
                .where(func.json_extract(literal_column("value"), "$.tag") == tag)
            )
        )
    if q:
        pattern = f"%{_escape_like(q)}%"
        where.append(cast(ResultRow.data, Text).ilike(pattern, escape="\\"))
    total = session.scalar(select(func.count()).select_from(ResultRow).where(*where)) or 0
    rows = session.scalars(
        select(ResultRow)
        .where(*where)
        .order_by(ResultRow.row_idx)
        .offset(max(offset, 0))
        .limit(max(limit, 0))
    )
    return list(rows), total
