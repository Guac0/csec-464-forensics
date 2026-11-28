"""Indicator watchlists: per-case lists of indicators (process names, paths, IPs, domains,
hashes, registry keys, other text) checked against the result rows of the case's images.

Only the indicator crosses between images: every hit points to a row in that image's OWN data.
Hits are never added to an image's rows, hooks or AI context.

Matching (``Matcher``):
- ``exact`` (default): the whole cell equals the indicator after normalising both for the
  indicator's type (case-insensitive, \\ and / alike for paths, canonical IP form...). A
  ``process`` indicator also matches a path cell whose file name is the process name.
- ``contains``: the normalised indicator appears anywhere in the normalised cell. Opt-in per
  indicator: more false positives (``svchost`` is everywhere) and slower.
- ``column``: optionally only look in one result column.
New match modes or types go in ``normalize`` / ``Matcher`` only.

When matching runs:
- New runs: as soon as a run's rows are stored, against the indicators of every case its image
  is in (one pass over its rows; cheap).
- Everything else (an indicator added after runs exist, images added to a case): on demand,
  "Check all images" on the case page (``start_case_check``), which re-checks every run of the
  case's images. It runs in the background; it can take a while on big filescan-type runs.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.models import (
    Case,
    CaseEvidence,
    Evidence,
    Indicator,
    IndicatorHit,
    IndicatorType,
    MatchMode,
    ResultRow,
    Run,
    RunStatus,
    utcnow,
)
from app.services import audit

logger = logging.getLogger(__name__)

MAX_VALUE = 1000
MAX_CELL = 500
ROW_BATCH = 2000
_HEX = re.compile(r"^[0-9a-f]+$")
_PROCESS_EXT = frozenset({"exe", "dll", "sys", "scr", "bat", "ps1", "cpl", "ocx"})
_FILE_EXT = frozenset(
    {"dmp", "bin", "dat", "tmp", "log", "txt", "img", "vmem", "raw", "mem", "lnk", "zip", "db"}
)
_IPV4_LOOSE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HASH_LENGTHS = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}


# --------------------------------------------------------------------------------- normalise


def normalize(kind: IndicatorType, value: Any) -> str:
    """Canonical form of a value for comparison as ``kind``. Used for indicators AND cells."""
    text = str(value).strip()
    if kind == IndicatorType.IP:
        candidate = text.strip("[]")
        if _IPV4_LOOSE.match(candidate):  # tools sometimes zero-pad octets: 010.000.000.001
            candidate = ".".join(str(int(p)) for p in candidate.split("."))
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            return text.casefold()
    if kind in (IndicatorType.PATH, IndicatorType.REGISTRY):
        text = text.replace("/", "\\").casefold()
        return re.sub(r"\\+", r"\\", text).rstrip("\\")
    if kind == IndicatorType.DOMAIN:
        return text.casefold().rstrip(".")
    return text.casefold()


def validate(kind: IndicatorType, value: str) -> str:
    """Normalised indicator value, or ValueError with a human-readable reason."""
    value = (value or "").strip()
    if not value:
        raise ValueError("indicator value must not be empty")
    if len(value) > MAX_VALUE:
        raise ValueError(f"indicator longer than {MAX_VALUE} characters")
    norm = normalize(kind, value)
    if kind == IndicatorType.HASH and (not _HEX.match(norm) or len(norm) not in _HASH_LENGTHS):
        raise ValueError("a hash must be 32 (MD5), 40 (SHA-1) or 64 (SHA-256) hex characters")
    if kind == IndicatorType.IP:
        try:
            ipaddress.ip_address(norm)
        except ValueError as exc:
            raise ValueError(f"not an IP address: {value!r}") from exc
    return norm


def guess_type(value: str) -> IndicatorType:
    """Best guess of an indicator type for a cell value (used by "make indicator from row")."""
    v = str(value).strip()
    low = v.casefold()
    try:
        ipaddress.ip_address(normalize(IndicatorType.IP, v))
        return IndicatorType.IP
    except ValueError:
        pass
    if _HEX.match(low) and len(low) in _HASH_LENGTHS:
        return IndicatorType.HASH
    if low.startswith(("hkey_", "hklm\\", "hkcu\\", "\\registry\\")):
        return IndicatorType.REGISTRY
    if "\\" in v or (len(v) > 2 and v[1] == ":") or v.startswith("/"):
        return IndicatorType.PATH
    ext = low.rsplit(".", 1)[-1] if "." in low else ""
    if ext in _PROCESS_EXT and re.fullmatch(r"[\w\-. ]+", low):
        return IndicatorType.PROCESS
    if ext in _FILE_EXT:  # a file name, not a domain (pid.101.0x1000.dmp)
        return IndicatorType.TEXT
    if re.fullmatch(r"(?=.{4,253}$)([a-z0-9-]+\.)+[a-z]{2,63}\.?", low):
        return IndicatorType.DOMAIN
    return IndicatorType.TEXT


# --------------------------------------------------------------------------------- matcher


@dataclass
class _Ind:
    id: int
    kind: IndicatorType
    norm: str
    mode: MatchMode
    column: str


@dataclass
class Matcher:
    """Matches cells against a set of indicators. Exact lookups are dictionary hits, so the
    cost is per cell (and per indicator type present), not per indicator."""

    indicators: list[_Ind]
    _exact: dict[tuple[IndicatorType, str], list[_Ind]] = field(default_factory=dict)
    _contains: list[_Ind] = field(default_factory=list)
    _kinds: set[IndicatorType] = field(default_factory=set)

    def __post_init__(self) -> None:
        for ind in self.indicators:
            self._kinds.add(ind.kind)
            if ind.mode == MatchMode.CONTAINS:
                self._contains.append(ind)
            else:
                self._exact.setdefault((ind.kind, ind.norm), []).append(ind)

    @classmethod
    def for_indicators(cls, rows: Iterable[Indicator]) -> Matcher:
        return cls([_Ind(i.id, i.type, i.normalized, i.match_mode, i.column or "") for i in rows])

    def __bool__(self) -> bool:
        return bool(self.indicators)

    def match_row(self, data: dict[str, Any]) -> list[tuple[int, str, str]]:
        """[(indicator id, column, cell)] for one row's data."""
        out: list[tuple[int, str, str]] = []
        for column, value in data.items():
            if column == "__children" or value is None or isinstance(value, (dict, list, bool)):
                continue
            cell = str(value)
            if not cell.strip():
                continue
            seen: set[int] = set()
            for kind in self._kinds:
                norm = normalize(kind, cell)
                candidates = list(self._exact.get((kind, norm), ()))
                if kind == IndicatorType.PROCESS and "\\" in cell.replace("/", "\\"):
                    base = normalize(kind, cell.replace("/", "\\").rsplit("\\", 1)[-1])
                    candidates += self._exact.get((kind, base), ())
                candidates += [
                    i for i in self._contains if i.kind == kind and i.norm and i.norm in norm
                ]
                for ind in candidates:
                    if ind.id in seen or (ind.column and ind.column != column):
                        continue
                    seen.add(ind.id)
                    out.append((ind.id, column, cell[:MAX_CELL]))
        return out


# --------------------------------------------------------------------------------- CRUD


def list_indicators(session: Session, case_id: int) -> list[Indicator]:
    return list(
        session.scalars(
            select(Indicator).where(Indicator.case_id == case_id).order_by(Indicator.id)
        )
    )


def add_indicator(
    session: Session,
    case_id: int,
    kind: IndicatorType | str,
    value: str,
    *,
    mode: MatchMode | str = MatchMode.EXACT,
    column: str = "",
    comment: str = "",
    source_key: str = "",
) -> Indicator:
    """Add an indicator to a case's watchlist. It is checked against NEW runs automatically;
    existing runs are checked on demand (``start_case_check``)."""
    from app.services.cases import get_case

    case = get_case(session, case_id)
    kind = IndicatorType(kind)
    mode = MatchMode(mode)
    norm = validate(kind, value)
    column = (column or "").strip()
    dup = session.scalar(
        select(Indicator.id).where(
            Indicator.case_id == case_id,
            Indicator.type == kind,
            Indicator.normalized == norm,
            Indicator.match_mode == mode,
            Indicator.column == column,
        )
    )
    if dup:
        raise ValueError("this indicator is already on the case's watchlist")
    ind = Indicator(
        case_id=case_id,
        type=kind,
        value=value.strip(),
        normalized=norm,
        match_mode=mode,
        column=column,
        comment=(comment or "").strip()[:2000],
        source_key=source_key or "",
        created_by=audit.current_context().actor,
    )
    session.add(ind)
    session.flush()
    audit.record(
        session,
        "indicator.add",
        object_type="indicator",
        object_id=ind.id,
        summary=f"Indicator {kind.value} {value.strip()!r} added to case {case.name}",
        details={
            "case_id": case_id,
            "type": kind.value,
            "value": ind.value,
            "mode": mode.value,
            "column": column,
            "source_key": ind.source_key,
        },
    )
    session.commit()
    return ind


def remove_indicator(session: Session, indicator_id: int) -> int:
    """Remove an indicator and its hits. Returns its case id."""
    ind = session.get(Indicator, indicator_id)
    if ind is None:
        raise LookupError(f"indicator {indicator_id} not found")
    case_id = ind.case_id
    hits = session.scalar(
        select(func.count(IndicatorHit.id)).where(IndicatorHit.indicator_id == ind.id)
    )
    session.execute(delete(IndicatorHit).where(IndicatorHit.indicator_id == ind.id))
    audit.record(
        session,
        "indicator.remove",
        object_type="indicator",
        object_id=ind.id,
        summary=f"Indicator {ind.type.value} {ind.value!r} removed from case {case_id}",
        details={"case_id": case_id, "hits_removed": hits},
    )
    session.delete(ind)
    session.commit()
    return case_id


# --------------------------------------------------------------------------------- matching


def _matchable_runs(session: Session, evidence_ids: Iterable[int]) -> list[Run]:
    ids = list(evidence_ids)
    if not ids:
        return []
    return list(
        session.scalars(
            select(Run)
            .where(
                Run.evidence_id.in_(ids),
                Run.status == RunStatus.SUCCEEDED,
                Run.deleted_at.is_(None),
            )
            .order_by(Run.id)
        )
    )


def _match_run_rows(
    session: Session, run: Run, matcher: Matcher, on_progress: Any = None
) -> list[IndicatorHit]:
    hits: list[IndicatorHit] = []
    last_idx = -1
    while True:
        rows = session.execute(
            select(ResultRow.row_idx, ResultRow.data)
            .where(ResultRow.run_id == run.id, ResultRow.row_idx > last_idx)
            .order_by(ResultRow.row_idx)
            .limit(ROW_BATCH)
        ).all()
        if not rows:
            return hits
        for row_idx, data in rows:
            for ind_id, column, cell in matcher.match_row(data or {}):
                hits.append(
                    IndicatorHit(
                        indicator_id=ind_id,
                        run_id=run.id,
                        evidence_id=run.evidence_id,
                        row_idx=row_idx,
                        column=column,
                        cell=cell,
                    )
                )
        last_idx = rows[-1][0]
        if on_progress is not None:
            on_progress()


def match_run(session: Session, run_id: int, on_progress: Any = None) -> int:
    """Check one run's rows against the indicators of every case its image is in (called by
    the worker after storing a run's rows). Replaces earlier hits of that run. Returns the
    number of hits; an audit event is written only when there are hits."""
    run = session.get(Run, run_id)
    if run is None or run.status != RunStatus.SUCCEEDED or run.deleted_at is not None:
        return 0
    indicators = list(
        session.scalars(
            select(Indicator)
            .join(CaseEvidence, CaseEvidence.case_id == Indicator.case_id)
            .where(CaseEvidence.evidence_id == run.evidence_id)
        )
    )
    session.execute(delete(IndicatorHit).where(IndicatorHit.run_id == run_id))
    if not indicators:
        session.commit()
        return 0
    hits = _match_run_rows(session, run, Matcher.for_indicators(indicators), on_progress)
    session.add_all(hits)
    if hits:
        by_case: dict[int, int] = {}
        case_of = {i.id: i.case_id for i in indicators}
        for h in hits:
            by_case[case_of[h.indicator_id]] = by_case.get(case_of[h.indicator_id], 0) + 1
        audit.record(
            session,
            "indicators.match_run",
            object_type="run",
            object_id=run.id,
            evidence_id=run.evidence_id,
            summary=f"Run {run.id}: {len(hits)} indicator hit(s)",
            details={"hits": len(hits), "hits_by_case": by_case},
        )
    session.commit()
    return len(hits)


def check_case(session: Session, case_id: int, progress: dict[str, Any] | None = None) -> int:
    """Re-check every succeeded run of the case's images against all its indicators (the
    on-demand "Check all images"). Replaces the case's hits. Returns the number of hits."""
    from app.services.cases import get_case

    case = get_case(session, case_id)
    indicators = list_indicators(session, case_id)
    evidence_ids = list(
        session.scalars(select(CaseEvidence.evidence_id).where(CaseEvidence.case_id == case_id))
    )
    runs = _matchable_runs(session, evidence_ids)
    if progress is not None:
        progress.update(total=len(runs), done=0)
    ind_ids = [i.id for i in indicators]
    if ind_ids:
        session.execute(delete(IndicatorHit).where(IndicatorHit.indicator_id.in_(ind_ids)))
    total = 0
    matcher = Matcher.for_indicators(indicators)
    if matcher:
        for run in runs:
            hits = _match_run_rows(session, run, matcher)
            session.add_all(hits)
            session.commit()  # per run: other writers (the worker) are not blocked for long
            total += len(hits)
            if progress is not None:
                progress["done"] = progress.get("done", 0) + 1
    now = utcnow()
    for ind in indicators:
        ind.checked_at = now
    audit.record(
        session,
        "indicators.check_case",
        object_type="case",
        object_id=case_id,
        summary=f"Checked {len(runs)} run(s) of case {case.name} against "
        f"{len(indicators)} indicator(s): {total} hit(s)",
        details={"runs": len(runs), "indicators": len(indicators), "hits": total},
    )
    session.commit()
    return total


_jobs: dict[int, dict[str, Any]] = {}
_jobs_lock = threading.Lock()


def job_state(case_id: int) -> dict[str, Any]:
    with _jobs_lock:
        return dict(_jobs.get(case_id, {}))


def start_case_check(case_id: int) -> bool:
    """Run ``check_case`` in a background thread. False if one is already running."""
    from app.db import SessionLocal

    with _jobs_lock:
        if _jobs.get(case_id, {}).get("running"):
            return False
        state: dict[str, Any] = {"running": True, "done": 0, "total": 0}
        _jobs[case_id] = state

    def _target() -> None:
        try:
            with SessionLocal() as s, audit.audit_context(origin="worker", request_id=None):
                state["hits"] = check_case(s, case_id, state)
        except Exception as exc:
            logger.exception("indicator check of case %s failed", case_id)
            state["error"] = str(exc)
        finally:
            state["running"] = False

    threading.Thread(target=_target, name=f"indicators-{case_id}", daemon=True).start()
    return True


# --------------------------------------------------------------------------------- reading


@dataclass
class HitView:
    hit: IndicatorHit
    indicator: Indicator
    run: Run
    evidence: Evidence


def hits(
    session: Session, case_id: int, evidence_id: int | None = None, run_id: int | None = None
) -> list[HitView]:
    """Hits of a case's indicators (optionally on one image or one run), with context."""
    stmt = (
        select(IndicatorHit, Indicator, Run, Evidence)
        .join(Indicator, Indicator.id == IndicatorHit.indicator_id)
        .join(Run, Run.id == IndicatorHit.run_id)
        .join(Evidence, Evidence.id == IndicatorHit.evidence_id)
        .where(Indicator.case_id == case_id)
        .order_by(Indicator.id, IndicatorHit.evidence_id, IndicatorHit.run_id, IndicatorHit.row_idx)
    )
    if evidence_id is not None:
        stmt = stmt.where(IndicatorHit.evidence_id == evidence_id)
    if run_id is not None:
        stmt = stmt.where(IndicatorHit.run_id == run_id)
    return [HitView(h, i, r, e) for h, i, r, e in session.execute(stmt)]


def hit_counts(session: Session, case_id: int) -> dict[int, dict[int, int]]:
    """{indicator_id: {evidence_id: hits}} for a case."""
    out: dict[int, dict[int, int]] = {}
    for ind_id, ev_id, n in session.execute(
        select(IndicatorHit.indicator_id, IndicatorHit.evidence_id, func.count(IndicatorHit.id))
        .join(Indicator, Indicator.id == IndicatorHit.indicator_id)
        .where(Indicator.case_id == case_id)
        .group_by(IndicatorHit.indicator_id, IndicatorHit.evidence_id)
    ):
        out.setdefault(ind_id, {})[ev_id] = n
    return out


def row_hits(session: Session, case_id: int, run_id: int) -> dict[int, list[str]]:
    """{row_idx: [indicator value, ...]} for marking rows on a run page (active case only)."""
    out: dict[int, list[str]] = {}
    for row_idx, value in session.execute(
        select(IndicatorHit.row_idx, Indicator.value)
        .join(Indicator, Indicator.id == IndicatorHit.indicator_id)
        .where(Indicator.case_id == case_id, IndicatorHit.run_id == run_id)
    ):
        out.setdefault(row_idx, []).append(value)
    return out


def remove_hits_for_image(session: Session, case_id: int, evidence_id: int) -> None:
    """When an image leaves a case: drop its hits for that case's indicators (no commit)."""
    ids = select(Indicator.id).where(Indicator.case_id == case_id)
    session.execute(
        delete(IndicatorHit).where(
            IndicatorHit.evidence_id == evidence_id, IndicatorHit.indicator_id.in_(ids)
        )
    )


def unchecked_count(session: Session, case_id: int) -> int:
    return (
        session.scalar(
            select(func.count(Indicator.id)).where(
                Indicator.case_id == case_id, Indicator.checked_at.is_(None)
            )
        )
        or 0
    )


def case_name(session: Session, case_id: int) -> str:
    case = session.get(Case, case_id)
    return case.name if case else str(case_id)
