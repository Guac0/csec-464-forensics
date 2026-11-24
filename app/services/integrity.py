"""Evidence integrity: hashing, change detection, expected-hash checks and the pre-run gate.

Lifecycle of an image
---------------------
1. Registered by a scan: not hashed yet.
2. Hashed (SHA-256 + MD5 + SHA-1 in one pass) either by the analyst ("Verify") or automatically
   by the worker before the first run. Every hash computation is stored in ``integrity_checks``
   (append-only) and the audit log.
3. Before **every** run the worker compares the file's size and modification time with the
   hashed values (cheap). ``FT_VERIFY_ON_RUN=true`` re-hashes the whole file instead.
4. The analyst may enter the hashes from the acquisition report (``expected_*``). A difference is
   a *mismatch*.

Problems and FT_INTEGRITY_MODE
------------------------------
- ``changed``  - the file differs from what was hashed (size/mtime, or content on a full check)
- ``mismatch`` - computed hashes differ from the expected ones and nobody acknowledged it

``strict`` (default): new runs are refused and queued runs fail with a clear message. The
analyst resolves a *change* by verifying the image again (which accepts its current content as
the new baseline, recorded in the audit log), and a *mismatch* by correcting the expected hashes
or acknowledging it with a reason.
``warn``: runs go ahead; the problem is stored on the run (``Run.integrity_warning``).

Every run records the SHA-256, size and mtime of the evidence it actually ran against.
"""

from __future__ import annotations

import hashlib
import logging
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Evidence, IntegrityCheck, Run, utcnow
from app.services import audit

logger = logging.getLogger(__name__)

HASH_CHUNK_SIZE = 1024 * 1024  # 1 MiB
PROGRESS_EVERY_BYTES = 256 * 1024 * 1024  # call on_progress about every 256 MiB
ALGORITHMS = ("sha256", "md5", "sha1")
_HEX_LEN = {"sha256": 64, "md5": 32, "sha1": 40}

# Evidence integrity states (see status()).
NOT_HASHED = "not_hashed"
HASHED = "hashed"
MATCHES_EXPECTED = "matches_expected"
MISMATCH = "mismatch"
MISMATCH_ACKNOWLEDGED = "mismatch_acknowledged"
CHANGED = "changed"
BLOCKING_STATES = (MISMATCH, CHANGED)


class IntegrityError(ValueError):
    """An action is refused because of the evidence's integrity state (strict mode)."""


class HashCancelled(Exception):  # noqa: N818
    """Hashing was stopped (run cancelled / worker shutting down)."""


# --------------------------------------------------------------------------------- hashing


@dataclass(frozen=True)
class HashResult:
    sha256: str
    md5: str
    sha1: str
    size_bytes: int
    mtime: float
    seconds: float


def compute_hashes(
    path: Path,
    should_stop: Callable[[], bool] | None = None,
    on_progress: Callable[[int], None] | None = None,
) -> HashResult:
    """SHA-256, MD5 and SHA-1 of a file in a single read. Raises HashCancelled if
    ``should_stop()`` becomes true, RuntimeError if the file changes while being hashed."""
    st = path.stat()
    started = time.perf_counter()
    sha256 = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False)  # for comparison with acquisition reports
    sha1 = hashlib.sha1(usedforsecurity=False)
    done = since_progress = 0
    with path.open("rb") as f:
        while chunk := f.read(HASH_CHUNK_SIZE):
            sha256.update(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            done += len(chunk)
            since_progress += len(chunk)
            if since_progress >= PROGRESS_EVERY_BYTES:
                since_progress = 0
                if on_progress:
                    on_progress(done)
                if should_stop and should_stop():
                    raise HashCancelled(f"hashing {path.name} stopped")
    after = path.stat()
    if (after.st_size, after.st_mtime) != (st.st_size, st.st_mtime):
        raise RuntimeError(f"{path.name} changed while it was being hashed")
    return HashResult(
        sha256.hexdigest(),
        md5.hexdigest(),
        sha1.hexdigest(),
        st.st_size,
        st.st_mtime,
        round(time.perf_counter() - started, 3),
    )


_locks: dict[int, threading.Lock] = {}
_locks_guard = threading.Lock()


def _lock_for(evidence_id: int) -> threading.Lock:
    """One hash at a time per image (the worker and the Verify button may race)."""
    with _locks_guard:
        return _locks.setdefault(evidence_id, threading.Lock())


def is_hashing(evidence_id: int) -> bool:
    lock = _locks.get(evidence_id)
    return lock is not None and lock.locked()


# --------------------------------------------------------------------------------- state


def mismatched_algorithms(ev: Evidence) -> list[str]:
    """Algorithms whose computed hash differs from the expected one (only when both exist)."""
    out = []
    for algo in ALGORITHMS:
        expected, actual = getattr(ev, f"expected_{algo}"), getattr(ev, algo)
        if expected and actual and expected.lower() != actual.lower():
            out.append(algo)
    return out


def has_expected(ev: Evidence) -> bool:
    return any(getattr(ev, f"expected_{a}") for a in ALGORITHMS)


def needs_hashing(ev: Evidence) -> bool:
    """True if any algorithm has not been computed (never hashed, or hashed before MD5/SHA-1)."""
    return any(getattr(ev, a) is None for a in ALGORITHMS)


def status(ev: Evidence) -> str:
    if ev.sha256 is None:
        return NOT_HASHED
    if ev.changed_detected_at is not None:
        return CHANGED
    if mismatched_algorithms(ev):
        return MISMATCH_ACKNOWLEDGED if ev.mismatch_ack_at else MISMATCH
    if has_expected(ev) and not needs_hashing(ev):
        return MATCHES_EXPECTED
    return HASHED


def stat_matches(ev: Evidence, path: Path) -> bool:
    st = path.stat()
    return (st.st_size, st.st_mtime) == (ev.size_bytes, ev.mtime)


def describe_problem(ev: Evidence) -> str | None:
    """Human-readable reason runs are blocked/flagged, or None if fine."""
    state = status(ev)
    if state == CHANGED:
        return (
            f"{ev.rel_path} changed since it was hashed. Verify it on the evidence page to accept "
            "its current content (recorded in the audit log)."
        )
    if state == MISMATCH:
        algos = ", ".join(a.upper().replace("SHA", "SHA-") for a in mismatched_algorithms(ev))
        return (
            f"{ev.rel_path} does not match its expected {algos}. Correct the expected hashes or "
            "acknowledge the mismatch on the evidence page."
        )
    return None


def check_can_run(ev: Evidence) -> None:
    """Gate for queueing runs: raises IntegrityError in strict mode if the image is blocked."""
    problem = describe_problem(ev)
    if problem and get_settings().integrity_mode == "strict":
        raise IntegrityError(problem)


# --------------------------------------------------------------------------------- actions


def hash_evidence(
    session: Session,
    evidence_id: int,
    *,
    kind: str = "verify",
    accept: bool = True,
    run_id: int | None = None,
    should_stop: Callable[[], bool] | None = None,
    on_progress: Callable[[int], None] | None = None,
) -> IntegrityCheck:
    """Hash the image, record an IntegrityCheck + audit event, and update the evidence.

    ``accept=True`` (analyst-initiated or first hash): the computed hashes become the image's
    baseline and any "changed" flag is cleared. ``accept=False`` (pre-run full check in strict
    mode): if the content differs from the baseline the image is flagged "changed" and the
    baseline is kept.
    """
    from app.services.evidence import get_evidence, resolve_evidence_path

    with _lock_for(evidence_id):
        ev = get_evidence(session, evidence_id)
        session.refresh(ev)
        path = resolve_evidence_path(ev)
        try:
            res = compute_hashes(path, should_stop=should_stop, on_progress=on_progress)
        except HashCancelled:
            raise
        except Exception as exc:
            check = _add_check(session, ev, kind, "error", run_id, detail=f"{exc}")
            audit.record(
                session,
                "evidence.hash_failed",
                object_type="evidence",
                object_id=ev.id,
                evidence_id=ev.id,
                summary=f"Hashing {ev.rel_path} failed: {exc}",
                details={"kind": kind, "error": f"{type(exc).__name__}: {exc}"},
            )
            session.commit()
            raise

        previous = {a: getattr(ev, a) for a in ALGORITHMS}
        changed = previous["sha256"] is not None and previous["sha256"] != res.sha256
        new = {"sha256": res.sha256, "md5": res.md5, "sha1": res.sha1}
        if changed and not accept:
            result = "changed"
            detail = "content differs from the hashed baseline; baseline kept"
            ev.changed_detected_at = ev.changed_detected_at or utcnow()
        else:
            if changed or previous != new:
                ev.mismatch_ack_at = None  # an acknowledgement applied to the old content
                ev.mismatch_ack_reason = None
            for algo, value in new.items():
                setattr(ev, algo, value)
            ev.size_bytes, ev.mtime, ev.hashed_at = res.size_bytes, res.mtime, utcnow()
            ev.changed_detected_at = None
            mism = mismatched_algorithms(ev)
            result = "changed" if changed else ("mismatch" if mism else "ok")
            detail = (
                "content differs from the previous hash; current content accepted"
                if changed
                else (f"differs from expected {', '.join(mism)}" if mism else "")
            )
        check = _add_check(session, ev, kind, result, run_id, res=res, detail=detail)
        audit.record(
            session,
            "evidence.hash",
            object_type="evidence",
            object_id=ev.id,
            evidence_id=ev.id,
            summary=f"Hashed {ev.rel_path} ({kind}): {result}",
            details={
                "kind": kind,
                "result": result,
                "accepted": accept or not changed,
                "run_id": run_id,
                **new,
                "previous": previous,
                "size_bytes": res.size_bytes,
                "mtime": res.mtime,
                "seconds": res.seconds,
                "status_after": status(ev),
            },
        )
        session.commit()
        logger.info("hashed evidence %s (%s): %s in %.1fs", ev.id, kind, result, res.seconds)
        return check


def _add_check(
    session: Session,
    ev: Evidence,
    kind: str,
    result: str,
    run_id: int | None,
    res: HashResult | None = None,
    detail: str = "",
) -> IntegrityCheck:
    check = IntegrityCheck(
        evidence_id=ev.id,
        run_id=run_id,
        kind=kind,
        result=result,
        sha256=res.sha256 if res else None,
        md5=res.md5 if res else None,
        sha1=res.sha1 if res else None,
        size_bytes=res.size_bytes if res else None,
        mtime=res.mtime if res else None,
        seconds=res.seconds if res else None,
        detail=detail,
    )
    session.add(check)
    session.flush()
    return check


def mark_changed(session: Session, ev: Evidence, reason: str) -> bool:
    """Flag the image as changed since hashing (idempotent). Returns True if newly flagged.
    The caller commits."""
    if ev.sha256 is None or ev.changed_detected_at is not None:
        return False
    ev.changed_detected_at = utcnow()
    audit.record(
        session,
        "evidence.changed_on_disk",
        object_type="evidence",
        object_id=ev.id,
        evidence_id=ev.id,
        summary=f"{ev.rel_path} changed since it was hashed ({reason})",
        details={"reason": reason, "hashed": {"size_bytes": ev.size_bytes, "mtime": ev.mtime}},
    )
    return True


def set_expected_hashes(
    session: Session,
    evidence_id: int,
    *,
    sha256: str | None = None,
    md5: str | None = None,
    sha1: str | None = None,
) -> Evidence:
    """Set the expected hashes (blank/None clears one). Raises ValueError for malformed hex.
    Changing them withdraws any previous mismatch acknowledgement."""
    from app.services.evidence import get_evidence

    ev = get_evidence(session, evidence_id)
    new = {"sha256": sha256, "md5": md5, "sha1": sha1}
    for algo, value in list(new.items()):
        value = (value or "").strip().lower() or None
        if value is not None and not re.fullmatch(rf"[0-9a-f]{{{_HEX_LEN[algo]}}}", value):
            raise ValueError(f"expected {algo} must be {_HEX_LEN[algo]} hex characters")
        new[algo] = value
    before = {a: getattr(ev, f"expected_{a}") for a in ALGORITHMS}
    if before == new:
        return ev
    for algo, value in new.items():
        setattr(ev, f"expected_{algo}", value)
    ev.mismatch_ack_at = None
    ev.mismatch_ack_reason = None
    audit.record(
        session,
        "evidence.expected_hashes",
        object_type="evidence",
        object_id=ev.id,
        evidence_id=ev.id,
        summary=f"Expected hashes for {ev.rel_path} set; status {status(ev)}",
        details={"before": before, "after": new, "status_after": status(ev)},
    )
    session.commit()
    return ev


def acknowledge_mismatch(session: Session, evidence_id: int, reason: str) -> Evidence:
    """Record the analyst's decision to run despite a hash mismatch."""
    from app.services.evidence import get_evidence

    ev = get_evidence(session, evidence_id)
    reason = (reason or "").strip()
    if status(ev) != MISMATCH:
        raise ValueError("there is no unacknowledged hash mismatch to acknowledge")
    if not reason:
        raise ValueError("a reason is required to acknowledge a hash mismatch")
    ev.mismatch_ack_at = utcnow()
    ev.mismatch_ack_reason = reason
    audit.record(
        session,
        "evidence.mismatch_acknowledged",
        object_type="evidence",
        object_id=ev.id,
        evidence_id=ev.id,
        summary=f"Hash mismatch on {ev.rel_path} acknowledged: {reason}",
        details={
            "reason": reason,
            "mismatched": mismatched_algorithms(ev),
            "computed": {a: getattr(ev, a) for a in ALGORITHMS},
            "expected": {a: getattr(ev, f"expected_{a}") for a in ALGORITHMS},
        },
    )
    session.commit()
    return ev


def list_checks(session: Session, evidence_id: int) -> list[IntegrityCheck]:
    return list(
        session.scalars(
            select(IntegrityCheck)
            .where(IntegrityCheck.evidence_id == evidence_id)
            .order_by(IntegrityCheck.id.desc())
        )
    )


# --------------------------------------------------------------------------------- pre-run


class IntegrityBlocked(Exception):  # noqa: N818
    """The worker must not run the tool on this evidence (strict mode)."""


def prepare_for_run(
    session: Session,
    run: Run,
    ev: Evidence,
    path: Path,
    *,
    should_stop: Callable[[], bool] | None = None,
    on_progress: Callable[[int], None] | None = None,
    set_phase: Callable[[str], None] | None = None,
) -> str | None:
    """Make sure the image is hashed and unchanged before a run. Returns a warning (warn mode)
    or None; raises IntegrityBlocked (strict) or HashCancelled. Records the evidence snapshot
    on the run."""
    settings = get_settings()
    strict = settings.integrity_mode == "strict"
    warnings: list[str] = []

    def phase(name: str) -> None:
        if set_phase:
            set_phase(name)

    session.refresh(ev)
    # 1. Cheap check: has the file changed since it was hashed?
    if ev.sha256 is not None and (ev.changed_detected_at or not stat_matches(ev, path)):
        mark_changed(session, ev, "size or modification time differs from the hashed file")
        session.commit()
        if strict:
            raise IntegrityBlocked(describe_problem(ev) or "evidence changed")
        phase("hashing")
        hash_evidence(
            session, ev.id, kind="rehash", run_id=run.id,
            should_stop=should_stop, on_progress=on_progress,
        )  # fmt: skip
        warnings.append("evidence changed since it was hashed; re-hashed and used anyway")
    # 2. Never hashed (or hashed before MD5/SHA-1 were added): hash it now.
    elif needs_hashing(ev):
        phase("hashing")
        hash_evidence(
            session, ev.id, kind="initial" if ev.sha256 is None else "rehash", run_id=run.id,
            should_stop=should_stop, on_progress=on_progress,
        )  # fmt: skip
    # 3. Optional full verification against the baseline.
    elif settings.verify_on_run:
        phase("verifying")
        check = hash_evidence(
            session, ev.id, kind="pre_run", accept=not strict, run_id=run.id,
            should_stop=should_stop, on_progress=on_progress,
        )  # fmt: skip
        if check.result == "changed":
            if strict:
                session.refresh(ev)
                raise IntegrityBlocked(describe_problem(ev) or "evidence content changed")
            warnings.append("evidence content changed since it was hashed; used anyway")
    session.refresh(ev)
    # 4. Expected hashes.
    state = status(ev)
    if state == MISMATCH:
        if strict:
            raise IntegrityBlocked(describe_problem(ev) or "hash mismatch")
        warnings.append(f"hash mismatch with expected {', '.join(mismatched_algorithms(ev))}")
    elif state == MISMATCH_ACKNOWLEDGED:
        warnings.append(f"hash mismatch acknowledged: {ev.mismatch_ack_reason}")
    # 5. Snapshot of what the tool runs against.
    run.evidence_sha256 = ev.sha256
    run.evidence_size_bytes = ev.size_bytes
    run.evidence_mtime = ev.mtime
    run.integrity_warning = "; ".join(warnings) or None
    session.commit()
    return run.integrity_warning
