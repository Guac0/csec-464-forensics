"""Evidence discovery, safe path resolution and hashing.

Evidence files live in the read-only ``settings.evidence_dir`` mount; we only ever read them.
"""

from __future__ import annotations

import contextvars
import hashlib
import logging
import os
import threading
import time
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import SessionLocal
from app.models import Evidence, utcnow
from app.services import audit

logger = logging.getLogger(__name__)

HASH_CHUNK_SIZE = 1024 * 1024  # 1 MiB

# Evidence ids currently being hashed by a background thread (avoid duplicate work).
_hashing: set[int] = set()
_hashing_lock = threading.Lock()


def _evidence_root() -> Path:
    return get_settings().evidence_dir.resolve()


def _iter_evidence_files(root: Path) -> list[Path]:
    """Regular files under root, skipping hidden entries, excluded file types (README, hash
    files, archives; see ``Settings.evidence_exclude_extensions``) and symlinks escaping root."""
    excluded = get_settings().excluded_evidence_suffixes
    found: list[Path] = []
    # followlinks=False: symlinked directories are never descended into.
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
        for name in sorted(filenames):
            if name.startswith("."):
                continue
            path = Path(dirpath) / name
            if path.suffix.lower() in excluded:
                continue
            if path.is_symlink():
                try:
                    target = path.resolve(strict=True)
                except (OSError, RuntimeError):
                    continue  # dangling or looping link
                if not target.is_relative_to(root):
                    logger.warning("skipping symlink escaping evidence dir: %s", path)
                    continue
            if path.is_file():
                found.append(path)
    return found


def scan_evidence(session: Session) -> list[Evidence]:
    """Walk the evidence dir and upsert one Evidence row per file (keyed by rel_path).

    Returns the Evidence records for the files currently present. Records for files that have
    disappeared are kept (runs may reference them) but are not returned.
    """
    root = _evidence_root()
    if not root.is_dir():
        logger.warning("evidence dir does not exist: %s", root)
        return []

    existing = {e.rel_path: e for e in session.scalars(select(Evidence))}
    result: list[Evidence] = []
    added: list[str] = []
    changed: list[str] = []
    for path in _iter_evidence_files(root):
        rel_path = path.relative_to(root).as_posix()
        try:
            st = path.stat()
        except OSError:
            logger.warning("cannot stat evidence file: %s", path, exc_info=True)
            continue
        ev = existing.get(rel_path)
        if ev is None:
            ev = Evidence(rel_path=rel_path, size_bytes=st.st_size, mtime=st.st_mtime)
            session.add(ev)
            session.flush()  # assign ev.id for the audit event
            audit.record(
                session,
                "evidence.register",
                object_type="evidence",
                object_id=ev.id,
                evidence_id=ev.id,
                summary=f"Registered evidence {rel_path}",
                details={"rel_path": rel_path, "size_bytes": st.st_size, "mtime": st.st_mtime},
            )
            added.append(rel_path)
        elif ev.size_bytes != st.st_size or ev.mtime != st.st_mtime:
            # File changed on disk: the old hash no longer describes it.
            audit.record(
                session,
                "evidence.changed_on_disk",
                object_type="evidence",
                object_id=ev.id,
                evidence_id=ev.id,
                summary=f"Evidence file {rel_path} changed on disk; hash cleared",
                details={
                    "before": {"size_bytes": ev.size_bytes, "mtime": ev.mtime, "sha256": ev.sha256},
                    "after": {"size_bytes": st.st_size, "mtime": st.st_mtime},
                },
            )
            ev.size_bytes = st.st_size
            ev.mtime = st.st_mtime
            ev.sha256 = None
            ev.hashed_at = None
            changed.append(rel_path)
        result.append(ev)
    audit.record(
        session,
        "evidence.scan",
        summary=f"Scanned evidence folder: {len(result)} file(s), {len(added)} new, "
        f"{len(changed)} changed",
        details={"files": len(result), "added": added, "changed": changed},
    )
    session.commit()
    return result


def get_evidence(session: Session, evidence_id: int) -> Evidence:
    """Return the Evidence or raise LookupError."""
    ev = session.get(Evidence, evidence_id)
    if ev is None:
        raise LookupError(f"evidence {evidence_id} not found")
    return ev


def list_evidence(session: Session) -> list[Evidence]:
    return list(session.scalars(select(Evidence).order_by(Evidence.rel_path)))


def update_description(session: Session, evidence_id: int, description: str) -> Evidence:
    ev = get_evidence(session, evidence_id)
    audit.record(
        session,
        "evidence.describe",
        object_type="evidence",
        object_id=ev.id,
        evidence_id=ev.id,
        summary=f"Changed description of {ev.rel_path}",
        details={"before": ev.description, "after": description},
    )
    ev.description = description
    session.commit()
    return ev


def resolve_evidence_path(evidence: Evidence) -> Path:
    """Absolute path of the evidence file. Raises ValueError if it would leave evidence_dir."""
    root = _evidence_root()
    rel = evidence.rel_path
    if not rel or Path(rel).is_absolute():
        raise ValueError(f"invalid evidence path: {rel!r}")
    path = (root / rel).resolve()
    if not path.is_relative_to(root) or path == root:
        raise ValueError(f"evidence path escapes evidence dir: {rel!r}")
    return path


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(HASH_CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()


def hash_evidence(session: Session, evidence_id: int) -> Evidence:
    """Compute the SHA-256 of an evidence file. Skipped if already hashed at the same size+mtime."""
    ev = get_evidence(session, evidence_id)
    path = resolve_evidence_path(ev)
    st = path.stat()
    if ev.sha256 and ev.size_bytes == st.st_size and ev.mtime == st.st_mtime:
        return ev
    logger.info("hashing evidence %s (%s, %d bytes)", ev.id, ev.rel_path, st.st_size)
    started = time.perf_counter()
    digest = _sha256_file(path)
    # Re-stat: if the file changed while hashing, the digest is not trustworthy.
    st_after = path.stat()
    if (st_after.st_size, st_after.st_mtime) != (st.st_size, st.st_mtime):
        raise RuntimeError(f"evidence {ev.rel_path!r} changed while hashing")
    ev.size_bytes = st.st_size
    ev.mtime = st.st_mtime
    audit.record(
        session,
        "evidence.hash",
        object_type="evidence",
        object_id=ev.id,
        evidence_id=ev.id,
        summary=f"Hashed {ev.rel_path}: SHA-256 {digest}",
        details={
            "sha256": digest,
            "previous_sha256": ev.sha256,
            "size_bytes": st.st_size,
            "mtime": st.st_mtime,
            "seconds": round(time.perf_counter() - started, 3),
        },
    )
    ev.sha256 = digest
    ev.hashed_at = utcnow()
    session.commit()
    return ev


def is_hashing(evidence_id: int) -> bool:
    with _hashing_lock:
        return evidence_id in _hashing


def start_hash_in_background(evidence_id: int) -> None:
    """Hash in a daemon thread with its own DB session. No-op if already in progress."""
    with _hashing_lock:
        if evidence_id in _hashing:
            return
        _hashing.add(evidence_id)

    def _target() -> None:
        try:
            with SessionLocal() as s:
                hash_evidence(s, evidence_id)
        except Exception as exc:
            logger.exception("background hash of evidence %s failed", evidence_id)
            audit.record_now(
                "evidence.hash_failed",
                object_type="evidence",
                object_id=evidence_id,
                evidence_id=evidence_id,
                summary=f"Hashing evidence {evidence_id} failed: {exc}",
                details={"error": f"{type(exc).__name__}: {exc}"},
            )
        finally:
            with _hashing_lock:
                _hashing.discard(evidence_id)

    # Run in a copy of the caller's context so audit events keep the request's origin/id.
    ctx = contextvars.copy_context()
    threading.Thread(
        target=ctx.run, args=(_target,), name=f"hash-evidence-{evidence_id}", daemon=True
    ).start()
