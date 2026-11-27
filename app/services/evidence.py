"""Evidence discovery, safe path resolution and hashing.

Evidence files live in the read-only ``settings.evidence_dir`` mount; we only ever read them.
"""

from __future__ import annotations

import contextvars
import logging
import os
import threading
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import SessionLocal
from app.models import Evidence
from app.services import audit, integrity

logger = logging.getLogger(__name__)

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
            if ev.sha256 is None:
                # Not hashed yet: nothing to protect, just track the current file.
                ev.size_bytes, ev.mtime = st.st_size, st.st_mtime
            elif integrity.mark_changed(
                session,
                ev,
                f"scan: size {ev.size_bytes} -> {st.st_size}, mtime {ev.mtime} -> {st.st_mtime}",
            ):
                # The hashed size/mtime are kept as the baseline; the analyst must re-verify.
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


def hash_evidence(session: Session, evidence_id: int) -> Evidence:
    """Hash (or re-verify) an image now: SHA-256 + MD5 + SHA-1, recorded as an integrity check.

    This is the analyst's "Verify": the current content becomes the image's baseline (a change
    since the last hash is recorded as result "changed"). See app/services/integrity.py.
    """
    ev = get_evidence(session, evidence_id)
    integrity.hash_evidence(
        session, evidence_id, kind="initial" if ev.sha256 is None else "verify", accept=True
    )
    session.refresh(ev)
    return ev


def is_hashing(evidence_id: int) -> bool:
    """True while a background verify or the worker is hashing this image."""
    with _hashing_lock:
        return evidence_id in _hashing or integrity.is_hashing(evidence_id)


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
        except Exception:
            # integrity.hash_evidence already recorded the failure (check + audit event).
            logger.exception("background hash of evidence %s failed", evidence_id)
        finally:
            with _hashing_lock:
                _hashing.discard(evidence_id)

    # Run in a copy of the caller's context so audit events keep the request's origin/id.
    ctx = contextvars.copy_context()
    threading.Thread(
        target=ctx.run, args=(_target,), name=f"hash-evidence-{evidence_id}", daemon=True
    ).start()
