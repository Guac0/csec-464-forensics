"""Derived artifacts: files a tool wrote during a run (e.g. processes dumped with ``--dump``).

- The worker calls :func:`register_run_outputs` after every run (also failed/cancelled ones, so
  partial output is accounted for). Each file is hashed (SHA-256, MD5, SHA-1), typed by its
  first bytes, and linked to the result row that names it (e.g. pslist's "File output").
- Files live under ``<data_dir>/runs/<run_id>/output/`` and may be live malware. Downloads are
  an AES-encrypted zip by default (password ``FT_ARTIFACT_ZIP_PASSWORD``, "infected"), or the
  raw file when explicitly requested. Every download re-checks the SHA-256 and is audited.
- ``FT_MAX_ARTIFACT_BYTES`` caps what one run may write (enforced by the executor).
"""

from __future__ import annotations

import logging
import os
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import DerivedArtifact, ResultRow, Run
from app.services import audit
from app.services.integrity import compute_hashes

logger = logging.getLogger(__name__)

_ROW_BATCH = 1000


class ArtifactIntegrityError(Exception):
    """The stored file no longer matches the hash recorded when it was registered."""


# --------------------------------------------------------------------------------- typing


def guess_file_type(path: Path) -> str:
    """Rough type from the first bytes (no external libmagic needed)."""
    try:
        with path.open("rb") as f:
            head = f.read(4096)
    except OSError:
        return "unreadable"
    if not head:
        return "empty"
    if head.startswith(b"MZ"):
        pe_offset = int.from_bytes(head[0x3C:0x40], "little") if len(head) >= 0x40 else 0
        if head[pe_offset : pe_offset + 4] == b"PE\0\0":
            characteristics = int.from_bytes(head[pe_offset + 22 : pe_offset + 24], "little")
            return "PE DLL" if characteristics & 0x2000 else "PE executable"
        return "MZ executable"
    signatures: tuple[tuple[bytes, str], ...] = (
        (b"\x7fELF", "ELF executable"),
        (b"PK\x03\x04", "ZIP archive"),
        (b"%PDF", "PDF document"),
        (b"\x1f\x8b", "gzip archive"),
        (b"MSCF", "CAB archive"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE document"),
        (b"regf", "Windows registry hive"),
        (b"SQLite format 3\0", "SQLite database"),
        (b"\x89PNG", "PNG image"),
        (b"\xff\xd8\xff", "JPEG image"),
        (b"GIF8", "GIF image"),
        (b"MDMP", "minidump"),
    )
    for magic, name in signatures:
        if head.startswith(magic):
            return name
    try:
        head.decode("utf-8")
        return "text"
    except UnicodeDecodeError:
        return "data"


# --------------------------------------------------------------------------------- registering


def register_run_outputs(session: Session, run: Run, output_dir: Path) -> list[DerivedArtifact]:
    """Hash and record every file in the run's output dir (idempotent), link them to result
    rows, and write one audit event. The caller commits."""
    settings = get_settings()
    if not output_dir.is_dir():
        return []
    existing = {
        a.rel_path
        for a in session.scalars(select(DerivedArtifact).where(DerivedArtifact.run_id == run.id))
    }
    created: list[DerivedArtifact] = []
    for root, dirs, files in os.walk(output_dir):
        dirs.sort()
        for name in sorted(files):
            path = Path(root) / name
            if path.is_symlink() or not path.is_file():
                continue
            rel_path = path.relative_to(settings.data_dir).as_posix()
            if rel_path in existing:
                continue
            try:
                hashes = compute_hashes(path)
            except Exception:  # unreadable or still changing: skip, it is logged
                logger.warning("could not hash artifact %s", path, exc_info=True)
                continue
            artifact = DerivedArtifact(
                run_id=run.id,
                evidence_id=run.evidence_id,
                rel_path=rel_path,
                filename=path.relative_to(output_dir).as_posix(),
                size_bytes=hashes.size_bytes,
                sha256=hashes.sha256,
                md5=hashes.md5,
                sha1=hashes.sha1,
                file_type=guess_file_type(path),
            )
            session.add(artifact)
            created.append(artifact)
    if not created:
        return []
    _link_rows(session, run.id, created)
    session.flush()
    audit.record(
        session,
        "artifacts.register",
        object_type="run",
        object_id=run.id,
        evidence_id=run.evidence_id,
        summary=f"Run {run.id} wrote {len(created)} file(s), "
        f"{sum(a.size_bytes for a in created)} bytes",
        details={
            "files": [
                {
                    "artifact_id": a.id,
                    "filename": a.filename,
                    "size_bytes": a.size_bytes,
                    "sha256": a.sha256,
                    "file_type": a.file_type,
                    "source_row_idx": a.source_row_idx,
                }
                for a in created
            ]
        },
    )
    return created


def _link_rows(session: Session, run_id: int, artifacts: Iterable[DerivedArtifact]) -> None:
    """Link each artifact to the first row with a string value equal to its file name (or
    ending in "/name"), which is how volatility reports dumped files."""
    by_name: dict[str, list[DerivedArtifact]] = {}
    for a in artifacts:
        by_name.setdefault(Path(a.filename).name, []).append(a)
    remaining = set(by_name)
    last = -1
    while remaining:
        batch = session.execute(
            select(ResultRow.row_idx, ResultRow.data)
            .where(ResultRow.run_id == run_id, ResultRow.row_idx > last)
            .order_by(ResultRow.row_idx)
            .limit(_ROW_BATCH)
        ).all()
        if not batch:
            return
        for row_idx, data in batch:
            for value in (data or {}).values():
                if not isinstance(value, str):
                    continue
                name = value.replace("\\", "/").rsplit("/", 1)[-1]
                if name in remaining:
                    for a in by_name[name]:
                        a.source_row_idx = row_idx
                    remaining.discard(name)
        last = batch[-1].row_idx


# --------------------------------------------------------------------------------- reading


def list_for_run(session: Session, run_id: int) -> list[DerivedArtifact]:
    return list(
        session.scalars(
            select(DerivedArtifact)
            .where(DerivedArtifact.run_id == run_id)
            .order_by(DerivedArtifact.filename)
        )
    )


def get_artifact(session: Session, artifact_id: int) -> DerivedArtifact:
    artifact = session.get(DerivedArtifact, artifact_id)
    if artifact is None:
        raise LookupError(f"artifact {artifact_id} not found")
    return artifact


def artifact_path(artifact: DerivedArtifact) -> Path:
    """Absolute path; refuses anything outside the run's output dir."""
    data_dir = get_settings().data_dir.resolve()
    path = (data_dir / artifact.rel_path).resolve()
    allowed = (data_dir / "runs" / str(artifact.run_id) / "output").resolve()
    if not path.is_relative_to(allowed):
        raise ValueError(f"artifact path escapes its run output dir: {artifact.rel_path!r}")
    return path


def _verified_path(artifact: DerivedArtifact) -> Path:
    from sqlalchemy.orm import object_session

    session = object_session(artifact)
    run = session.get(Run, artifact.run_id) if session is not None else None
    if run is not None and run.deleted_at is not None:
        raise ArtifactIntegrityError(
            f"{artifact.filename} was deleted with run {artifact.run_id} "
            f"({run.delete_reason}); only its hashes are kept"
        )
    path = artifact_path(artifact)
    if not path.is_file():
        raise ArtifactIntegrityError(f"{artifact.filename} is missing from disk")
    if compute_hashes(path).sha256 != artifact.sha256:
        raise ArtifactIntegrityError(
            f"{artifact.filename} no longer matches the SHA-256 recorded when it was written"
        )
    return path


# --------------------------------------------------------------------------------- downloads


def prepare_download(
    session: Session, artifact_id: int, fmt: str = "zip"
) -> tuple[Path, str, bool]:
    """Verify the file and return (path to send, download filename, is_temporary).

    ``fmt="zip"``: AES-256 encrypted zip (password from settings) written to a temp file in
    ``<data_dir>/tmp`` (the caller deletes it after sending). ``fmt="raw"``: the file itself.
    The download is recorded in the audit log (category key_read), including failures.
    """
    if fmt not in ("zip", "raw"):
        raise ValueError("format must be 'zip' or 'raw'")
    artifact = get_artifact(session, artifact_id)
    details: dict[str, Any] = {
        "format": fmt,
        "filename": artifact.filename,
        "sha256": artifact.sha256,
        "run_id": artifact.run_id,
    }
    try:
        path = _verified_path(artifact)
    except ArtifactIntegrityError as exc:
        audit.record(
            session,
            "artifact.download_refused",
            category=audit.KEY_READ,
            object_type="artifact",
            object_id=artifact.id,
            evidence_id=artifact.evidence_id,
            summary=f"Download of {artifact.filename} refused: {exc}",
            details=details | {"error": str(exc)},
        )
        session.commit()
        raise
    base = Path(artifact.filename).name
    if fmt == "raw":
        result = (path, base, False)
    else:
        result = (_encrypted_zip(path, base), f"{base}.zip", True)
    audit.record(
        session,
        "artifact.download",
        category=audit.KEY_READ,
        object_type="artifact",
        object_id=artifact.id,
        evidence_id=artifact.evidence_id,
        summary=f"Downloaded {artifact.filename} "
        f"({'raw file' if fmt == 'raw' else 'encrypted zip'})",
        details=details,
    )
    session.commit()
    return result


def _encrypted_zip(path: Path, arcname: str) -> Path:
    import pyzipper

    settings = get_settings()
    tmp_dir = settings.data_dir / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix="artifact-", suffix=".zip", dir=tmp_dir)
    os.close(fd)
    with pyzipper.AESZipFile(
        tmp_name, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
    ) as zf:
        zf.setpassword(settings.artifact_zip_password.encode("utf-8"))
        zf.write(path, arcname)
    return Path(tmp_name)
