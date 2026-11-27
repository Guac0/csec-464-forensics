"""Backups of the case: database snapshot + raw tool output, verifiable and restorable.

A backup is one ZIP in ``FT_BACKUP_DIR`` (its own volume, so losing the data volume does not
lose the backups) named ``forensics-backup-<UTC time>-<trigger>.zip``:

- ``forensics.db``      consistent snapshot taken with SQLite's online backup API (safe while
                        the app is running and writing)
- ``runs/<id>/stdout.jsonl``, ``runs/<id>/stderr.txt``  raw tool output of finished runs
- ``manifest.json``     what is inside, with the SHA-256 of every file, the schema version, and
                        the audit chain head (verified on the snapshot)

Dumped files (``runs/<id>/output/``) are NOT included (possible malware, often big): after a
restore they are reused if they are still on disk and still match their recorded hashes, and
can otherwise be re-dumped by re-running the plugin.

Each backup appends the audit chain head to ``FT_BACKUP_DIR/audit-anchors.jsonl``. That file
lives outside the database, so someone who rebuilds the whole audit chain inside the database
file is caught: the System page checks the live chain still contains the last anchored head.

Restore (``python -m app.backup restore``) only runs while the app is stopped; the current
database and raw outputs are moved aside to ``<data_dir>/pre-restore-<time>/`` first.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import re
import shutil
import sqlite3
import tempfile
import threading
import zipfile
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from importlib import metadata
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.services.resources import fmt_bytes

logger = logging.getLogger(__name__)

FORMAT_VERSION = 1
DB_NAME = "forensics.db"
MANIFEST = "manifest.json"
ANCHORS = "audit-anchors.jsonl"
APP_LOCK = ".app.lock"
NAME_RE = re.compile(r"^forensics-backup-(\d{8}T\d{6}Z)-(manual|scheduled|cli)\.zip$")
RAW_FILES = ("stdout.jsonl", "stderr.txt")
TRIGGERS = ("manual", "scheduled", "cli")


class BackupError(Exception):
    """A backup could not be created, verified or restored."""


@dataclass
class BackupInfo:
    name: str
    path: Path
    created_at: datetime
    trigger: str
    size_bytes: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "created_at": self.created_at.isoformat(),
            "trigger": self.trigger,
            "size_bytes": self.size_bytes,
        }


@dataclass
class VerifyReport:
    name: str
    ok: bool
    problems: list[str] = field(default_factory=list)
    files: int = 0
    audit_events: int = 0
    head_hash: str = ""
    schema: str = ""
    created_at: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RestoreReport:
    backup: str
    moved_aside_to: str | None
    files_restored: int
    dumped_ok: int
    dumped_missing: int
    dumped_mismatch: int


# --------------------------------------------------------------------------------- helpers


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _stamp(dt: datetime) -> str:
    return dt.strftime("%Y%m%dT%H%M%SZ")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def _app_version() -> str:
    try:
        return metadata.version("forensics-tool")
    except metadata.PackageNotFoundError:
        return "unknown"


def backup_dir(settings: Settings | None = None) -> Path:
    return (settings or get_settings()).backup_dir


def list_backups(settings: Settings | None = None) -> list[BackupInfo]:
    """Backups in FT_BACKUP_DIR, newest first."""
    folder = backup_dir(settings)
    if not folder.is_dir():
        return []
    out = []
    for path in folder.iterdir():
        m = NAME_RE.match(path.name)
        if not m or not path.is_file():
            continue
        created = datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
        out.append(BackupInfo(path.name, path, created, m.group(2), path.stat().st_size))
    return sorted(out, key=lambda b: (b.created_at, b.name), reverse=True)


def get_backup(name: str, settings: Settings | None = None) -> BackupInfo:
    for b in list_backups(settings):
        if b.name == name:
            return b
    raise LookupError(f"backup {name!r} not found")


def _resolve(path_or_name: str | Path) -> Path:
    path = Path(path_or_name)
    if path.is_file():
        return path
    return get_backup(str(path_or_name)).path


@contextlib.contextmanager
def _file_lock(path: Path, *, blocking: bool) -> Iterator[bool]:
    """Exclusive advisory lock on ``path`` (POSIX). Yields False if it is held elsewhere; yields
    True where locking is unsupported (Windows without Docker)."""
    try:
        import fcntl
    except ImportError:  # pragma: no cover - Windows
        yield True
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        except BlockingIOError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


# The running app holds this lock (see app.main) so restore can refuse while it runs.
_app_lock_file: Any = None


def hold_app_lock(settings: Settings | None = None) -> bool:
    """Called at app startup: take the data folder's app lock for the app's lifetime. Returns
    False (and logs) if another process holds it, e.g. a second app on the same data."""
    global _app_lock_file
    try:
        import fcntl
    except ImportError:  # pragma: no cover - Windows
        return True
    path = (settings or get_settings()).data_dir / APP_LOCK
    path.parent.mkdir(parents=True, exist_ok=True)
    f = path.open("a")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        f.close()
        logger.warning("another process is using %s (second app instance or a restore?)", path)
        return False
    _app_lock_file = f
    return True


def release_app_lock() -> None:
    global _app_lock_file
    if _app_lock_file is not None:
        _app_lock_file.close()
        _app_lock_file = None


# --------------------------------------------------------------------------------- create

_create_lock = threading.Lock()


def _snapshot_db(src: Path, dst: Path) -> None:
    source = sqlite3.connect(f"file:{src}?mode=ro", uri=True, timeout=30)
    target = sqlite3.connect(dst)
    try:
        source.backup(target)  # consistent snapshot even while the app writes (WAL)
    finally:
        target.close()
        source.close()


def _inspect_db(db_path: Path) -> dict[str, Any]:
    """Integrity check, schema revision, audit chain and run states of a database file."""
    from app.models import Run, RunStatus
    from app.services import audit

    engine = create_engine(f"sqlite:///{db_path}")
    try:
        with engine.connect() as conn:
            integrity = conn.execute(text("PRAGMA integrity_check")).scalar()
            schema = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
        with Session(engine) as s:
            report = audit.verify_chain(s)
            active = {
                rid
                for (rid,) in s.execute(
                    select(Run.id).where(Run.status.in_((RunStatus.QUEUED, RunStatus.RUNNING)))
                )
            }
            dumped = s.execute(
                text("SELECT count(*), coalesce(sum(size_bytes), 0) FROM derived_artifacts")
            ).one()
    finally:
        engine.dispose()
    return {
        "integrity": integrity,
        "schema": schema,
        "chain": report,
        "active_runs": active,
        "dumped": (int(dumped[0]), int(dumped[1])),
    }


def _append_anchor(folder: Path, entry: dict[str, Any]) -> None:
    with (folder / ANCHORS).open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")


def last_anchor(settings: Settings | None = None) -> dict[str, Any] | None:
    path = backup_dir(settings) / ANCHORS
    if not path.is_file():
        return None
    last = None
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                with contextlib.suppress(ValueError):
                    last = json.loads(line)
    return last


def estimate_size(settings: Settings | None = None) -> int:
    """Upper bound of a backup's size (database + raw outputs, before compression)."""
    settings = settings or get_settings()
    total = 0
    for p in settings.data_dir.glob(f"{DB_NAME}*"):
        total += p.stat().st_size
    if settings.runs_dir.is_dir():
        for run in settings.runs_dir.iterdir():
            for name in RAW_FILES:
                f = run / name
                if f.is_file():
                    total += f.stat().st_size
    return total


def create_backup(trigger: str = "manual", settings: Settings | None = None) -> BackupInfo:
    """Make a backup (see module docstring). Raises BackupError if one is already being made,
    the backup folder is unusable or full, or the snapshot fails its checks."""
    from app.services import audit

    settings = settings or get_settings()
    if trigger not in TRIGGERS:
        raise ValueError(f"unknown trigger {trigger!r}")
    folder = backup_dir(settings)
    try:
        folder.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise BackupError(f"cannot create backup folder {folder}: {exc}") from exc
    if not _create_lock.acquire(blocking=False):
        raise BackupError("a backup is already being made")
    try:
        with _file_lock(folder / ".backup.lock", blocking=False) as locked:
            if not locked:
                raise BackupError("a backup is already being made (another process)")
            needed = estimate_size(settings)
            free = shutil.disk_usage(folder).free
            if free < needed + 100 * 1024**2:
                raise BackupError(
                    f"not enough space in {folder}: {fmt_bytes(free)} free, up to "
                    f"{fmt_bytes(needed)} needed"
                )
            info = _create(trigger, settings, folder)
    except BackupError as exc:
        audit.record_now(
            "backup.failed", summary=f"Backup failed: {exc}", details={"trigger": trigger}
        )
        raise
    finally:
        _create_lock.release()
    if trigger == "scheduled":
        prune(settings)
    return info


def _create(trigger: str, settings: Settings, folder: Path) -> BackupInfo:
    from app.services import audit

    created = _now()
    while any(folder.glob(f"forensics-backup-{_stamp(created)}-*.zip")):
        created += timedelta(seconds=1)  # names have 1 s resolution: never overwrite one
    name = f"forensics-backup-{_stamp(created)}-{trigger}.zip"
    with tempfile.TemporaryDirectory(dir=folder, prefix=".tmp-") as tmp:
        tmpdir = Path(tmp)
        snap = tmpdir / DB_NAME
        try:
            _snapshot_db(settings.data_dir / DB_NAME, snap)
            info = _inspect_db(snap)
        except Exception as exc:
            raise BackupError(f"database snapshot failed: {exc}") from exc
        if info["integrity"] != "ok":
            raise BackupError(f"database integrity check failed: {info['integrity']}")
        chain = info["chain"]

        entries: list[tuple[str, Path]] = [(DB_NAME, snap)]
        skipped_active = sorted(info["active_runs"])
        if settings.runs_dir.is_dir():
            for run in sorted(settings.runs_dir.iterdir(), key=lambda p: p.name):
                if not run.name.isdigit() or int(run.name) in info["active_runs"]:
                    continue  # still being written: not consistent with the snapshot
                for raw in RAW_FILES:
                    f = run / raw
                    if f.is_file() and not f.is_symlink():
                        entries.append((f"runs/{run.name}/{raw}", f))

        files = []
        part = tmpdir / (name + ".part")
        with zipfile.ZipFile(part, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            for arcname, path in entries:
                files.append(
                    {"path": arcname, "size": path.stat().st_size, "sha256": _sha256(path)}
                )
                zf.write(path, arcname)
            manifest = {
                "format": FORMAT_VERSION,
                "created_at": created.isoformat(),
                "trigger": trigger,
                "app_version": _app_version(),
                "schema": info["schema"],
                "audit_chain": {
                    "ok": chain.ok,
                    "events": chain.events,
                    "head_seq": chain.head_seq,
                    "head_hash": chain.head_hash,
                    "error": chain.error,
                },
                "files": files,
                "excluded": {
                    "dumped_files": info["dumped"][0],
                    "dumped_bytes": info["dumped"][1],
                    "active_runs": skipped_active,
                },
            }
            manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode()
            zf.writestr(MANIFEST, manifest_bytes)
        final = folder / name
        os.replace(part, final)

    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    _append_anchor(
        folder,
        {
            "at": created.isoformat(),
            "backup": name,
            "head_seq": chain.head_seq,
            "head_hash": chain.head_hash,
            "manifest_sha256": manifest_sha,
        },
    )
    size = final.stat().st_size
    audit.record_now(
        "backup.create",
        summary=f"Backup {name} ({fmt_bytes(size)}, {len(files)} files)",
        details={
            "backup": name,
            "trigger": trigger,
            "size_bytes": size,
            "files": len(files),
            "manifest_sha256": manifest_sha,
            "audit_head_seq": chain.head_seq,
            "audit_head_hash": chain.head_hash,
            "audit_chain_ok": chain.ok,
            "dumped_files_excluded": info["dumped"][0],
        },
    )
    logger.info("backup %s created (%s)", name, fmt_bytes(size))
    if not chain.ok:
        logger.error("backup %s: the audit chain did NOT verify: %s", name, chain.error)
    return BackupInfo(name, final, created, trigger, size)


def prune(settings: Settings | None = None) -> list[str]:
    """Keep the newest FT_BACKUP_KEEP scheduled backups; delete older scheduled ones. Manual
    and command-line backups are never deleted automatically."""
    from app.services import audit

    settings = settings or get_settings()
    scheduled = [b for b in list_backups(settings) if b.trigger == "scheduled"]
    removed = []
    for b in scheduled[max(1, settings.backup_keep) :]:
        try:
            b.path.unlink()
            removed.append(b.name)
        except OSError:
            logger.exception("could not delete old backup %s", b.path)
    if removed:
        audit.record_now(
            "backup.prune",
            summary=f"Deleted {len(removed)} old scheduled backup(s)",
            details={"removed": removed, "keep": settings.backup_keep},
        )
    return removed


# --------------------------------------------------------------------------------- verify


def verify_backup(path_or_name: str | Path) -> VerifyReport:
    """Check a backup: every file matches the manifest hash, the database passes SQLite's
    integrity check, its audit chain verifies and matches the manifest (and the anchor file)."""
    path = _resolve(path_or_name)
    report = VerifyReport(name=path.name, ok=False)
    try:
        zf = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        report.problems.append(f"not a readable ZIP: {exc}")
        return report
    with zf, tempfile.TemporaryDirectory() as tmp:
        try:
            manifest = json.loads(zf.read(MANIFEST))
        except (KeyError, ValueError) as exc:
            report.problems.append(f"manifest.json missing or invalid: {exc}")
            return report
        report.created_at = manifest.get("created_at", "")
        report.schema = manifest.get("schema") or ""
        names = set(zf.namelist()) - {MANIFEST}
        listed = {f["path"] for f in manifest.get("files", [])}
        for extra in sorted(names - listed):
            report.problems.append(f"{extra}: not listed in the manifest")
        for f in manifest.get("files", []):
            if f["path"] not in names:
                report.problems.append(f"{f['path']}: missing")
                continue
            h = hashlib.sha256()
            with zf.open(f["path"]) as src:
                while chunk := src.read(1024 * 1024):
                    h.update(chunk)
            if h.hexdigest() != f["sha256"]:
                report.problems.append(f"{f['path']}: SHA-256 does not match the manifest")
            report.files += 1
        if DB_NAME in names:
            db = Path(tmp) / DB_NAME
            with zf.open(DB_NAME) as src, db.open("wb") as dst:
                shutil.copyfileobj(src, dst)
            try:
                info = _inspect_db(db)
            except Exception as exc:
                report.problems.append(f"database cannot be read: {exc}")
            else:
                chain = info["chain"]
                report.audit_events = chain.events
                report.head_hash = chain.head_hash
                if info["integrity"] != "ok":
                    report.problems.append(f"database integrity check: {info['integrity']}")
                if not chain.ok:
                    report.problems.append(f"audit chain does not verify: {chain.error}")
                expected = manifest.get("audit_chain", {})
                if (chain.head_seq, chain.head_hash) != (
                    expected.get("head_seq"),
                    expected.get("head_hash"),
                ):
                    report.problems.append("audit chain head differs from the manifest")
        else:
            report.problems.append(f"{DB_NAME} missing")
    anchors = backup_dir() / ANCHORS
    if anchors.is_file() and path.parent == backup_dir():
        matching = [
            a
            for a in (json.loads(x) for x in anchors.read_text().splitlines() if x.strip())
            if a.get("backup") == path.name
        ]
        if matching and matching[-1].get("head_hash") != report.head_hash:
            report.problems.append("audit head differs from the one anchored when it was made")
    report.ok = not report.problems
    return report


# --------------------------------------------------------------------------------- restore


def app_is_running(settings: Settings | None = None) -> bool:
    """True if a process holds the data folder's app lock (POSIX only)."""
    path = (settings or get_settings()).data_dir / APP_LOCK
    with _file_lock(path, blocking=False) as free:
        return not free


def restore_backup(path_or_name: str | Path, settings: Settings | None = None) -> RestoreReport:
    """Replace the case data with a backup. The app must be stopped. The backup is verified
    first; the current database and raw outputs are moved to ``pre-restore-<time>/``. Dumped
    files are not in backups: existing ones are kept and checked against the restored hashes."""
    from app import db
    from app.models import DerivedArtifact, Run
    from app.services import audit

    settings = settings or get_settings()
    path = _resolve(path_or_name)
    if app_is_running(settings):
        raise BackupError("the app is running on this data folder; stop it before restoring")
    report = verify_backup(path)
    if not report.ok:
        raise BackupError("backup failed verification: " + "; ".join(report.problems))

    data = settings.data_dir
    data.mkdir(parents=True, exist_ok=True)
    with _file_lock(data / APP_LOCK, blocking=False) as locked:
        if not locked:
            raise BackupError("the app started while restoring; stop it and try again")
        aside: Path | None = None
        current = [p for p in data.glob(f"{DB_NAME}*") if p.is_file()]
        raw_now = [
            f
            for run in (settings.runs_dir.iterdir() if settings.runs_dir.is_dir() else [])
            for f in (run / n for n in RAW_FILES)
            if f.is_file()
        ]
        if current or raw_now:
            aside = data / f"pre-restore-{_stamp(_now())}"
            aside.mkdir()
            for p in current:
                os.replace(p, aside / p.name)
            for f in raw_now:
                target = aside / f.relative_to(data)
                target.parent.mkdir(parents=True, exist_ok=True)
                os.replace(f, target)

        restored = 0
        with zipfile.ZipFile(path) as zf:
            for member in zf.namelist():
                if member == MANIFEST:
                    continue
                target = (data / member).resolve()
                if data.resolve() not in target.parents:
                    raise BackupError(f"unsafe path in backup: {member}")
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src, target.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
                restored += 1

        db.init_engine()
        db.migrate()  # an older backup is brought up to the current schema
        ok = missing = mismatch = 0
        with db.SessionLocal() as s:
            for a in s.scalars(select(DerivedArtifact)):
                run = s.get(Run, a.run_id)
                if run is not None and run.deleted_at is not None:
                    continue
                f = data / a.rel_path
                if not f.is_file():
                    missing += 1
                elif _sha256(f) != a.sha256:
                    mismatch += 1
                else:
                    ok += 1
            audit.record(
                s,
                "backup.restore",
                summary=f"Restored backup {path.name}",
                details={
                    "backup": path.name,
                    "moved_aside_to": aside.name if aside else None,
                    "files_restored": restored,
                    "dumped_files_ok": ok,
                    "dumped_files_missing": missing,
                    "dumped_files_mismatch": mismatch,
                },
            )
            s.commit()
    return RestoreReport(
        backup=path.name,
        moved_aside_to=str(aside) if aside else None,
        files_restored=restored,
        dumped_ok=ok,
        dumped_missing=missing,
        dumped_mismatch=mismatch,
    )


# --------------------------------------------------------------------------------- schedule


class BackupScheduler:
    """Background thread making a ``scheduled`` backup every FT_BACKUP_INTERVAL_HOURS (when the
    newest backup of any kind is older than that), keeping FT_BACKUP_KEEP of them."""

    CHECK_SECONDS = 300.0
    FIRST_CHECK_SECONDS = 60.0

    def __init__(self) -> None:
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_error: str | None = None
        self.last_attempt: datetime | None = None

    def start(self) -> None:
        if get_settings().backup_interval_hours <= 0 or self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="backup-scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(5)
            self._thread = None

    def due(self, now: datetime | None = None) -> bool:
        settings = get_settings()
        if settings.backup_interval_hours <= 0:
            return False
        now = now or _now()
        backups = list_backups(settings)
        if backups and now - backups[0].created_at < timedelta(
            hours=settings.backup_interval_hours
        ):
            return False
        # After a failure, wait a while before trying again.
        return not (
            self.last_error
            and self.last_attempt
            and now - self.last_attempt < timedelta(minutes=30)
        )

    def run_once(self) -> BackupInfo | None:
        if not self.due():
            return None
        self.last_attempt = _now()
        try:
            info = create_backup("scheduled")
        except Exception as exc:
            self.last_error = str(exc)
            logger.exception("scheduled backup failed")
            return None
        self.last_error = None
        return info

    def _loop(self) -> None:
        if self._stop.wait(self.FIRST_CHECK_SECONDS):
            return
        while not self._stop.is_set():
            self.run_once()
            self._stop.wait(self.CHECK_SECONDS)


_scheduler = BackupScheduler()


def get_scheduler() -> BackupScheduler:
    return _scheduler


# --------------------------------------------------------------------------------- manual (UI)

_manual_state: dict[str, Any] = {"running": False, "result": None, "error": None}


def start_manual_backup() -> bool:
    """Start a manual backup in a background thread. False if one is already running."""
    if _manual_state["running"]:
        return False
    _manual_state.update(running=True, result=None, error=None)

    def _target() -> None:
        try:
            _manual_state["result"] = create_backup("manual").name
        except Exception as exc:
            logger.exception("manual backup failed")
            _manual_state["error"] = str(exc)
        finally:
            _manual_state["running"] = False

    threading.Thread(target=_target, name="backup-manual", daemon=True).start()
    return True


def manual_state() -> dict[str, Any]:
    return dict(_manual_state)
