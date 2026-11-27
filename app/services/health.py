"""Setup and health checks shown on the System page (/system) and at /api/system/health.

Cheap checks run on every page load: disk space, folders, symbol tables, the worker, the
database, the audit chain, hooks and key settings. Checks that are slow or cost money (running
``vol``, calling the AI provider) only run when asked (``run_volatility_test`` / ``run_ai_test``).

``/health`` (app/main.py) stays a plain liveness probe for Docker.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import threading
import time
from contextlib import suppress
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.models import Evidence, Run, RunStatus
from app.services.resources import disk_status, fmt_bytes

Status = Literal["ok", "warn", "fail", "info"]
_RANK = {"ok": 0, "info": 0, "warn": 1, "fail": 2}

VOL_TEST_TIMEOUT = 120  # seconds; `vol -h` imports every plugin, which takes a few seconds
AI_TEST_PROMPT = "Reply with the single word OK."
BADGE_CACHE_SECONDS = 30.0
SECRET_SETTINGS = frozenset({"ai_api_key"})


@dataclass
class Check:
    key: str
    name: str
    status: Status
    summary: str
    details: list[tuple[str, str]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["details"] = [{"label": k, "value": v} for k, v in self.details]
        return d


def overall(checks: list[Check]) -> Status:
    worst = max((_RANK[c.status] for c in checks), default=0)
    return "fail" if worst == 2 else "warn" if worst == 1 else "ok"


# --------------------------------------------------------------------------- cheap checks


def check_disk(settings: Settings) -> Check:
    try:
        st = disk_status(settings, fresh=True)
    except OSError as exc:
        return Check(
            "disk", "Disk space", "fail", f"cannot read disk usage of the data folder: {exc}"
        )
    details = [
        ("Free on data volume", f"{fmt_bytes(st.free_bytes)} of {fmt_bytes(st.total_bytes)}"),
        ("New runs need (FT_MIN_FREE_DISK_BYTES)", fmt_bytes(st.min_free_bytes)),
        (
            "Running runs stop below (FT_HARD_MIN_FREE_DISK_BYTES)",
            fmt_bytes(st.hard_min_free_bytes),
        ),
        (
            "Data folder cap (FT_MAX_DATA_BYTES)",
            f"{fmt_bytes(st.data_bytes)} used of {fmt_bytes(st.max_data_bytes)}"
            if st.max_data_bytes
            else "no cap",
        ),
    ]
    if st.problem:
        return Check("disk", "Disk space", "fail", f"New runs are blocked: {st.problem}.", details)
    if st.warning:
        return Check(
            "disk", "Disk space", "warn", st.warning[0].upper() + st.warning[1:] + ".", details
        )
    return Check("disk", "Disk space", "ok", f"{fmt_bytes(st.free_bytes)} free.", details)


def _writable(path: Path) -> str | None:
    """None if a file can be created in ``path``, else the reason."""
    try:
        with tempfile.NamedTemporaryFile(dir=path, prefix=".healthcheck-"):
            pass
    except OSError as exc:
        return str(exc)
    return None


def check_folders(session: Session, settings: Settings) -> Check:
    problems: list[str] = []
    details: list[tuple[str, str]] = []
    ev_dir = settings.evidence_dir
    if not ev_dir.is_dir():
        problems.append(f"evidence folder {ev_dir} does not exist (is the volume mounted?)")
        details.append(("Evidence folder (FT_EVIDENCE_DIR)", f"{ev_dir} — missing"))
    elif not os.access(ev_dir, os.R_OK | os.X_OK):
        problems.append(f"evidence folder {ev_dir} is not readable")
        details.append(("Evidence folder (FT_EVIDENCE_DIR)", f"{ev_dir} — not readable"))
    else:
        count = session.scalar(select(func.count(Evidence.id))) or 0
        ro = "read-only" if not os.access(ev_dir, os.W_OK) else "writable (read-only is safer)"
        details.append(("Evidence folder (FT_EVIDENCE_DIR)", f"{ev_dir} — {ro}, {count} item(s)"))
    err = _writable(settings.data_dir)
    if err:
        problems.append(f"data folder {settings.data_dir} is not writable: {err}")
    details.append(
        (
            "Data folder (FT_DATA_DIR)",
            f"{settings.data_dir} — {'not writable' if err else 'writable'}",
        )
    )
    if problems:
        return Check("folders", "Folders", "fail", "; ".join(problems) + ".", details)
    return Check(
        "folders", "Folders", "ok", "Evidence folder readable, data folder writable.", details
    )


def check_symbols(settings: Settings) -> Check:
    path = settings.symbols_dir
    details = [
        ("Symbols folder (FT_SYMBOLS_DIR)", str(path)),
        ("Offline mode (FT_VOL_OFFLINE)", "on" if settings.vol_offline else "off"),
    ]
    if not path.is_dir():
        return Check(
            "symbols", "Symbol tables", "warn", f"symbols folder {path} does not exist.", details
        )
    try:
        entries = [e for e in path.iterdir() if not e.name.startswith(".")]
    except OSError as exc:
        return Check("symbols", "Symbol tables", "fail", f"cannot list {path}: {exc}", details)
    details.append(("Entries", str(len(entries))))
    writable = _writable(path) is None
    details.append(("Writable", "yes" if writable else "no"))
    if settings.vol_offline and not entries:
        return Check(
            "symbols",
            "Symbol tables",
            "warn",
            "Offline mode is on but the symbols folder is empty: most Windows plugins will fail. "
            "Pre-fill it with the volatility3 symbol packs.",
            details,
        )
    if not settings.vol_offline and not writable:
        return Check(
            "symbols",
            "Symbol tables",
            "warn",
            "The symbols folder is not writable, so downloaded symbols cannot be cached.",
            details,
        )
    summary = (
        f"{len(entries)} entr{'y' if len(entries) == 1 else 'ies'}"
        + (
            ""
            if settings.vol_offline
            else "; missing symbols are downloaded on demand (needs internet)"
        )
        + "."
    )
    return Check("symbols", "Symbol tables", "ok", summary, details)


def check_worker(session: Session, settings: Settings) -> Check:
    from app.jobs.worker import get_worker

    worker = get_worker()
    queued = session.scalar(select(func.count(Run.id)).where(Run.status == RunStatus.QUEUED)) or 0
    running = session.scalar(select(func.count(Run.id)).where(Run.status == RunStatus.RUNNING)) or 0
    interrupted = (
        session.scalar(select(func.count(Run.id)).where(Run.status == RunStatus.INTERRUPTED)) or 0
    )
    details = [
        (
            "Running / max at once (FT_MAX_CONCURRENT_RUNS)",
            f"{running} / {settings.max_concurrent_runs}",
        ),
        ("Queued", str(queued)),
        ("Default timeout (FT_RUN_TIMEOUT_SECONDS)", f"{settings.run_timeout_seconds} s"),
        ("Interrupted runs (all time)", str(interrupted)),
    ]
    if not worker.running:
        return Check(
            "worker",
            "Run worker",
            "fail",
            "The worker is not running: queued runs will not start.",
            details,
        )
    if worker.disk_problem and queued:
        return Check(
            "worker",
            "Run worker",
            "warn",
            f"{queued} queued run(s) waiting for disk space.",
            details,
        )
    return Check(
        "worker", "Run worker", "ok", f"Running; {running} running, {queued} queued.", details
    )


def check_database(session: Session, settings: Settings) -> Check:
    from alembic.script import ScriptDirectory

    from app.db import alembic_config

    details: list[tuple[str, str]] = []
    try:
        current = session.execute(text("SELECT version_num FROM alembic_version")).scalar()
        head = ScriptDirectory.from_config(alembic_config()).get_current_head()
        details.append(("Schema version", f"{current} (latest {head})"))
        details.append(("SQLite", session.execute(text("SELECT sqlite_version()")).scalar() or "?"))
        details.append(
            ("Journal mode", session.execute(text("PRAGMA journal_mode")).scalar() or "?")
        )
        db_file = settings.data_dir / "forensics.db"
        if db_file.exists():
            details.append(("File size", fmt_bytes(db_file.stat().st_size)))
    except Exception as exc:
        return Check("database", "Database", "fail", f"cannot query the database: {exc}", details)
    if current != head:
        return Check(
            "database", "Database", "fail", f"schema is at {current}, expected {head}.", details
        )
    return Check("database", "Database", "ok", "Reachable and up to date.", details)


def check_audit(session: Session, settings: Settings) -> Check:
    from app.services import audit

    report = audit.verify_chain(session)
    details = [
        ("Events", str(report.events)),
        ("Head hash", report.head_hash or "—"),
        ("Level (FT_AUDIT_LEVEL)", settings.audit_level),
    ]
    if not report.ok:
        return Check(
            "audit", "Audit log", "fail", f"Integrity check FAILED: {report.error}", details
        )
    if settings.audit_level == "all":
        return Check(
            "audit",
            "Audit log",
            "info",
            f"Chain verified ({report.events} events). Level is 'all' (temporary for the PoC; "
            "intended: key_reads).",
            details,
        )
    return Check("audit", "Audit log", "ok", f"Chain verified ({report.events} events).", details)


def check_hooks(settings: Settings) -> Check:
    from app.tools import hooks

    errors = hooks.load_hooks()
    registered = hooks.registered_hooks()
    details = [("Enabled (FT_HOOKS_ENABLED)", "yes" if settings.hooks_enabled else "no")]
    details += [(f"Failed to load: {m}", e) for m, e in sorted(errors.items())]
    if errors:
        return Check(
            "hooks",
            "Post-run hooks",
            "warn",
            f"{len(errors)} hook module(s) failed to load.",
            details,
        )
    return Check("hooks", "Post-run hooks", "ok", f"{len(registered)} hook(s) registered.", details)


def check_backups(session: Session, settings: Settings) -> Check:
    from app.models import AuditEvent
    from app.services import backup

    folder = settings.backup_dir
    details = [
        ("Folder (FT_BACKUP_DIR)", str(folder)),
        (
            "Automatic (FT_BACKUP_INTERVAL_HOURS / FT_BACKUP_KEEP)",
            f"every {settings.backup_interval_hours} h, keep {settings.backup_keep}"
            if settings.backup_interval_hours
            else "off",
        ),
    ]
    with suppress(OSError):
        folder.mkdir(parents=True, exist_ok=True)
    if not folder.is_dir() or _writable(folder) is not None:
        return Check(
            "backups",
            "Backups",
            "fail",
            f"backup folder {folder} is missing or not writable.",
            details,
        )
    backups = backup.list_backups(settings)
    if backups:
        details.append(("Latest", f"{backups[0].name} ({fmt_bytes(backups[0].size_bytes)})"))
        details.append(("Backups kept", str(len(backups))))
    with suppress(OSError):
        if os.stat(folder).st_dev == os.stat(settings.data_dir).st_dev:
            details.append(
                ("Same disk as data", "yes — copy backups off this machine for real safety")
            )
    scheduler = backup.get_scheduler()
    if scheduler.last_error:
        details.append(("Last automatic backup error", scheduler.last_error))

    # Anchor: the audit head recorded (outside the DB) by the last backup must still be in the
    # live chain with the same hash; otherwise the chain was rebuilt or the DB replaced.
    anchor = backup.last_anchor(settings)
    if anchor and anchor.get("head_seq"):
        live = session.scalar(select(AuditEvent.hash).where(AuditEvent.seq == anchor["head_seq"]))
        if live != anchor.get("head_hash"):
            return Check(
                "backups",
                "Backups",
                "fail",
                f"The audit log no longer contains the event anchored by backup "
                f"{anchor.get('backup')} (seq {anchor['head_seq']}): the log was rebuilt, or this "
                "database is not the one that was backed up (e.g. after a restore of an older "
                "backup).",
                details,
            )
        details.append(("Audit anchor", f"seq {anchor['head_seq']} matches"))

    if scheduler.last_error:
        return Check("backups", "Backups", "warn", "The last automatic backup failed.", details)
    if not backups:
        status: Status = "warn" if settings.backup_interval_hours else "info"
        return Check("backups", "Backups", status, "No backup yet.", details)
    age = datetime.now(UTC) - backups[0].created_at
    hours = age.total_seconds() / 3600
    if settings.backup_interval_hours and hours > 2 * settings.backup_interval_hours:
        return Check("backups", "Backups", "warn", f"Latest backup is {hours:.0f} h old.", details)
    return Check("backups", "Backups", "ok", f"Latest backup {hours:.1f} h ago.", details)


def check_catalog() -> Check:
    from app.tools import registry

    runner = registry.get_runner("volatility3")
    problems = runner.catalog_problems()
    valid = runner.plugins()
    writing = [p.name for p in valid if p.may_write_files]
    details = [
        ("Usable plugins", str(len(valid))),
        ("May write files", ", ".join(writing) or "none"),
    ]
    details += [(f"Skipped: {name}", "; ".join(errs)) for name, errs in sorted(problems.items())]
    if problems:
        return Check(
            "catalog",
            "Plugin catalog",
            "fail",
            f"{len(problems)} catalog entr{'y' if len(problems) == 1 else 'ies'} skipped as "
            "invalid (see details; fix app/tools/volatility/plugins.py).",
            details,
        )
    return Check("catalog", "Plugin catalog", "ok", f"{len(valid)} plugin(s), all valid.", details)


def check_ai_config(settings: Settings) -> Check:
    details = [
        ("Base URL (FT_AI_BASE_URL)", settings.ai_base_url),
        ("Model (FT_AI_MODEL)", settings.ai_model),
        ("API key (FT_AI_API_KEY)", "set" if settings.ai_api_key else "not set"),
    ]
    if not settings.ai_api_key and "localhost" not in settings.ai_base_url:
        return Check(
            "ai_config",
            "AI provider settings",
            "warn",
            "No API key set for a non-local provider. Use 'Test AI' to check.",
            details,
        )
    return Check(
        "ai_config",
        "AI provider settings",
        "info",
        "Configured. Use 'Test AI' to check it responds.",
        details,
    )


def quick_checks(session: Session, settings: Settings | None = None) -> list[Check]:
    settings = settings or get_settings()
    checks = []
    for fn in (
        lambda: check_disk(settings),
        lambda: check_folders(session, settings),
        lambda: check_symbols(settings),
        lambda: check_worker(session, settings),
        lambda: check_database(session, settings),
        lambda: check_audit(session, settings),
        lambda: check_hooks(settings),
        check_catalog,
        lambda: check_backups(session, settings),
        lambda: check_ai_config(settings),
    ):
        try:
            checks.append(fn())
        except Exception as exc:  # a broken check must not break the page
            checks.append(Check("error", "Check failed", "fail", f"{type(exc).__name__}: {exc}"))
    return checks


def settings_summary(settings: Settings | None = None) -> list[tuple[str, str]]:
    """All settings as (FT_NAME, value), secrets masked."""
    settings = settings or get_settings()
    out = []
    for name, value in sorted(settings.model_dump().items()):
        if name in SECRET_SETTINGS:
            shown = "set" if value else "not set"
        else:
            shown = str(value)
        out.append((f"FT_{name.upper()}", shown))
    return out


# --------------------------------------------------------------------------- top-bar badge

_badge_lock = threading.Lock()
_badge_cache: tuple[float, Status, str] | None = None


def badge(session: Session) -> tuple[Status, str]:
    """(status, tooltip) for the top bar, from the cheapest checks; cached briefly."""
    global _badge_cache
    now = time.monotonic()
    with _badge_lock:
        if _badge_cache and now - _badge_cache[0] < BADGE_CACHE_SECONDS:
            return _badge_cache[1], _badge_cache[2]
    settings = get_settings()
    checks = [
        check_disk(settings),
        check_folders(session, settings),
        check_worker(session, settings),
    ]
    status = overall(checks)
    tip = "; ".join(c.summary for c in checks if c.status in ("warn", "fail")) or "All good"
    with _badge_lock:
        _badge_cache = (now, status, tip)
    return status, tip


def clear_badge_cache() -> None:
    global _badge_cache
    with _badge_lock:
        _badge_cache = None


# --------------------------------------------------------------------------- on-demand tests


def run_volatility_test(settings: Settings | None = None) -> Check:
    """Run ``vol -h``: checks volatility3 starts and that every catalog plugin exists in it."""
    from app.tools import registry
    from app.tools.volatility.runner import vol_command

    settings = settings or get_settings()
    argv = [*vol_command(settings.vol_executable), "-h"]
    details = [("Command", " ".join(argv))]
    started = time.monotonic()
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv from settings, no shell
            argv,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=VOL_TEST_TIMEOUT,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except FileNotFoundError:
        return Check(
            "volatility",
            "Volatility test",
            "fail",
            f"{argv[0]!r} not found (FT_VOL_EXECUTABLE).",
            details,
        )
    except subprocess.TimeoutExpired:
        return Check(
            "volatility",
            "Volatility test",
            "fail",
            f"`vol -h` did not finish in {VOL_TEST_TIMEOUT}s.",
            details,
        )
    except OSError as exc:
        return Check(
            "volatility", "Volatility test", "fail", f"cannot start {argv[0]!r}: {exc}", details
        )
    elapsed = time.monotonic() - started
    output = proc.stdout + "\n" + proc.stderr
    first = next((ln.strip() for ln in output.splitlines() if "Volatility" in ln), "")
    details.append(("Exit code", str(proc.returncode)))
    details.append(("Took", f"{elapsed:.1f} s"))
    if first:
        details.append(("Reports", first))
    if proc.returncode != 0:
        tail = output.strip()[-500:]
        details.append(("Output (tail)", tail))
        return Check(
            "volatility",
            "Volatility test",
            "fail",
            f"`vol -h` exited with code {proc.returncode}.",
            details,
        )
    catalog = [p.name for p in registry.get_runner("volatility3").plugins()]
    missing = [name for name in catalog if name not in output]
    details.append(("Catalog plugins found", f"{len(catalog) - len(missing)} / {len(catalog)}"))
    if missing:
        details.append(("Missing from this volatility", ", ".join(missing)))
        return Check(
            "volatility",
            "Volatility test",
            "warn",
            f"Volatility runs, but {len(missing)} catalog plugin(s) are not in it (wrong name or "
            "version).",
            details,
        )
    return Check(
        "volatility",
        "Volatility test",
        "ok",
        "Volatility runs and knows every catalog plugin.",
        details,
    )


def run_ai_test(settings: Settings | None = None) -> Check:
    """Send one tiny chat request to the configured provider."""
    from app.ai.client import AIClient, AIError

    settings = settings or get_settings()
    details = [("Base URL", settings.ai_base_url), ("Model", settings.ai_model)]
    started = time.monotonic()
    try:
        result = AIClient(settings).chat(
            [{"role": "user", "content": AI_TEST_PROMPT}], max_tokens=10, temperature=0
        )
    except AIError as exc:
        return Check("ai", "AI test", "fail", str(exc), details)
    details.append(("Took", f"{time.monotonic() - started:.1f} s"))
    details.append(("Model answering", result.model_returned or "—"))
    details.append(("Reply", (result.content or "").strip()[:100] or "(empty)"))
    if result.usage:
        details.append(("Tokens", str(result.usage.get("total_tokens", "?"))))
    return Check("ai", "AI test", "ok", "The AI provider answered.", details)
