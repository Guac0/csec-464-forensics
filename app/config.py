"""Application settings, read from environment variables (see .env.example)."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FT_", env_file=".env", extra="ignore")

    # Read-only mount containing RAM images placed there by the user.
    evidence_dir: Path = Path("/evidence")
    # Comma-separated file extensions ignored when scanning evidence_dir (docs, hashes, archives).
    # A denylist rather than an allowlist: memory images use many extensions (.raw, .mem, .vmem,
    # .dmp, .lime, .bin, .img, .001, ...) or none at all.
    evidence_exclude_extensions: str = (
        ".md,.txt,.rst,.pdf,.html,.json,.csv,.log,.ini,.yml,.yaml,"
        ".md5,.sha1,.sha256,.sha512,.sig,.asc,"
        ".zip,.7z,.rar,.gz,.bz2,.xz,.tar,.tgz"
    )
    # Writable persistent data: SQLite DB, raw tool output, dumped files.
    data_dir: Path = Path("/data")
    # Writable volatility3 symbol cache.
    symbols_dir: Path = Path("/symbols")
    # Backups (app/services/backup.py). Keep this on a different volume from data_dir.
    backup_dir: Path = Path("/backups")
    # Automatic backup when the newest backup is older than this many hours (0 = off).
    backup_interval_hours: int = 24
    # Number of automatic backups kept (manual and command-line backups are never pruned).
    backup_keep: int = 7

    # Max concurrent tool runs (volatility is memory hungry).
    max_concurrent_runs: int = 1
    # Default per-run timeout in seconds (a catalog entry can set its own timeout_seconds).
    run_timeout_seconds: int = 3600

    # Disk protection (app/services/resources.py), all in bytes:
    # new runs are refused, and queued runs wait, while free space on the data volume is below
    # this...
    min_free_disk_bytes: int = 5 * 1024**3
    # ...or while data_dir is larger than this (0 = no cap; warns from 80%).
    max_data_bytes: int = 0
    # A running run is stopped if free space drops below this (protects the SQLite database).
    hard_min_free_disk_bytes: int = 1024**3
    # Stall watchdog: an active run with no sign of progress for this many seconds (tool
    # heartbeat, row ingest, next hook) is marked interrupted / its hooks failed, and its worker
    # slot is freed. 0 = off. A slow but alive `vol` process is FT_RUN_TIMEOUT_SECONDS' job.
    run_stall_seconds: int = 600
    # Executable used to invoke volatility3.
    vol_executable: str = "vol"
    # Pass --offline to volatility3 (no symbol downloads; pre-fill the symbols volume first).
    vol_offline: bool = False

    # Audit log detail (app/services/audit.py):
    #   "changes"   - only actions that change data
    #   "key_reads" - changes + sensitive reads (verify, exports, downloads) <- intended default
    #   "all"       - also every HTTP request (page views, API reads, HTMX polling)
    # TEMPORARY: "all" while the PoC is being evaluated, for maximum coverage. Switching to the
    # intended level later is just changing this default (or FT_AUDIT_LEVEL); nothing else.
    audit_level: Literal["changes", "key_reads", "all"] = "all"

    # Evidence integrity (app/services/integrity.py):
    #   "strict" - runs are refused/failed if the image changed since it was hashed or does not
    #              match the analyst's expected hashes (unless the mismatch is acknowledged)
    #   "warn"   - runs go ahead; the problem is recorded on the run as a warning
    integrity_mode: Literal["strict", "warn"] = "strict"
    # Also re-hash the whole image before every run (slow on big images). Off: a fast size +
    # modification-time check is done before every run instead.
    verify_on_run: bool = False

    # Files written by tools (e.g. --dump) per run: the run is stopped if they exceed this.
    max_artifact_bytes: int = 2 * 1024**3
    # Password of the encrypted zip that artifacts are downloaded in (malware-sharing convention).
    artifact_zip_password: str = "infected"  # noqa: S105 - public convention, not a secret

    # Full-text (trigram) search index for result rows: near-instant substring search on very
    # large runs, at the cost of ~2x row storage and slower ingest. Applies to runs stored while
    # enabled (others use a scan, which is fine up to ~1M rows). See scripts/bench_rows.py.
    search_index: bool = False

    # Post-run hooks (app/tools/hooks.py).
    hooks_enabled: bool = True
    # Allow hooks to queue follow-up runs automatically.
    hook_followups_enabled: bool = True
    # Max length of a follow-up chain (user run -> follow-up -> follow-up ...). 0 = no follow-ups.
    hook_max_chain_depth: int = 2
    # Max follow-up runs a single run's hooks may queue in one pass.
    hook_max_followups_per_run: int = 10

    # External OpenAI-compatible AI provider.
    ai_base_url: str = "http://localhost:11434/v1"
    ai_api_key: str = ""
    ai_model: str = "gpt-4o-mini"
    ai_temperature: float = 0.2
    ai_max_tokens: int = 2000
    ai_timeout_seconds: int = 120
    # How the AI agent ("give the AI a goal") calls its tools: "native" = OpenAI function
    # calling, "text" = one fenced JSON action block per reply (any model), "auto" = native,
    # falling back to text when the provider rejects tools or the model ignores them.
    ai_tool_mode: Literal["auto", "native", "text"] = "auto"
    # Default limits of an AI agent task (the analyst can lower/raise them per task).
    agent_max_steps: int = 12  # model calls per task
    agent_max_seconds: int = 600  # wall-clock time per task
    agent_max_concurrent: int = 2  # tasks running at once (others wait)

    @property
    def excluded_evidence_suffixes(self) -> frozenset[str]:
        parts = (p.strip().lower() for p in self.evidence_exclude_extensions.split(","))
        return frozenset(p if p.startswith(".") else f".{p}" for p in parts if p)

    @property
    def database_url(self) -> str:
        return f"sqlite:///{self.data_dir / 'forensics.db'}"

    @property
    def runs_dir(self) -> Path:
        return self.data_dir / "runs"


@lru_cache
def get_settings() -> Settings:
    return Settings()
