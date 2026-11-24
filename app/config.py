"""Application settings, read from environment variables (see .env.example)."""

from functools import lru_cache
from pathlib import Path

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

    # Max concurrent tool runs (volatility is memory hungry).
    max_concurrent_runs: int = 1
    # Per-run timeout in seconds.
    run_timeout_seconds: int = 3600
    # Executable used to invoke volatility3.
    vol_executable: str = "vol"
    # Pass --offline to volatility3 (no symbol downloads; pre-fill the symbols volume first).
    vol_offline: bool = False

    # External OpenAI-compatible AI provider.
    ai_base_url: str = "http://localhost:11434/v1"
    ai_api_key: str = ""
    ai_model: str = "gpt-4o-mini"
    ai_temperature: float = 0.2
    ai_max_tokens: int = 2000
    ai_timeout_seconds: int = 120

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
