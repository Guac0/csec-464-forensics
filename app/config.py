"""Application settings, read from environment variables (see .env.example)."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FT_", env_file=".env", extra="ignore")

    # Read-only mount containing RAM images placed there by the user.
    evidence_dir: Path = Path("/evidence")
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
    def database_url(self) -> str:
        return f"sqlite:///{self.data_dir / 'forensics.db'}"

    @property
    def runs_dir(self) -> Path:
        return self.data_dir / "runs"


@lru_cache
def get_settings() -> Settings:
    return Settings()
