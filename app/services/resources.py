"""Disk-space guard for tool runs.

Volatility runs write raw output, dumped files and result rows into ``data_dir``. A full disk can
corrupt the SQLite database, so:

- New runs are refused (and queued runs wait) when free space on the data volume is below
  ``FT_MIN_FREE_DISK_BYTES`` or ``data_dir`` is larger than ``FT_MAX_DATA_BYTES`` (0 = no cap).
- A running run is stopped when free space drops below ``FT_HARD_MIN_FREE_DISK_BYTES``.

Queued runs are never failed for lack of space: the worker leaves them queued and starts them
as soon as space is available again.
"""

from __future__ import annotations

import logging
import os
import shutil
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from app.config import Settings, get_settings

logger = logging.getLogger(__name__)

# data_dir size is a directory walk; cache it for this many seconds.
DATA_SIZE_CACHE_SECONDS = 30.0


class DiskSpaceError(ValueError):
    """An action is refused because the data volume is (nearly) full."""


@dataclass(frozen=True)
class DiskStatus:
    free_bytes: int
    total_bytes: int
    data_bytes: int
    min_free_bytes: int
    hard_min_free_bytes: int
    max_data_bytes: int  # 0 = no cap

    @property
    def problem(self) -> str | None:
        """Why new runs are refused right now, or None."""
        if self.free_bytes < self.min_free_bytes:
            return (
                f"only {fmt_bytes(self.free_bytes)} free on the data volume; new runs need at "
                f"least {fmt_bytes(self.min_free_bytes)} (FT_MIN_FREE_DISK_BYTES)"
            )
        if self.max_data_bytes and self.data_bytes >= self.max_data_bytes:
            return (
                f"the data folder uses {fmt_bytes(self.data_bytes)}, at or over its cap of "
                f"{fmt_bytes(self.max_data_bytes)} (FT_MAX_DATA_BYTES)"
            )
        return None

    @property
    def warning(self) -> str | None:
        """Early warning (80% of the cap, or less than twice the minimum free space)."""
        if self.problem:
            return self.problem
        if self.max_data_bytes and self.data_bytes >= 0.8 * self.max_data_bytes:
            return (
                f"the data folder uses {fmt_bytes(self.data_bytes)} of its "
                f"{fmt_bytes(self.max_data_bytes)} cap"
            )
        if self.min_free_bytes and self.free_bytes < 2 * self.min_free_bytes:
            return f"free space is getting low ({fmt_bytes(self.free_bytes)} free)"
        return None


def fmt_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(size) < 1024 or unit == "TiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"  # pragma: no cover


def _dir_size(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            full = os.path.join(root, name)
            try:
                if not os.path.islink(full):
                    total += os.lstat(full).st_size
            except OSError:
                continue
    return total


_size_lock = threading.Lock()
_size_cache: dict[str, tuple[float, int]] = {}


def data_dir_size(settings: Settings | None = None, *, fresh: bool = False) -> int:
    """Total size of files under data_dir (cached for DATA_SIZE_CACHE_SECONDS)."""
    settings = settings or get_settings()
    key = str(settings.data_dir)
    now = time.monotonic()
    with _size_lock:
        cached = _size_cache.get(key)
        if cached and not fresh and now - cached[0] < DATA_SIZE_CACHE_SECONDS:
            return cached[1]
    size = _dir_size(settings.data_dir)
    with _size_lock:
        _size_cache[key] = (now, size)
    return size


def free_bytes(settings: Settings | None = None) -> int:
    settings = settings or get_settings()
    return shutil.disk_usage(settings.data_dir).free


def disk_status(settings: Settings | None = None, *, fresh: bool = False) -> DiskStatus:
    settings = settings or get_settings()
    usage = shutil.disk_usage(settings.data_dir)
    return DiskStatus(
        free_bytes=usage.free,
        total_bytes=usage.total,
        # Only walk the folder when a cap is configured (the walk can be slow on big cases).
        data_bytes=data_dir_size(settings, fresh=fresh) if settings.max_data_bytes else 0,
        min_free_bytes=settings.min_free_disk_bytes,
        hard_min_free_bytes=settings.hard_min_free_disk_bytes,
        max_data_bytes=settings.max_data_bytes,
    )


def check_can_start_run(settings: Settings | None = None) -> None:
    """Raise DiskSpaceError if a new run must not be queued or started right now."""
    problem = disk_status(settings).problem
    if problem:
        raise DiskSpaceError(f"not enough disk space: {problem}")


def hard_floor_problem(settings: Settings | None = None) -> str | None:
    """Reason to stop a running run (free space under the hard floor), or None. Cheap."""
    settings = settings or get_settings()
    if not settings.hard_min_free_disk_bytes:
        return None
    try:
        free = free_bytes(settings)
    except OSError:
        return None
    if free < settings.hard_min_free_disk_bytes:
        return (
            f"stopped: free disk space fell to {fmt_bytes(free)}, below the hard minimum of "
            f"{fmt_bytes(settings.hard_min_free_disk_bytes)} (FT_HARD_MIN_FREE_DISK_BYTES); "
            "output written so far was kept"
        )
    return None
