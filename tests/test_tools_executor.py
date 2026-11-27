"""executor.execute with tests/fixtures/fake_vol.py standing in for `vol`."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time
from pathlib import Path

import pytest

from app.config import Settings, get_settings
from app.tools.base import ArgValidationError, ToolRequest
from app.tools.executor import execute
from app.tools.volatility.runner import VolatilityRunner

FAKE_VOL = Path(__file__).parent / "fixtures" / "fake_vol.py"


@pytest.fixture
def fake_vol(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> Settings:
    if not os.access(FAKE_VOL, os.X_OK):  # e.g. lost exec bit on checkout
        FAKE_VOL.chmod(0o755)
    monkeypatch.setenv("FT_VOL_EXECUTABLE", str(FAKE_VOL))
    get_settings.cache_clear()
    return get_settings()


def run(
    settings: Settings,
    tmp_path: Path,
    *,
    request: ToolRequest | None = None,
    timeout: float = 30,
    cancel: threading.Event | None = None,
    **kw,
):
    return execute(
        VolatilityRunner(),
        settings.evidence_dir / "sample.raw",
        request or ToolRequest("windows.pslist.PsList", {"pid": [4]}),
        tmp_path / "run",
        timeout,
        cancel or threading.Event(),
        **kw,
    )


def _pid_alive(pid: int) -> bool:
    if os.name == "nt":  # os.kill(pid, 0) would TERMINATE the process on Windows
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        code = ctypes.c_ulong()
        try:
            kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        finally:
            kernel32.CloseHandle(handle)
        return code.value == 259  # STILL_ACTIVE
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # Might be a zombie awaiting reap by init; check /proc where available.
    stat = Path(f"/proc/{pid}/stat")
    if stat.exists():
        return stat.read_text().split(")")[-1].split()[0] != "Z"
    return True


def test_success(fake_vol: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_VOL_MODE", "ok")
    res = run(fake_vol, tmp_path)
    assert res.returncode == 0
    assert not res.timed_out and not res.cancelled
    assert res.stdout_path == tmp_path / "run" / "stdout.jsonl"
    assert res.stderr_path == tmp_path / "run" / "stderr.txt"
    assert (tmp_path / "run" / "output").is_dir()
    assert res.stdout_sha256 == hashlib.sha256(res.stdout_path.read_bytes()).hexdigest()
    assert "Volatility 3 Framework" in res.stderr_path.read_text()
    assert res.argv[:2] == [sys.executable, str(FAKE_VOL)]  # .py scripts run via Python
    rows = list(VolatilityRunner().parse_output(res.stdout_path))
    assert [(r.data["PID"], r.depth, r.parent_idx) for r in rows] == [
        (4, 0, None),
        (100, 1, 0),
        (101, 2, 1),
        (200, 0, None),
    ]


def test_argv_reaches_process(
    fake_vol: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_VOL_MODE", "argv")
    res = run(fake_vol, tmp_path)
    line = [ln for ln in res.stdout_path.read_text().splitlines() if ln.strip()][0]
    assert json.loads(line)["argv"] == res.argv[2:]  # after [python, fake_vol.py]
    assert res.argv[-3:] == ["windows.pslist.PsList", "--pid", "4"]


def test_nonzero_exit(fake_vol: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_VOL_MODE", "fail")
    monkeypatch.setenv("FAKE_VOL_EXIT", "3")
    res = run(fake_vol, tmp_path)
    assert res.returncode == 3
    assert "Unsatisfied requirement" in res.stderr_path.read_text()
    assert res.stdout_sha256 == hashlib.sha256(b"").hexdigest()


def test_timeout_kills_process_group(
    fake_vol: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_VOL_MODE", "spawn")
    t0 = time.monotonic()
    res = run(fake_vol, tmp_path, timeout=1.5, kill_grace=1.0)
    assert time.monotonic() - t0 < 10
    assert res.timed_out and not res.cancelled
    assert res.returncode is not None and res.returncode != 0
    child_pid = json.loads(res.stdout_path.read_text().splitlines()[0])["child_pid"]
    deadline = time.monotonic() + 5
    while _pid_alive(child_pid) and time.monotonic() < deadline:
        time.sleep(0.1)
    assert not _pid_alive(child_pid), "grandchild survived process-group kill"


def test_cancel_event(fake_vol: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_VOL_MODE", "sleep")
    cancel = threading.Event()
    threading.Timer(0.5, cancel.set).start()
    t0 = time.monotonic()
    res = run(fake_vol, tmp_path, cancel=cancel, kill_grace=1.0)
    assert time.monotonic() - t0 < 10
    assert res.cancelled and not res.timed_out
    assert res.returncode != 0


def test_heartbeat_called(
    fake_vol: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_VOL_MODE", "sleep")
    monkeypatch.setenv("FAKE_VOL_SLEEP", "1.5")
    beats: list[float] = []
    res = run(fake_vol, tmp_path, on_heartbeat=lambda: beats.append(1), heartbeat_interval=0.3)
    assert res.returncode == 0
    assert len(beats) >= 2


def test_heartbeat_exception_does_not_break_run(
    fake_vol: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_VOL_MODE", "sleep")
    monkeypatch.setenv("FAKE_VOL_SLEEP", "0.8")

    def boom() -> None:
        raise RuntimeError("db down")

    res = run(fake_vol, tmp_path, on_heartbeat=boom, heartbeat_interval=0.2)
    assert res.returncode == 0


def test_missing_executable(
    settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FT_VOL_EXECUTABLE", str(tmp_path / "no-such-vol"))
    get_settings.cache_clear()
    res = run(get_settings(), tmp_path)
    assert res.returncode is None
    assert res.stdout_sha256 is None
    assert "failed to launch" in res.stderr_path.read_text()


def test_invalid_request_raises_before_launch(fake_vol: Settings, tmp_path: Path) -> None:
    with pytest.raises(ArgValidationError):
        run(fake_vol, tmp_path, request=ToolRequest("windows.pslist.PsList", {"bad": 1}))
    assert not (tmp_path / "run" / "stdout.jsonl").exists()
