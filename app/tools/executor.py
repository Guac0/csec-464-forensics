"""Generic, tool-agnostic subprocess executor.

Runs the argv produced by ``runner.build_argv`` without a shell, streams stdout/stderr to files in
``run_dir``, enforces a timeout, honours a cancel event, and kills the whole process group when
stopping early.
"""

from __future__ import annotations

import hashlib
import os
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from pathlib import Path

from app.tools.base import ExecutionResult, ToolRequest, ToolRunner

STDOUT_NAME = "stdout.jsonl"
STDERR_NAME = "stderr.txt"
OUTPUT_DIR_NAME = "output"

HEARTBEAT_INTERVAL = 5.0  # seconds between on_heartbeat calls
POLL_INTERVAL = 0.2  # seconds between checks of process/cancel/timeout
KILL_GRACE = 5.0  # seconds between SIGTERM and SIGKILL
OUTPUT_CHECK_INTERVAL = 2.0  # seconds between output-dir size checks


def dir_size(path: Path) -> int:
    """Total size of regular files under ``path`` (symlinks not followed)."""
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                st = os.lstat(os.path.join(root, name))
            except OSError:
                continue
            if not os.path.islink(os.path.join(root, name)):
                total += st.st_size
    return total


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


IS_WINDOWS = os.name == "nt"


def _kill_tree_windows(proc: subprocess.Popen[bytes]) -> None:
    """Windows has no process groups/signals: kill the process and all its descendants with
    taskkill /T (must run while the parent is still alive, or its children are not found)."""
    try:
        subprocess.run(  # noqa: S603 - fixed argv
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],  # noqa: S607 - system tool
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        proc.kill()  # in case taskkill was unavailable
    except OSError:
        pass


def _signal_group(proc: subprocess.Popen[bytes], sig: int) -> None:
    """Send ``sig`` to the process group of ``proc``; fall back to the process itself."""
    killpg = getattr(os, "killpg", None)
    if killpg is not None:
        try:
            killpg(proc.pid, sig)  # start_new_session=True => pgid == pid
            return
        except ProcessLookupError:
            return
        except OSError:
            pass  # fall through to single-process kill
    try:
        if sig == getattr(signal, "SIGKILL", None):
            proc.kill()
        else:
            proc.terminate()
    except ProcessLookupError:
        pass


def _stop(proc: subprocess.Popen[bytes], grace: float) -> None:
    """SIGTERM the process group, then SIGKILL it if still alive after ``grace`` seconds.
    On Windows the whole process tree is killed at once (there is no graceful signal)."""
    if IS_WINDOWS:
        _kill_tree_windows(proc)
        try:
            proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:  # pragma: no cover - pathological
            pass
        return
    _signal_group(proc, signal.SIGTERM)
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        pass
    # Kill the group even if the leader exited: children may still be running.
    _signal_group(proc, getattr(signal, "SIGKILL", signal.SIGTERM))
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:  # pragma: no cover - pathological
        proc.kill()
        proc.wait()


def execute(
    runner: ToolRunner,
    evidence_path: Path,
    request: ToolRequest,
    run_dir: Path,
    timeout: float,
    cancel_event: threading.Event,
    on_heartbeat: Callable[[], None] | None = None,
    *,
    heartbeat_interval: float = HEARTBEAT_INTERVAL,
    kill_grace: float = KILL_GRACE,
    max_output_bytes: int | None = None,
    output_check_interval: float | None = None,
    on_start: Callable[[int, list[str]], None] | None = None,
    should_stop: Callable[[], str | None] | None = None,
) -> ExecutionResult:
    """Run one tool invocation and return its ExecutionResult.

    - Creates ``run_dir`` and ``run_dir/"output"`` (passed to ``build_argv`` as ``output_dir``
      for files the tool dumps).
    - ``runner.build_argv`` validates the request; ``ArgValidationError`` propagates unchanged
      (nothing is launched).
    - stdout -> ``run_dir/stdout.jsonl``, stderr -> ``run_dir/stderr.txt``; stdin is /dev/null.
    - The process runs in its own session; on timeout or ``cancel_event`` the whole process group
      gets SIGTERM, then SIGKILL after ``kill_grace`` seconds. ``timed_out`` / ``cancelled`` are set
      on the result and ``returncode`` is whatever the killed process returned (negative signal
      number on POSIX).
    - ``on_heartbeat`` is called roughly every ``heartbeat_interval`` seconds while running.
      Exceptions it raises are swallowed so a DB hiccup cannot orphan the child process.
    - If the executable cannot be launched (``FileNotFoundError`` / ``PermissionError``) no
      exception is raised: the result has ``returncode=None``, ``stdout_sha256=None`` and a clear
      message written to the stderr file, so the worker's usual "record stderr tail" failure path
      applies. Callers should treat ``returncode is None`` (and not cancelled/timed out) as failure.
    - ``stdout_sha256`` is the SHA-256 of the stdout file after exit.
    - ``max_output_bytes``: if the files the tool writes into ``run_dir/output`` grow past this,
      the process group is stopped and ``output_limit_exceeded`` is set (checked every
      ``output_check_interval`` seconds and once more after exit).
    - ``on_start(pid, argv)`` is called once the process is launched (the worker records both,
      so an interrupted run keeps its exact command and an orphaned process can be found after a
      crash). Its exceptions are swallowed.
    - ``should_stop()`` is called every ``output_check_interval`` seconds; if it returns a
      reason, the process group is stopped and ``stop_reason`` is set (e.g. disk nearly full).
    """
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    output_dir = run_dir / OUTPUT_DIR_NAME
    output_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = run_dir / STDOUT_NAME
    stderr_path = run_dir / STDERR_NAME

    argv = runner.build_argv(evidence_path, request, output_dir)
    tool_version = runner.version()

    timed_out = False
    cancelled = False
    with stdout_path.open("wb") as out_f, stderr_path.open("wb") as err_f:
        try:
            proc = subprocess.Popen(
                argv,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=out_f,
                stderr=err_f,
                start_new_session=True,
                cwd=run_dir,
            )
        except (FileNotFoundError, PermissionError) as exc:
            err_f.write(
                f"failed to launch tool executable {argv[0]!r}: {exc}\n".encode("utf-8", "replace")
            )
            return ExecutionResult(
                argv=argv,
                returncode=None,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                stdout_sha256=None,
                tool_version=tool_version,
            )

        if on_start is not None:
            try:
                on_start(proc.pid, list(argv))
            except Exception:  # noqa: S110 - bookkeeping must not orphan the child process
                pass

        output_check_interval = output_check_interval or OUTPUT_CHECK_INTERVAL
        start = time.monotonic()
        last_heartbeat = last_output_check = start
        output_limit_exceeded = False
        stop_reason: str | None = None
        while True:
            try:
                proc.wait(timeout=POLL_INTERVAL)
                break
            except subprocess.TimeoutExpired:
                pass
            now = time.monotonic()
            if cancel_event.is_set():
                cancelled = True
                _stop(proc, kill_grace)
                break
            if timeout and now - start >= timeout:
                timed_out = True
                _stop(proc, kill_grace)
                break
            if now - last_output_check >= output_check_interval:
                last_output_check = now
                if max_output_bytes is not None and dir_size(output_dir) > max_output_bytes:
                    output_limit_exceeded = True
                    _stop(proc, kill_grace)
                    break
                if should_stop is not None:
                    try:
                        stop_reason = should_stop()
                    except Exception:
                        stop_reason = None
                    if stop_reason:
                        _stop(proc, kill_grace)
                        break
            if on_heartbeat is not None and now - last_heartbeat >= heartbeat_interval:
                last_heartbeat = now
                try:
                    on_heartbeat()
                except Exception:  # noqa: S110 - heartbeat failures must not kill the run
                    pass

    return ExecutionResult(
        argv=argv,
        returncode=proc.returncode,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        stdout_sha256=sha256_file(stdout_path),
        tool_version=tool_version,
        timed_out=timed_out,
        cancelled=cancelled,
        output_limit_exceeded=output_limit_exceeded
        or (max_output_bytes is not None and dir_size(output_dir) > max_output_bytes),
        stop_reason=stop_reason,
    )
