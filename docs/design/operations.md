> Written mainly for AI coding assistants. People: start with README.md or forensics/README.md.

# Operations and safety: decisions

## Crash recovery, limits, health (PR #12, migration 0007)
- Runs left running at startup become INTERRUPTED with a Re-run button; queued runs resume.
- Disk guard: block new runs below 5 GiB free, stop running ones below 1 GiB; optional
  `FT_MAX_DATA_BYTES` cap.
- System page: cheap checks on load, expensive ones behind Test buttons.

## Backups, catalog check, run deletion, watchdog (PR #13, migration 0008)
- Backups: CLI (`python -m app.backup`) + button + automatic every 24 h, own `/backups` volume,
  dumped files excluded, audit anchors written beside them.
- Run deletion = tombstone (rows/artifacts removed, run record kept for the audit trail).
- Invalid catalog entries are skipped, logged and shown on the System page; CI fails on them.
  Plugins/options that write files must be declared `writes_files=True`.
- Stall watchdog: `FT_RUN_STALL_SECONDS=600` frees the slot of a run with no progress.

## Windows test compatibility (PR #14)
Tests run natively on Windows: no symlinks without a skip, no `os.kill(pid, 0)`, close DB
connections before moving files, `.py` vol stand-ins run via `vol_command`.

## Earlier (phase 1)
Alembic, post-run hooks, hash-chained audit log, evidence integrity checks, derived artifacts
(dumped files hashed + linked to rows), large-result paging/index, AI eval harness, case export.
Details per area in CONTRACTS.md.
