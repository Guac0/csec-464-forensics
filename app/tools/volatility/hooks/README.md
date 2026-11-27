# Post-run hooks (volatility3)

A hook is plugin-specific Python that runs **after a run succeeds**, reads its rows, and adds
meaning on top of the raw output. Use hooks for things like OS detection, flagging suspicious
rows, summarising a run, or queueing the obvious next plugin. Hooks never change the raw output.

Engine: `app/tools/hooks.py` (owned by the infrastructure side). This folder: your hooks.

## Adding a hook

1. Copy `_template.py` to a new file **without** the leading underscore, e.g. `pslist_orphans.py`.
   Every module in this folder is imported automatically at startup; files starting with `_` are
   skipped.
2. Set the plugin name(s) in `@post_run(...)`: the full name from `plugins.py` (e.g.
   `"windows.pslist.PsList"`), several names, or `"*"` for every plugin.
3. Write the logic using only the `ctx` methods below.
4. Add a test (see "Testing" below), then start the app. A hook module that fails to import is
   logged and listed at `GET /api/hooks` (`load_errors`); the app still starts.

```python
from app.tools.hooks import HookContext, post_run


@post_run("windows.pslist.PsList", version="1")
def flag_orphans(ctx: HookContext) -> None:
    """Flag processes whose parent PID is not in the list."""
    rows = list(ctx.rows())
    pids = {r.data.get("PID") for r in rows}
    orphans = [r.row_idx for r in rows if r.data.get("PPID") not in pids]
    for idx in orphans:
        ctx.annotate(idx, "orphan", severity="low", note="parent PID not in pslist")
    if orphans:
        ctx.add_finding(f"{len(orphans)} processes without a listed parent", rows=orphans)
```

(Illustrative only: check column names against real captured output, not memory.)

## What `ctx` offers

| Read | |
|---|---|
| `ctx.rows(run_id=None)` | Rows of this run (or another run on the same evidence) as read-only `HookRow(row_idx, depth, parent_idx, data)`, streamed in order |
| `ctx.artifacts()` | Files this run wrote (e.g. `--dump`): filename, size, SHA-256/MD5/SHA-1, guessed type, row that names it |
| `ctx.latest_run(plugin, args=None)` | Latest **succeeded** run of another plugin on this evidence (`RunInfo`), or `None` |
| `ctx.run_id`, `plugin`, `args`, `row_count`, `chain_depth` | About this run |
| `ctx.evidence_id`, `evidence_path`, `evidence_sha256`, `os_info` | About the image |

| Write (staged) | Shown where |
|---|---|
| `ctx.annotate(row_idx, tag, severity="info", note="")` | Badge in the results table, row highlighted by severity, filterable by tag, sent to the AI with the row |
| `ctx.add_finding(title, detail="", severity="info", rows=[...])` | "Post-processing" panel on the run page with row citations; sent to the AI |
| `ctx.update_evidence_metadata(**fields)` | Merged into `Evidence.os_info` (evidence list/page, AI context) |
| `ctx.queue_follow_up(plugin, args, reason="")` | Queues another run (origin `hook`), linked to this run |

Severities: `info`, `low`, `medium`, `high`.

## Rules the engine enforces

- **All or nothing per hook.** Writes are staged and applied only if your function returns. If it
  raises, nothing it staged is kept, the error (type, message, file/line) is shown on the run page,
  and the **run stays succeeded**. Other hooks still run.
- **Invalid calls raise** (row index out of range, unknown severity, empty tag/title, metadata that
  isn't JSON-serialisable). That surfaces as a hook error, so mistakes are visible.
- **Re-runnable.** Each hook pass clears the previous pass's annotations, findings and hook results
  for that run. "Re-run post-processing" on the run page (or `POST /api/runs/{id}/hooks/rerun`)
  re-imports the hook modules and runs them again, without re-running volatility. Evidence
  metadata is merged (not cleared).
- **Follow-up guards.** A follow-up is skipped (and the reason recorded, not an error) if:
  follow-ups are disabled (`FT_HOOK_FOLLOWUPS_ENABLED`), the chain would exceed
  `FT_HOOK_MAX_CHAIN_DEPTH` (default 2), the run already queued `FT_HOOK_MAX_FOLLOWUPS_PER_RUN`
  (default 10), the plugin/args are not in the allowlist, or an identical run (same evidence,
  plugin, args) is already queued, running or succeeded.
- Hooks run in the worker thread right after the run succeeds. **Keep them fast** (seconds); there
  is no per-hook timeout. Don't do network calls or write files.
- Bump `version=` when you change a hook's logic; it's recorded with each result.
- `FT_HOOKS_ENABLED=false` switches all hooks off.

## Testing

Hooks can be tested without volatility or Docker: insert a succeeded run with rows from a recorded
fixture, call `hooks.run_hooks(session, run_id)`, and check the results. See
`tests/test_hooks.py::test_example_windows_info_hook` for the pattern.

## Example in this folder

`windows_info.py` copies `windows.info` variables into the evidence's OS info. It is an EXAMPLE
(TODO(forensics): review the keys against real output).
