# Forensics content: start here

This folder holds everything the forensics team owns: which volatility3 plugins the tool may
run, with which options, what it recommends running next, and the hooks that flag interesting
rows. The rest of the repository (the web app, the job runner, the AI plumbing) is the
infrastructure. You shouldn't need to touch it to add or change forensic content.

Each plugin lives in its own file, and the file holds everything about that plugin.

```
forensics/
  README.md            this guide
  sdk.py               the names you import in plugin files (don't edit)
  common.py            pieces shared by several plugins, like the --pid option
  plugins/
    _template.py       copy this to add a plugin (it is never loaded itself)
    windows/
      pslist.py        windows.pslist.PsList
      malware_malfind.py   windows.malware.malfind.Malfind
      ...
  hooks/               hooks that read several plugins' output (rare)
```

Still outside this folder for now (they move here in a later change): the AI prompts
(`app/ai/prompts.py`), which rows are sent to the AI (`app/ai/context.py`), citation checking
(`app/ai/citations.py`), evaluation cases (`evals/cases/`) and captured output
(`tests/fixtures/`). Search for `TODO(forensics)` to find everything left to review.

## Add a plugin

1. Find the exact name and options on the volatility version the tool uses:

   ```bash
   docker compose run --rm app vol -h                         # all plugin names
   docker compose run --rm app vol windows.dlllist.DllList -h # that plugin's options
   ```

   Never guess names, options or output columns, and don't trust an AI assistant's memory of
   them: they often mix up volatility 2 and 3.

2. Copy `plugins/_template.py` into the folder for the plugin's OS. Name the file after the
   plugin without its class name, with dots turned into underscores:

   | Plugin | File |
   |---|---|
   | `windows.pslist.PsList` | `plugins/windows/pslist.py` |
   | `windows.malware.malfind.Malfind` | `plugins/windows/malware_malfind.py` |

3. Fill in the fields you need and delete the rest. Only `name` is required. The template
   explains each field; the table below is a summary.

4. Check your work:

   ```bash
   python -m app.tools.guide                   # prints the guide and lists any problems
   pytest tests/test_forensics_content.py      # the same checks CI runs on this folder
   ```

5. Start the app and look at the run form, the `/guide` page and the System page. A file with a
   mistake is skipped (the other plugins keep working) and the error is shown on the System page.

A short example (`plugins/windows/cmdline.py`):

```python
"""windows.cmdline.CmdLine: the command line of each process.

Checked against volatility3 2.28.2: --pid is a list of numbers.
"""

from forensics.common import PID_FILTER
from forensics.sdk import Baseline, Plugin

PLUGIN = Plugin(
    name="windows.cmdline.CmdLine",
    description="Show the command line used to start each process.",
    args=[PID_FILTER],
    baseline=Baseline(30, "How each process was started (paths, arguments)."),
)
```

## Plugin fields

| Field | What it does |
|---|---|
| `name` | Full name exactly as `vol -h` shows it. Short names can run the wrong plugin. |
| `description` | One line shown on the run form. |
| `args` | The options analysts may use. Anything not listed can never be passed to volatility. |
| `presets` | One-click queries on the run form: `Preset("PID 4 (System)", pid=[4])`. |
| `auto_enumerate` | `True` runs the plugin automatically on every new image. Use it only for identifying the image (OS, kernel). |
| `timeout_seconds` | Stop the run after this long. Default: 1 hour. Slow scans on big images may need more. |
| `writes_files` | `True` if the plugin always writes files, whatever the options. |
| `compare_keys` | For the comparison page: the columns that identify "the same" row in two images. Never PIDs or memory offsets, they change between captures. |
| `compare_ignore` | Extra columns that shouldn't count as a change on the comparison page. |
| `baseline` | Put the plugin in the standard first pass: `Baseline(10, "why")`. Lower numbers come first. |
| `next` | Suggestions shown after this plugin ran: `Next("windows.pstree.PsTree", "why", ...)`. |

Each option in `args` is an `Arg`:

```python
Arg(name="dump", flag="--dump", type="bool", help="Extract to files", writes_files=True)
```

- `name`: the key used on the form and in presets (snake_case).
- `flag`: the option exactly as `vol <plugin> -h` shows it. Only `--long-form` flags.
- `type`: `"int"` (`--flag 5`), `"int_list"` (`--flag 1 2 3`), `"bool"` (`--flag` when ticked)
  or `"str"` (`--flag text`).
- `required=True` only if volatility itself requires the option.
- `writes_files=True` for any option that makes volatility write files (like `--dump`). Written
  files can be large and may be live malware; they are hashed and offered as an encrypted zip.

Options used by several plugins go in `common.py`, for example `PID_FILTER`.

## Investigation guide ("Recommended next")

The "Recommended next" panel on an image page comes from the `baseline` and `next` fields of
the plugin files. No AI is involved.

- **Baseline**: the standard first pass after the image is identified, shown in order of the
  numbers you give. Leave gaps (10, 20, 30) so a plugin can be slotted in later. "Run remaining
  baseline" queues all of them.
- **Next**: written in the file of the plugin that ran first. `next` in `pslist.py` means "after
  pslist ran, suggest these". Options:
  - `when="succeeded"` (default): the run succeeded.
  - `when="has_rows"`: ... and returned at least one row.
  - `when="has_flags"`: ... and a hook flagged at least one row.
  - `when="tag:suspicious-parent"`: ... and a hook flagged a row with that tag.
  - `priority=20`: higher numbers are shown first.
  - `args={"pid": [4]}`: run with these options.

A suggestion disappears once that plugin with those options has run (or is queued) on the image.
Analysts can also dismiss it. Write each reason as one short sentence for a junior analyst.

The guide can't use values from the output ("dlllist for the flagged PID") or depend on two
plugins at once. For that, write a hook that queues the follow-up run.

Everything in the guide is checked against the plugins' options, so a typo is reported
by `python -m app.tools.guide`, on the `/guide` page and in CI. The report names the file.

## Hooks

A hook is a small Python function that runs after a plugin run succeeds. It reads the rows and
adds meaning on top: it can flag rows, write a short finding, record facts about the image, or
queue another run. It never changes the raw output.

Put a hook for one plugin in that plugin's file:

```python
@PLUGIN.post_run(version="1")
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

(Check column names against real output, not memory.) A hook that reads several plugins goes
in `hooks/` and names its plugins: `@post_run("windows.pslist.PsList", "windows.psscan.PsScan")`.

What a hook can do with `ctx`:

| Call | Result |
|---|---|
| `ctx.rows()` | The run's rows, one by one: `row.row_idx`, `row.data` (column → value), `row.depth`, `row.parent_idx`. |
| `ctx.rows(run_id)` | Rows of another run on the same image. |
| `ctx.latest_run("windows.psscan.PsScan")` | The latest successful run of another plugin on this image, or `None`. |
| `ctx.artifacts()` | Files the run wrote (name, size, hashes, which row names them). |
| `ctx.annotate(row_idx, tag, severity, note)` | Flags a row: badge in the table, filterable by tag, sent to the AI with the row. |
| `ctx.add_finding(title, detail, severity, rows)` | A finding on the run page, with links to the rows; also sent to the AI. |
| `ctx.update_evidence_metadata(**facts)` | Adds facts to the image's OS info. |
| `ctx.queue_follow_up(plugin, args, reason)` | Queues another run, linked to this one. |

Severities are `info`, `low`, `medium` and `high`.

Rules:

- A hook either completes fully or changes nothing. If it raises an error, the error is shown on
  the run page and the run itself stays successful.
- "Re-run post-processing" on the run page runs your hooks again on existing output. Use it while
  developing; there's no need to re-run volatility.
- Follow-up runs are limited (chain depth 2, 10 per run by default) and skipped if the same run
  already exists.
- Keep hooks fast (seconds). No network calls, no writing files.
- Raise `version` when you change a hook's logic; it is recorded with every result.

To test a hook without volatility, insert a run with rows from captured output and call
`hooks.run_hooks(session, run_id)`. `tests/test_hooks.py::test_example_windows_info_hook` shows
the pattern.

## What the checks look for

`pytest tests/test_forensics_content.py` (also run in CI) fails if:

- a plugin file has an error or no `PLUGIN = Plugin(...)`,
- two files define the same plugin,
- a plugin's options are invalid (bad flag, a flag that writes files without `writes_files=True`),
- a guide step points at a missing plugin or uses options the plugin doesn't have,
- a hook file has an error,
- a file isn't named after its plugin, or sits outside an OS folder,
- `_template.py` stops being a working example.

The infrastructure tests use their own copy of a few plugins (`tests/content/`), so changing
your files never breaks them.
