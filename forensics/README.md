# Forensics content: start here

This folder holds everything the forensics team owns: which volatility3 plugins the tool may
run, with which options, what it recommends running next, the hooks that flag interesting rows,
what the AI is told, and the material used to test the AI. The rest of the repository (the web app, the job runner, the AI plumbing) is the
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
  prompts/             what the AI is told (plain text)
  citations.py         which values in AI answers are checked against the cited rows
  fixtures/            real volatility output, one file per plugin
  evals/cases/         test cases for the AI; evals/baselines/ holds saved scores
```

Search for `TODO(forensics)` to find everything left to review. Output parsing is shared by all
plugins (`app/tools/volatility/runner.py`); hooks are the place to interpret a plugin's rows.

## Add a plugin

1. Find the exact name and options on the volatility version the tool uses:

   ```bash
   docker compose run --rm app vol -h                         # all plugin names
   docker compose run --rm app vol windows.dlllist.DllList -h # that plugin's options
   ```

   Never guess names, options or output columns, and don't trust an AI assistant's memory of
   them: they often mix up volatility 2 and 3.

2. Create the file:

   ```bash
   python -m forensics new windows.dlllist.DllList
   ```

   This writes `plugins/windows/dlllist.py` with the plugin's real options from `vol -h` pasted
   in as notes to copy from (when volatility is installed where you run it; inside Docker use
   `docker compose run --rm app python -m forensics new ...`). You can also copy
   `plugins/_template.py` by hand. Files are named after the plugin without its class name,
   with dots turned into underscores:

   | Plugin | File |
   |---|---|
   | `windows.pslist.PsList` | `plugins/windows/pslist.py` |
   | `windows.malware.malfind.Malfind` | `plugins/windows/malware_malfind.py` |

3. Fill in the fields you need. Only `name` is required. `plugins/_template.py` explains every
   field; the table below is a summary.

4. Check your work:

   ```bash
   python -m forensics check                   # every check on this folder, plus a to-do list
   pytest tests/test_forensics_content.py      # the same checks as tests (CI runs both)
   ```

5. Start the app and look at the run form and the **Content** page (`/content`, in the top bar).
   It shows every plugin with its status (error, example, reviewed), options, guide steps,
   hooks, captured output and evaluation cases, plus what is still to do. A file with a mistake
   is skipped (the other plugins keep working) and the error is shown there and on the System
   page.

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
| `ai_context` | Which rows the AI sees: `AIContext(max_rows=100, columns=["PID", "ImageFileName"])`. See "What the AI sees". |

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
by `python -m forensics check`, on the `/guide` and `/content` pages and in CI. The report names the file.

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

## What the AI sees

When an analyst asks the AI a question, the app sends the image's details, its notes and rows from
its runs. By default that is the first 50 rows of each run (200 for "Summarize this run"), plus
every row a hook flagged. Per plugin you can change it:

- `ai_context=AIContext(max_rows=100)`: send more or fewer rows.
- `ai_context=AIContext(columns=["PID", "ImageFileName"])`: only send these columns. Shorter rows
  mean more rows fit, but the AI can't mention what it doesn't see.
- A function named `select_ai_rows` in the plugin file picks the rows itself. It gets every row
  in order and returns the `row_idx` of the rows to send, most important first:

  ```python
  def select_ai_rows(rows):
      for row in rows:
          if row.data.get("Protection") == "PAGE_EXECUTE_READWRITE":
              yield row.row_idx
  ```

  If it raises an error, the AI gets the first rows instead and the context says so.

## Prompts

The files in `prompts/` are the instructions the AI gets. Write them as plain text to the AI:

| File | Used for |
|---|---|
| `analysis.md` | Every analysis answer (questions in the AI panel, run summaries). |
| `run_summary.md` | The "Summarize this run" question. `{run_id}` and `{plugin}` are filled in. |
| `recommend_next.md` | The "What should I run next?" question. |
| `agent.md` | The goal-driven agent ("Give the AI a goal"). |

A comment at the top (`<!-- ... -->`) is for people and isn't sent. The app adds its own fixed
rules after your text: cite rows as `[R12:34]`, use only the given data, the suggestions block
that becomes Run buttons, and the agent's tool rules. Don't repeat or change those in your text;
if they get in the way, ask the infrastructure side.

Every AI answer records a prompt version (like `p-3fa9c2d1`). It changes by itself whenever a
prompt file changes, so you can tell which prompt produced which answer or score.

To see whether a prompt change helps, run the evaluation before and after (next section).

## Testing the AI (evaluation cases)

`evals/cases/` holds test cases: a small investigation built from captured output, a question,
and what a good answer must contain (rows to cite, words to mention or avoid). Run them with:

```bash
python -m evals.run                     # all cases, 3 tries each
python -m evals.run --save-baseline     # save the scores in evals/baselines/ (commit the file)
python -m evals.run --fail-on-regression
```

The `*_example.yaml` cases use synthetic output and only show the format. The full guide is
[evals/README.md](../evals/README.md).

## Captured output (fixtures)

`fixtures/` holds real volatility output, one file per plugin, named like the plugin file
(`fixtures/windows/pslist.jsonl` for `plugins/windows/pslist.py`). Evaluation cases load these
files, and the checks make sure every column named in `compare_keys` or `ai_context` really
appears in the output. How to capture one: `fixtures/README.md`.

## Citation checks

When the AI writes "explorer.exe (PID 2000) [R12:3]", the app checks that `explorer.exe` and
`2000` really appear in row R12:3, and marks the citation "unsupported" if not. `citations.py`
decides which values are checked: file extensions, the words that mark a number as a PID or
port, and how long Windows process names can be before they are cut off.

## Checklist before the first real case

The **Content** page and `python -m forensics check` show the live status of each item.

- [ ] **Plugins:** review each plugin's options, description and `timeout_seconds` (big scans
      may need more than the 1-hour default). Decide which plugins may write files.
- [ ] **Presets:** add one-click queries where they help.
- [ ] **Auto-enumerate:** choose the plugins that run automatically on every new image.
- [ ] **Investigation guide:** replace the EXAMPLE `baseline` and `next` steps with the team's
      workflow.
- [ ] **Hooks:** review the EXAMPLE OS-detection hook in `plugins/windows/info.py`, then add
      hooks that flag suspicious rows, summarise runs and queue sensible follow-ups.
- [ ] **Comparison keys:** set `compare_keys` (and `compare_ignore`) for each plugin.
- [ ] **Captured output:** capture real output for every plugin into `fixtures/` and replace
      the two synthetic files. Check that the shared parser reads each one correctly.
- [ ] **What the AI sees:** set `ai_context` (or `select_ai_rows`) for plugins with large output.
- [ ] **Prompts:** replace the four EXAMPLE files in `prompts/`.
- [ ] **Citation settings:** review `citations.py` against real answers.
- [ ] **Evaluation cases:** replace the EXAMPLE cases with ones built from real output, then save
      a baseline for each model you use.

## Tools

| Command / page | What it does |
|---|---|
| `python -m forensics new <plugin>` | Creates a plugin file, with the real options from `vol -h`. |
| `python -m forensics check` | Runs every check below and lists what is still EXAMPLE or missing. Exit code 1 on errors. |
| `python -m forensics guide` | Prints the investigation guide as a Markdown table. |
| `/content` page | The same report in the app, per plugin. |
| `/guide` page | The investigation guide as analysts see it. |

On GitHub, the "forensics-content" check runs `python -m forensics check` and the content tests
on every pull request, separately from the infrastructure tests.

## What the checks look for

`python -m forensics check` and `pytest tests/test_forensics_content.py` fail if:

- a plugin file has an error or no `PLUGIN = Plugin(...)`,
- two files define the same plugin,
- a plugin's options are invalid (bad flag, a flag that writes files without `writes_files=True`),
- a guide step points at a missing plugin or uses options the plugin doesn't have,
- a hook file has an error,
- a file isn't named after its plugin, or sits outside an OS folder,
- `_template.py` stops being a working example,
- a prompt file is missing or empty, or `run_summary.md` lost `{run_id}` / `{plugin}`,
- `citations.py` has invalid settings,
- a fixture doesn't parse, has no plugin file, or lacks a column named in `compare_keys`,
  `compare_ignore` or `ai_context`,
- the evaluation cases don't load.

The infrastructure tests use their own copy of a few plugins (`tests/content/`), so changing
your files never breaks them.
