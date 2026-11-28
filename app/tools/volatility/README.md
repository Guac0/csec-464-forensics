# volatility3 runner - hand-off notes for the forensics team

The scaffold provides the **mechanism** for running volatility3 safely. The **forensic content**
(which plugins, which options, presets, interpretation) is yours. Search the code for
`TODO(forensics)`.

## How it works

1. A request is `ToolRequest(plugin, args)` from the UI, a preset, auto-enumeration or a
   validated AI suggestion.
2. `VolatilityRunner.validate()` (`runner.py`) accepts only plugins in `plugins.PLUGINS` and only
   args declared in that plugin's `ArgSpec`s, coercing values by type
   (`int`, `int_list`, `bool`, `str`; strings may not start with `-`, contain newlines/NUL or
   exceed 1024 chars).
3. `build_argv()` produces a fixed argv (no shell):

   ```
   vol -q -r jsonl -s <symbols_dir> --cache-path <data_dir>/vol_cache -o <run_dir>/output \
       -f <evidence> <plugin> [plugin flags from ArgSpecs]
   ```

   Global flags (incl. `-p/--plugin-dirs`) can never come from user input; an ArgSpec whose flag
   collides with a global vol option is rejected. Verified against volatility3 2.28.2.
4. `app/tools/executor.py` runs it in its own process group, streams stdout to
   `<data_dir>/runs/<run_id>/stdout.jsonl` and stderr to `stderr.txt`, heartbeats, and kills the
   group on timeout/cancel. stdout is SHA-256 hashed; the vol version is recorded.
5. `parse_output()` flattens vol's jsonl (one object per root node, nested `__children`)
   depth-first into rows with `depth` / `parent_idx`. The raw stdout is kept on disk as the
   source of truth.

## What you need to fill in

- **Plugin catalog** - `plugins.py` includes Windows system details, process lists and trees,
  process scans, command lines, DLLs, handles, possible code injection (Malfind), network
  endpoints, services, and file objects.
  CmdLine, DllList, Handles, and Malfind accept a list of PIDs. These entries are available for
  on-demand runs. Use the full plugin name from `vol -h` (vol does substring matching and errors on ambiguity) when extending the catalog. Instructions are in the module docstring.
- **Presets** - `PluginSpec.presets`: `(label, args)` one-click queries.
- **Auto-enumeration set** - `PluginSpec.auto_enumerate=True` on the plugins to queue for each
  new evidence item. Keep it to *identification* (OS, kernel); deeper work is the guide's job.
- **Investigation guide** - `guide.py`: the baseline steps and "after X, suggest Y" relationships
  behind the "Recommended next" panel. See [Investigation guide](#investigation-guide) below.
- **Post-run hooks** - plugin-specific post-processing (OS detection, flagging rows, run
  findings, follow-up runs) goes in `hooks/`. See [hooks/README.md](hooks/README.md). An EXAMPLE
  hook (`hooks/windows_info.py`) fills `Evidence.os_info` from `windows.info.Info`; review its keys.
- **Per-plugin parsing** - the generic parser keeps vol's column names and values
  (absent values -> `null`, datetimes -> ISO strings, bytes -> hex strings). Interpretation
  (flags, summaries) belongs in hooks; only fix the raw parse if a plugin's output is mis-read.
- **Symbols / offline** - Windows symbols are downloaded from Microsoft's symbol server and the
  generated ISF is written to `FT_SYMBOLS_DIR` (first writable symbol dir). For air-gapped use,
  pre-populate that dir and run with `--offline` (`VolatilityRunner(offline=True)`; a settings
  switch `FT_VOL_OFFLINE` still needs to be added to `app/config.py`). Linux/macOS images need
  matching ISF files placed in `FT_SYMBOLS_DIR/linux|mac/`.

## Investigation guide

`guide.py` decides what the "Recommended next" panel on an image page suggests. It is plain data
(two lists of `Step(...)`), validated against the catalog, with no AI involved. The full field
reference is the docstring at the top of `guide.py`; the read-only page `/guide` shows the
current guide and its problems.

- `BASELINE`: the standard first pass of a deeper investigation, in order. Each step is shown
  until it has run (or is queued) on the image. "Run remaining baseline" queues them all.
- `NEXT`: `{"<plugin that ran>": [Step(...), ...]}`. Shown after that plugin succeeded on the
  image, optionally only when its output matched a condition (`when="has_rows"`,
  `"has_flags"`, `"tag:<hook tag>"`). Ranked by `priority`, then by how many runs suggest it.

### Worked example: add `windows.dlllist.DllList`

Goal: suggest the DLL list when a hook flagged processes in a pslist run, and suggest the
command lines after a DLL list.

1. Add the plugin to `plugins.py` (check `vol windows.dlllist.DllList --help` for options):

   ```python
   (
       PluginSpec(
           name="windows.dlllist.DllList",
           description="DLLs loaded by each process.",
           args=(ArgSpec(name="pid", flag="--pid", type="int_list", help="Only these process IDs"),),
       ),
   )
   ```

2. Add the relationships to `NEXT` in `guide.py`:

   ```python
   "windows.pslist.PsList": [
       ...,  # existing steps
       Step(
           "windows.dlllist.DllList",
           "A hook flagged processes: check them for injected or odd DLLs.",
           when="has_flags",
           priority=30,  # higher = shown above the other pslist follow-ups
       ),
   ],
   "windows.dlllist.DllList": [  # follow-ups of the new plugin itself
       Step("windows.cmdline.CmdLine", "Compare DLL paths with how the process was started."),
   ],
   ```

   The same plugin + args may appear only once per list (a duplicate is reported).

3. Check it: `python -m app.tools.volatility.guide` (prints the guide as Markdown; exit code 1
   and a "Problems" list if a step is invalid). `pytest tests/test_guide.py` runs the same check
   (`test_shipped_guide_is_valid`), so CI fails on a broken step.

4. Look at it in the app: open `/guide`, then an image page: after a pslist run succeeds, the
   new step appears under "Recommended next".

### Testing a guide rule

Rules are data, so a test is usually only worth it for conditions (`has_flags`, `tag:`). Copy
this into `tests/test_guide.py` and adapt (fixtures `session` and `ev` are defined there):

```python
def test_dlllist_after_flagged_pslist(session, ev):
    run = _run(session, ev, "windows.pslist.PsList", row_count=1)
    session.add(
        ResultRow(
            run_id=run.id,
            row_idx=0,
            data={"PID": 4},
            annotations=[{"hook": "x", "tag": "odd", "severity": "high"}],
        )
    )
    session.commit()
    items = recs.recommend(session, ev.id).items
    assert ("windows.dlllist.DllList", {}) in [(i.plugin, i.args) for i in items]
```

### What the guide cannot do (yet)

- Use values from the output as args ("dlllist for the flagged PID"): write a post-run hook
  (`hooks/README.md`) that queues a follow-up with computed args.
- Depend on several plugins at once ("after pslist AND netscan"): each NEXT entry has one source.

## Adding a fixture from real output

1. On a non-sensitive test image run:
   `vol -q -r jsonl -f image.raw windows.pslist.PsList > tests/fixtures/real_windows_pslist.jsonl`
2. Record the vol version and image source in `tests/fixtures/README.md`.
3. Add a test in `tests/test_tools_volatility.py` parsing it with `VolatilityRunner().parse_output`
   and asserting row count / key columns / tree shape.
   `tests/fixtures/sample_pstree.jsonl` is SYNTHETIC and only mirrors the format.

## Adding another tool later

1. Implement `app.tools.base.ToolRunner` (`plugins`, `validate`, `build_argv`, `version`,
   `parse_output`) in `app/tools/<tool>/runner.py`. Keep it stateless (read settings at call time).
2. Register a factory in `_FACTORIES` in `app/tools/registry.py`.
3. The executor is tool-agnostic: it only needs `build_argv`, `version` and an executable that
   writes results to stdout.

## Operational notes

- `vol` creates `~/.cache/volatility3` at import time regardless of `--cache-path`, so the
  container user needs a writable `$HOME` (or `XDG_CACHE_HOME`).
- Exit code is non-zero on errors such as unsatisfied requirements (wrong OS / missing symbols);
  the worker stores the stderr tail as the run error.
