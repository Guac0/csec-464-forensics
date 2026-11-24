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

- **Plugin catalog** - `plugins.py`. Currently only two EXAMPLE entries
  (`windows.info.Info`, `windows.pslist.PsList --pid`). Use the full plugin name from `vol -h`
  (vol does substring matching and errors on ambiguity). Instructions are in the module docstring.
- **Presets** - `PluginSpec.presets`: `(label, args)` one-click queries.
- **Auto-enumeration set** - `PluginSpec.auto_enumerate=True` on the plugins to queue for each
  new evidence item.
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
