> Written mainly for AI coding assistants. People: start with README.md or forensics/README.md.

# volatility3 runner (mechanism)

Forensic content (catalog, guide, hooks) is in `forensics/` (human docs: forensics/README.md),
loaded by `app/tools/content.py`. This folder is only the mechanism.

## Request flow

1. `ToolRequest(plugin, args)` from UI, preset, auto-enumeration, guide, validated AI suggestion,
   agent request or hook follow-up.
2. `VolatilityRunner.validate()` (`runner.py`): plugin must be in `content.current().plugins`
   and valid (`catalog_problems`); args only those declared in its ArgSpecs, coerced by type
   (`int`, `int_list`, `bool`, `str`; strings may not start with `-`, contain newlines/NUL or
   exceed 1024 chars).
3. `build_argv()` (no shell; paths resolved to absolute):

   ```
   vol -q -r jsonl -s <symbols_dir> --cache-path <data_dir>/vol_cache -o <run_dir>/output \
       -f <evidence> <plugin> [plugin flags in catalog order]
   ```

   Global flags (incl. `-p/--plugin-dirs`) never come from input; an ArgSpec flag colliding with
   a global vol option is rejected. Verified against volatility3 2.28.2. `vol_command()` runs a
   `.py` executable via the current interpreter (tests use `tests/fixtures/fake_vol.py`).
4. `app/tools/executor.py`: own process group, stdout -> `<data_dir>/runs/<id>/stdout.jsonl`,
   stderr -> `stderr.txt`, heartbeats, kills the group on timeout/cancel; stdout SHA-256 and vol
   version recorded.
5. `parse_output()` flattens vol jsonl (one object per root, nested `__children`) depth-first
   into rows with `depth` / `parent_idx`. Keeps vol column names; absent -> `null`, datetimes ->
   ISO strings, bytes -> hex. Raw stdout on disk is the source of truth. TODO(forensics):
   validate against real captured output per plugin.

## Catalog checks

`catalog_problems(plugins)`: full plugin names, flag syntax/clashes/duplicates, known
file-writing flags/plugins (`KNOWN_FILE_WRITING_FLAGS`, `KNOWN_FILE_WRITING_PLUGINS`) must be
declared `writes_files`. `VolatilityRunner.catalog_problems()` also includes content files that
failed to load (keyed by file path). Invalid entries are skipped, logged once, shown on the
System page.

## Symbols / offline

Windows symbols are downloaded from Microsoft on first use and the ISF written to
`FT_SYMBOLS_DIR`. `FT_VOL_OFFLINE=true` adds `--offline`; for air-gapped use pre-populate the
symbols dir. Linux/macOS images need ISF files in `FT_SYMBOLS_DIR/linux|mac/` (out of PoC scope).

## Adding another tool

1. Implement `app.tools.base.ToolRunner` (`plugins`, `validate`, `build_argv`, `version`,
   `parse_output`, optional `guide`, `catalog_problems`) in `app/tools/<tool>/runner.py`;
   stateless (read settings at call time).
2. Register a factory in `_FACTORIES` in `app/tools/registry.py`.
3. Content for it would need its own `Plugin`-like loader or a `tool` field on `Plugin`.

## Operational notes

- `vol` creates `~/.cache/volatility3` at import regardless of `--cache-path`: the container user
  needs a writable `$HOME` (or `XDG_CACHE_HOME`).
- Non-zero exit on unsatisfied requirements (wrong OS / missing symbols); the worker stores the
  stderr tail as the run error.
