> Written mainly for AI coding assistants. People: start with README.md or forensics/README.md.

# Instructions for AI coding assistants

Single-user PoC: FastAPI + Jinja/HTMX UI, in-process worker running the volatility3 CLI, SQLite,
external OpenAI-compatible AI. Read in this order: this file, `CONTRACTS.md` (module contracts),
then `docs/design/*.md` for the area you touch (architecture, multi-evidence, ai-investigation,
operations). Open work: `TODO.md`.

## Ownership (who changes what)

- **Forensics content (human team):** `forensics/` (one file per plugin in
  `forensics/plugins/<os>/`: catalog entry, presets, compare keys, guide `baseline`/`next`,
  hooks; shared bits in `forensics/common.py`). Still outside it (moving there later): prompts
  `app/ai/prompts.py`, AI row selection in `app/ai/context.py`, citation tuning in
  `app/ai/citations.py`, eval cases `evals/cases/`, real fixtures in `tests/fixtures/`. Marked
  `TODO(forensics)` / `EXAMPLE`.
- `forensics/sdk.py` and the loader `app/tools/content.py` are infrastructure (keep the names
  the team imports stable). Infrastructure tests must not depend on `forensics/`: use
  `tests/content/` (see CONTRACTS.md "Tool runner").
- **Infrastructure (AI-maintained, human-reviewed):** everything else in `app/`, `evals/*.py`,
  `scripts/`, `tests/`.
- Don't fill in forensics content on your own initiative. Never invent volatility3 plugin names,
  flags or output columns: they must come from `vol -h`, `vol <plugin> -h` on the pinned version,
  or real captured output. Models often produce volatility2 syntax (`--profile`, no `windows.`
  prefix).

## Frozen files (change only with team agreement)

`app/config.py`, `app/db.py`, `app/models.py`, `app/tools/base.py`, `tests/conftest.py`,
`pyproject.toml` dependencies, and applied migrations in `app/migrations/versions/`.

## Code conventions

- Every data change goes through `audit.record` in the same transaction; key reads use
  `category=audit.KEY_READ`.
- Schema change = new Alembic migration `app/migrations/versions/00NN_*.py` (down_revision =
  previous) in the same PR; `tests/test_migrations.py` checks models match migrations. New
  `RunOrigin` values need no migration (names <= 12 chars).
- Jinja: never build HTML attributes as strings (autoescape); don't name dict keys
  `keys`/`items` in templates; write `&amp;` for a literal `&` in hrefs.
- Subprocesses: argv lists only, never a shell. All plugin args (manual, preset, guide, AI, agent,
  hook follow-ups) pass the same allowlist validation.
- Don't weaken safety mechanisms (allowlist, read-only evidence, path-traversal checks, citation
  validation). If a test fails, fix the code, not the test.
- Export golden file: regenerate with `UPDATE_GOLDEN=1 pytest tests/test_export.py` only for
  intentional format changes.

## Tests (must pass on Windows too)

- No symlinks without a skip, no `os.kill(pid, 0)`, close DB connections before moving files,
  `.py` vol stand-ins run via `vol_command`.
- While working run only affected files (`pytest -q tests/test_x.py --tb=line`); run the full
  suite once at the end, plus `ruff check .` and `ruff format --check .`.
- Prefer assertions over screenshots for UI changes.

## Working efficiently

- Batch independent shell checks into one command; keep output quiet (`-q`, `| tail`, `--stat`).
- `grep -n` first, then read only the needed line range. Don't print large files (`pages.py`,
  `export.py`, templates, big tests) whole; exclude `app/web/static` (minified htmx) from greps.
- Change files with small targeted edits, not full rewrites.
- volatility3 plugin options can be checked offline: `pip download volatility3==<pinned> --no-deps`
  and read the plugin's `get_requirements`.
- Docker may not be available in sandboxed environments; say so when Dockerfile changes are
  untested.

## Documentation

- Human docs, plain language, no AI phrasing: README.md, docs/DEVELOPMENT.md, TODO.md,
  evidence/README.md, evals/README.md, forensics/README.md.
- AI docs, dense, start with the one-line "Written mainly for AI coding assistants" note:
  this file, CONTRACTS.md, docs/design/*, READMEs under app/, tests/fixtures/README.md.
- Code comments in forensics content are written for humans; elsewhere they can be terse.
- When behaviour changes, update CONTRACTS.md and the matching design doc in the same PR.
