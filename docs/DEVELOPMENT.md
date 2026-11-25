# Development guide

## Branch and PR workflow

- `main` is always deployable: it builds, tests pass, `docker compose up` works.
- Work on short-lived branches (`feat/run-search`, `fix/worker-cancel`, `forensics/pslist-parser`),
  open a PR early (draft is fine), keep PRs small (one concern, < ~400 changed lines).
- Every PR needs **1 approving review** and green CI (`lint`, `test`, `docker`). Forensics-owned
  paths (see `.github/CODEOWNERS`) need a review from a forensics owner.
- Squash-merge; write the PR title as the commit message ("Add pslist parser").
- Run `pre-commit run --all-files` and `pytest -q` before pushing; CI runs the same.
- Frozen contract files (listed in `CONTRACTS.md`, incl. `pyproject.toml` dependencies) change
  only after the team agrees, in a dedicated PR.

### Protect `main`

**In the GitHub UI:** Settings > Rules > Rulesets > New branch ruleset

1. Name `protect-main`, Enforcement status **Active**, Target branches: **Include default branch**.
2. Enable **Restrict deletions** and **Block force pushes**.
3. Enable **Require a pull request before merging**: required approvals `1`, dismiss stale
   approvals on new commits, (optional) require review from Code Owners - only after the
   placeholder handles in `.github/CODEOWNERS` are replaced with real usernames.
4. Enable **Require status checks to pass**, add `lint`, `test`, `docker` (they appear in the
   picker after CI ran once), and enable "Require branches to be up to date".
5. Save. (Classic alternative: Settings > Branches > Add branch protection rule for `main`.)

**With the GitHub CLI** (repo admin; replace `Guac0/csec-464-forensics`):

```bash
gh api --method POST repos/Guac0/csec-464-forensics/rulesets --input - <<'EOF'
{
  "name": "protect-main",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_review_thread_resolution": false
      } },
    { "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "required_status_checks": [
          { "context": "lint" }, { "context": "test" }, { "context": "docker" }
        ]
      } }
  ]
}
EOF
```

Rulesets on private repos need a paid plan (or GitHub Education/Team); on a free private repo,
make the repo public or agree on the rules socially.

## Working with AI assistants

AI coding assistants are allowed and encouraged, with these rules:

1. **Give it `CONTRACTS.md` first** (and the module you are working on). Ask it to stay inside your
   module's public interface. It must not change frozen files (`app/config.py`, `app/db.py`,
   `app/models.py`, `app/tools/base.py`, `tests/conftest.py`, `pyproject.toml` deps) - if it
   wants to, that is a team discussion.
2. **Never let it invent volatility3 plugins, flags or output columns.** Assistants confidently
   produce plugin names and options from volatility 2 or from nowhere. Every plugin/flag in
   `app/tools/volatility/plugins.py` must be checked against the installed version:

   ```bash
   docker compose run --rm app vol -h                       # global options, plugin list
   docker compose run --rm app vol windows.pslist.PsList -h # plugin options
   ```

   Column names come from real output (see fixtures below), not from the assistant.
3. **Don't weaken the safety mechanisms**: the argument allowlist, no-shell subprocess execution,
   the read-only evidence mount, path-traversal checks, citation validation. If a test fails,
   fix the code, not the test.
4. **Review everything it writes** as if a classmate wrote it; you are the author of the PR. Say in
   the PR which parts were AI-generated.
5. Don't paste real case data, API keys or `.env` content into an assistant.

## Performance check for big runs

`python -m scripts.bench_rows --rows 200000` (add `--search-index` to compare) builds a throwaway
database with a synthetic filescan-sized run through the real parser and ingest code, and times
paging, search, filters, sorting and CSV export. Run it before and after changes to row storage
or querying.

## Audit log

Everything that changes data must be recorded in the audit log, in the **same transaction** as
the change (so both are saved or neither is):

```python
from app.services import audit

note.body = new_body
audit.record(
    session,
    "note.edit",  # <object>.<verb>
    object_type="note",
    object_id=note.id,
    evidence_id=note.evidence_id,
    summary=f"Edited note {note.id}",  # human readable, shown in the Activity page
    details={"version": 3},  # JSON; anything useful to reconstruct what happened
)
session.commit()
```

- Who/where (`actor`, `origin`, `request_id`) is filled in automatically from the request or
  worker context.
- Use `category=audit.KEY_READ` for sensitive reads (exports, downloads). Ordinary reads need
  nothing: at `FT_AUDIT_LEVEL=all` the middleware logs every request.
- The log can't be edited or deleted (DB triggers) and is hash-chained; "Verify integrity" on
  the Activity page (or `GET /api/audit/verify`) recomputes the chain.
- `FT_AUDIT_LEVEL=all` is a temporary PoC default (very verbose). The intended setting is
  `key_reads`; switching is a one-line change of the default in `app/config.py`.
- New actions should get a line in `tests/test_audit.py::test_every_state_change_is_audited`.

## Database migrations

The schema is managed with [Alembic](https://alembic.sqlalchemy.org/). The app runs
`app.db.migrate()` at startup, which upgrades the database to the latest migration, so users
never lose their data when they pull a new version. (Databases created before Alembic was added
are detected and adopted automatically.)

**Any change to `app/models.py` must ship with a migration in the same PR:**

```bash
pip install -e ".[dev]"
mkdir -p data
FT_DATA_DIR=./data alembic upgrade head                        # bring your dev DB up to date
FT_DATA_DIR=./data alembic revision --autogenerate -m "add run hook results"
```

Then **review the generated file** in `app/migrations/versions/` (autogenerate is a draft, not
the truth):

- New columns on existing tables should be nullable or have a `server_default`, or existing rows
  will break the migration.
- SQLite can't alter columns in place; the generated `batch_alter_table` blocks rebuild the table
  for you. Keep them.
- Renames are detected as drop + add (data loss). Edit them into `alter_column(new_column_name=...)`.
- Fill in `downgrade()` and check it works: `alembic downgrade -1 && alembic upgrade head`.
- Data migrations (backfilling values) go in the same file using `op.execute(...)`.

Rules:

- **Never edit a migration that has been merged to `main`**; add a new one instead.
- **One head only.** If two PRs both add a migration on the same parent, CI fails
  (`tests/test_migrations.py::test_single_head`). Whoever merges second rebases and changes their
  migration's `down_revision` to the other migration's revision id.
- CI also fails if the models and the migrations disagree (`test_migrations_match_models`),
  i.e. someone changed `app/models.py` without generating a migration.
- Resetting a local DB is still fine for experiments: `docker compose down -v`.

## Fixtures: adding real volatility3 output

Unit tests never run real volatility: they use `tests/fixtures/fake_vol.py` and recorded
outputs. To add a real recording:

1. Use a **public, non-sensitive** Windows memory sample (e.g. from a published CTF/training
   dataset). Note where it came from and its SHA-256.
2. Capture the output with the same renderer the app uses:

   ```bash
   docker compose run --rm app vol -q -r jsonl -s /symbols -f /evidence/<image> windows.pslist.PsList \
     > tests/fixtures/real_windows_pslist.jsonl
   ```

   No local Docker/RAM to spare? Run the **Integration** workflow (Actions tab >
   "Integration (real memory sample)" > Run workflow) with the sample URL, its SHA-256 and the
   plugin, then download the `vol-...` artifact.
3. Trim it to a few dozen rows (keep the structure: leading blank line, one JSON object per root,
   nested `__children`). Keep it well under 1 MB (pre-commit rejects larger files).
4. Record provenance next to it in `tests/fixtures/README.md`: image name + SHA-256, plugin,
   volatility3 version (`vol -h | head -1`), date.
5. Add parser/summary tests against it. Fixture changes are reviewed by the forensics owners.

Never commit memory images or dumps; `.gitignore` and a pre-commit hook block the common
extensions, but check `git status` anyway.

## Useful commands

```bash
docker compose up --build             # run the app at http://127.0.0.1:8000
docker compose run --rm app vol -h    # run vol inside the image
docker compose exec app sh            # shell in the running container
docker compose down -v                # wipe DB, run outputs and symbol cache
FT_DATA_DIR=./data alembic current    # which migration a local dev DB is at
pre-commit autoupdate                 # bump hook versions (separate PR)
```
