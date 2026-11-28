# TODO

Checklist of what is left after the infrastructure scaffold. Tick items off as they are done.

## 1. Git and GitHub setup (repo owner)

### Before the first commit

- [X] **Replace placeholders:**
  - `.github/CODEOWNERS`: `@TEAM_MEMBER_DEFAULT`, `@TEAM_MEMBER_FORENSICS_1`,
    `@TEAM_MEMBER_FORENSICS_2` → real GitHub usernames.
  - `.github/ISSUE_TEMPLATE/config.yml`: `OWNER/REPO` → `Guac0/csec-464-forensics`.
- [X] **Set up pre-commit** (pins could not all be verified from the build sandbox):
  ```bash
  pip install -e ".[dev]"
  pre-commit autoupdate
  pre-commit install
  pre-commit run --all-files
  ```
- [X] **Check nothing sensitive is staged:** `git add -A && git status` — no `.env`, no memory
      images, no `data/`, `symbols/` or `__pycache__/`.
- [X] **First commit and push:** `git commit -m "Initial scaffold" && git push -u origin main`.

### On GitHub
- [ ] **Watch the first CI run.** The `docker` job is the first real build against the
      `python:3.12-slim` base image (the sandbox couldn't download it), so fix anything it finds.
- [ ] **Protect `main`** (Settings → Rules → Rulesets, or the `gh api` command in
      [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)):
  - require a pull request with 1 approval and Code Owner review,
  - require status checks `lint`, `test`, `docker`,
  - block force pushes and deletion.
- [X] **Actions settings:** leave default workflow permissions as read-only (the workflows request
      what they need).
- [X] **Security settings:** enable secret scanning + push protection and Dependabot alerts if your
      plan offers them (free on public repos).
- [X] **Dependabot: alerts only, no PRs.** Delete `.github/dependabot.yml` after unzipping (it
      only configures routine version-update PRs). In Settings → Code security, turn on
      *Dependency graph* and *Dependabot alerts*, and leave *Dependabot security updates* **off**
      (that setting is what opens security-fix PRs).
- [ ] **Optional:** create a Projects board, labels (`volatility`, `ai`, `ui`, `infra`) and a
      milestone for the demo date.
- [ ] **Integration workflow:** pick a small public Windows memory sample, record its URL and
      SHA-256, and run `integration.yml` manually once to check real volatility works in the image.
- [ ] **Releases (optional):** pushing a tag `v*` publishes the image to
      `ghcr.io/guac0/csec-464-forensics`; set the package visibility afterwards.

## 2. Forensics hand-off (human team)

Everything marked `TODO(forensics)` in the code. Find it with `git grep -n "TODO(forensics)"`;
the background is in [app/tools/volatility/README.md](app/tools/volatility/README.md).

- [ ] **Plugin catalog** — `app/tools/volatility/plugins.py`: replace the two EXAMPLE entries with
      the real allowlist of plugins and arguments.
- [ ] **Preset queries** — add `presets` to each plugin.
- [ ] **Investigation guide** — `app/tools/volatility/guide.py`: replace the EXAMPLE baseline and
      "after X, suggest Y" steps with the team's workflow (how-to: README.md in that folder,
      "Investigation guide"). Also review the EXAMPLE catalog entries added for it (pstree,
      cmdline, netscan).
- [ ] **Auto-enumerate set** — set `auto_enumerate=True` on the plugins that should run first.
- [ ] **Real output fixtures** — capture `vol -r jsonl` output for every catalog plugin into
      `tests/fixtures/` and replace the synthetic `sample_pstree.jsonl`.
- [ ] **Output parsing** — check `VolatilityRunner.parse_output` (`app/tools/volatility/runner.py`)
      against those fixtures; add per-plugin post-processing where needed.
- [ ] **Post-run hooks** — `app/tools/volatility/hooks/` (guide: `hooks/README.md`). Review the
      EXAMPLE `windows_info.py` OS-detection hook against real output, and add hooks that flag
      suspicious rows, summarise runs as findings, and queue sensible follow-up plugins.
- [ ] **AI prompts** — `app/ai/prompts.py`: the analysis system prompt, the run-summary question
      and the "what should I run next?" question (`RECOMMEND_QUESTION`), and the agent prompt
      (`AGENT_SYSTEM_PROMPT`).
      Bump `PROMPT_VERSION` with each change and compare with `python -m evals.run`.
- [ ] **Evaluation cases** — replace the two `evals/cases/*_example.yaml` (synthetic fixture) with
      cases built from real captured output, then save a baseline per model you use.
- [ ] **AI context** — `app/ai/context.py`: choose which rows of each plugin are worth sending.
- [ ] **Citation checking** — `app/ai/citations.py` now checks that typed values (IPs, paths,
      file names, hex, labelled PIDs/ports, quoted text) next to a citation appear in the cited
      row(s). Review it against real output: tune what is extracted and the volatility path
      forms it treats as equal; meaning-level checks (is the claim *true*?) are still manual.
- [ ] **Dependencies** — decide whether to depend on `volatility3[full]` (some Windows plugins need
      its extra libraries); this changes `pyproject.toml`.
- [ ] **README** — fill in the stubbed **Features** section.

## 3. Known infrastructure follow-ups

- [ ] **Audit level:** `FT_AUDIT_LEVEL` defaults to `all` (every page/API request) for the PoC.
      Switch the default in `app/config.py` to `key_reads` when evaluation is over.
- [ ] Audit log has no retention/archiving; at level `all` it grows with every request.
- [ ] Replace `.github/workflows/evals.yml` with the updated version (provided separately: provider
      check, agent tool mode, step summary, save-baseline artifact, optional self-hosted runner)
      and add the repo secrets `FT_AI_BASE_URL`, `FT_AI_API_KEY` + variables `FT_AI_MODEL`
      (optional `FT_AI_MAX_TOKENS`, `EVAL_RUNNER`). Check whether the RIT endpoint is reachable
      from GitHub-hosted runners; if not, use a self-hosted runner. Then save a first baseline.
- [ ] Large results: decide whether to enable `FT_SEARCH_INDEX` after measuring real runs on the
      team's machines (`python -m scripts.bench_rows --rows 1000000`); existing runs can be
      indexed later with `POST /api/runs/{id}/search-index`.
- [ ] Run deletion is manual (single or bulk clean-up); there is no automatic retention.
      Deleting a whole evidence item is not supported yet.
- [ ] Backups exclude dumped files by design, and live on the same machine (separate Docker
      volume, usually the same disk). Copying them off-machine is manual
      (`docker compose cp app:/backups ...`).
- [ ] Set real `timeout_seconds` per catalog plugin once the catalog is final (filescan/dumpfiles
      on big images may need more than the 1 h default).
- [ ] Orphaned `vol` processes are only found after a crash on Linux (uses /proc); in Docker a
      container restart ends them anyway.
- [ ] A stalled run's Python thread cannot be killed: the watchdog frees its slot, but if the
      thread is stuck holding SQLite's write lock the whole app waits until it lets go.
- [ ] Decide (forensics team) which plugins may write files; they must be declared with
      `writes_files=True`. Only the EXAMPLE pslist `--dump` is.
- [ ] Audit anchors (`audit-anchors.jsonl`) live in the backup folder; someone with write access
      to both volumes could still rewrite both. Copy backups/anchors off-machine for stronger
      guarantees.

- [ ] Comparison: set real `compare_keys` / `compare_ignore` for each catalog plugin (only EXAMPLE
      keys for pslist and info exist). Comparisons hold both runs' key values in memory: fine
      for typical runs, heavy for multi-million-row filescan runs. Values are compared exactly
      (no case-insensitivity or path normalisation yet).
- [ ] Indicators: no regex mode, no import/export of watchlists (e.g. STIX/CSV), and "Check all
      images" re-reads every row (no incremental index). Indicator types are generic; columns
      per plugin (e.g. which column holds a remote IP) are not used yet.
- [ ] Moving global notes into the "General" case during migration 0009 is not itself an audit
      event (the notes' own history is unchanged).
- [ ] Case export: the report has no row data inline (it is in the ZIP's CSVs), skips page/API
      request events, note edit history and full AI prompts. Revisit if reviewers need them.
- [ ] Case export ZIPs are built in a temp file; very large runs or dumped files make big
      downloads. No size limit or progress indicator yet.
- [ ] Integrity: a full re-hash before each run is off by default (`FT_VERIFY_ON_RUN`); the
      default pre-run check is size + modification time only. Decide per deployment.
- [ ] The UI doesn't refresh automatically after hashing finishes (reload the page).
- [x] Failed AI requests show the error text twice in the AI panel.
- [ ] The gitleaks pre-commit hook only protects local commits; in CI it checks nothing.
- [ ] Linux/macOS memory images (custom symbol tables) are out of scope for the PoC.
- [ ] AI agent: test against the real provider (`python -m app.ai.probe`, then a real goal and
      `python -m app.ai.probe task <id>`); replace the EXAMPLE agent eval case with real ones.
      Design choices to revisit if needed: waiting for runs counts against the time limit (only
      approval time is paused); runs a task queued keep going if the task ends by its time
      limit; resumed tasks redo an AI call that was in progress when the app stopped.
