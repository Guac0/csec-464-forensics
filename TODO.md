# TODO

What is still open. Tick items off as they are done, and delete them once merged.

For the forensics team's progress (which plugins, prompts and checks are still examples), the
**Content** page in the app and `python -m forensics check` are always up to date. The checklist
for the team is in [forensics/README.md](forensics/README.md#checklist-before-the-first-real-case).

## Repo owner

- [ ] **Watch the first CI run** of each job, especially `docker` (the first real build of the
      image) and the new `forensics-content` job.
- [ ] **Protect `main`** (Settings → Rules → Rulesets, or the `gh api` command in
      [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)): pull request with 1 approval, required checks
      `lint`, `test`, `forensics-content`, `docker`, no force pushes or deletion.
- [ ] **CODEOWNERS:** put the forensics team's GitHub usernames on `/forensics/` in
      `.github/CODEOWNERS` and uncomment the line.
- [ ] **AI evaluation on GitHub:** add the secrets `FT_AI_BASE_URL`, `FT_AI_API_KEY` and the
      variable `FT_AI_MODEL` (optional `FT_AI_MAX_TOKENS`, `EVAL_RUNNER`). Check whether the RIT
      endpoint is reachable from GitHub's runners; if not, use a self-hosted runner. Then save a
      first baseline.
- [ ] **Test the AI agent against the real provider:** `python -m app.ai.probe`, then a real
      goal, then `python -m app.ai.probe task <id>`.
- [ ] **Integration workflow:** pick a small public Windows memory sample, record its URL and
      SHA-256, and run `integration.yml` once to check real volatility works in the image.
- [ ] Optional: labels (`volatility`, `ai`, `ui`, `infra`), a project board and a milestone for
      the demo date.
- [ ] Optional: releases. Pushing a tag `v*` publishes the image to
      `ghcr.io/guac0/csec-464-forensics`; set the package visibility afterwards.

## Decisions for later

- [ ] **Activity log level:** `FT_AUDIT_LEVEL` is `all` (every page and API request) during the
      proof of concept. Switch the default in `app/config.py` to `key_reads` afterwards. The log
      has no clean-up, so at `all` it keeps growing.
- [ ] **Search index:** decide whether to turn on `FT_SEARCH_INDEX` after measuring real runs
      (`python -m scripts.bench_rows --rows 1000000`). Existing runs can be indexed later with
      `POST /api/runs/{id}/search-index`.
- [ ] **Full re-hash before every run** (`FT_VERIFY_ON_RUN`) is off; the default check is size
      and modification time. Decide per deployment.
- [ ] **Volatility extras:** decide whether to depend on `volatility3[full]` (some Windows plugins
      need its extra libraries). This changes `pyproject.toml`.

## Known limitations

- Run deletion is manual (one run, or "Clean up"); there is no automatic retention, and a
  whole image can't be deleted yet.
- Backups skip dumped files on purpose and live on the same machine as the app. Copy them off
  the machine yourself (`docker compose cp app:/backups ...`); the same goes for the audit
  anchors stored next to them.
- A stalled run's thread can't be killed: the watchdog frees its slot, but if it holds the
  database's write lock, the app waits until it lets go. Leftover `vol` processes are only found
  after a crash on Linux.
- Comparisons keep both runs' key values in memory (heavy for multi-million-row runs) and
  compare values exactly (no case or path normalisation).
- Indicators have no regex mode and no watchlist import/export, "Check all images" re-reads
  every row, and indicator types don't know which plugin column holds what.
- Case reports have no row data inline (it's in the ZIP's CSVs) and skip page/API request
  events, note edit history and full AI prompts. Export ZIPs have no size limit or progress bar.
- The image page doesn't refresh by itself after hashing finishes.
- The gitleaks pre-commit hook only protects local commits; CI doesn't run it.
- Linux and macOS memory images are out of scope (they need custom symbol files).
- AI agent design choices to revisit if needed: waiting for runs counts against the time limit
  (only waiting for approval is paused); runs a task queued keep going if the task hits its time
  limit; a resumed task redoes an AI call that was in progress when the app stopped.
