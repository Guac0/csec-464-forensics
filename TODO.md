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
- [ ] **Auto-enumerate set** — set `auto_enumerate=True` on the plugins that should run first.
- [ ] **Real output fixtures** — capture `vol -r jsonl` output for every catalog plugin into
      `tests/fixtures/` and replace the synthetic `sample_pstree.jsonl`.
- [ ] **Output parsing** — check `VolatilityRunner.parse_output` (`app/tools/volatility/runner.py`)
      against those fixtures; add per-plugin post-processing where needed.
- [ ] **OS detection** — fill `Evidence.os_info` from `windows.info` output (needs a small
      post-success hook in `app/jobs/worker.py` that calls your code).
- [ ] **AI prompts** — `app/ai/prompts.py`: the analysis system prompt and the run-summary question.
- [ ] **AI context** — `app/ai/context.py`: choose which rows of each plugin are worth sending.
- [ ] **Citation checking** — `app/ai/citations.py`: verify that cited row values actually
      support the claim (currently only checks the row exists).
- [ ] **Dependencies** — decide whether to depend on `volatility3[full]` (some Windows plugins need
      its extra libraries); this changes `pyproject.toml`.
- [ ] **README** — fill in the stubbed **Features** section.

## 3. Known infrastructure follow-ups

- [ ] Markdown export of notes, runs, hashes and AI outputs is not implemented yet.
- [ ] Runs don't re-verify the image hash before executing; a run records the evidence SHA-256 only
      if the image was hashed first.
- [ ] The UI doesn't refresh automatically after hashing finishes (reload the page).
- [ ] Failed AI requests show the error text twice in the AI panel.
- [ ] The gitleaks pre-commit hook only protects local commits; in CI it checks nothing.
- [ ] Linux/macOS memory images (custom symbol tables) are out of scope for the PoC.
