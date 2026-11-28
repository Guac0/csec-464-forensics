# Forensics Tool — AI-Assisted Memory Forensics (Proof of Concept)

A browser-based interface for analysing Windows RAM images with
[volatility3](https://github.com/volatilityfoundation/volatility3), with an external AI model
that helps interpret the output and suggests what to run next.

## Intent

Volatility is powerful but hard to drive from the command line: plugin names and flags are easy to
get wrong, output is large, and it is hard to keep track of what was run and what it showed. This
project wraps it in a local web app so an analyst can:

- pick a RAM image and run volatility plugins from a guided form instead of the CLI,
- browse, filter and keep every result, with the exact command, tool version and hashes recorded,
- keep notes next to the evidence, and group related images into cases,
- ask an AI assistant questions about the results, where every claim cites the specific result
  rows it relies on and the full prompt/model/parameters are recorded,
- run the follow-up queries the AI suggests with one click, after they pass the same argument
  allowlist as manual queries.

**AI output is a lead, never evidence.** It is always shown separately from tool output and must be
verified against the cited rows.

This is a deliberately small proof of concept: **single user, runs on your own workstation, bound to
`127.0.0.1`, no login.** See [basic_version_notes.md](basic_version_notes.md) for the design and
[CONTRACTS.md](CONTRACTS.md) for the code structure.

## Running it

**Requirements:** Docker Desktop (Windows/macOS) or Docker Engine with Compose v2.24+ (Linux), and
an OpenAI-compatible AI endpoint (e.g. a local Ollama/vLLM server or an approved hosted provider).

1. **Configure** (optional but needed for AI features):

   ```bash
   cp .env.example .env
   # edit FT_AI_BASE_URL, FT_AI_API_KEY, FT_AI_MODEL
   ```

2. **Add evidence:** copy RAM images into the `evidence/` folder. It is mounted read-only into the
   container and ignored by git as images are typically too large to version control and vary based on the user's needs.

3. **Start:**

   ```bash
   docker compose up --build
   ```

4. **Open** <http://127.0.0.1:8000> and click **Scan evidence folder**.

Stop with `Ctrl+C` or `docker compose down`. Your work (database, run output, symbol cache) is kept
in Docker volumes between restarts; `docker compose down -v` deletes it all. Logs:
`docker compose logs -f app`.

### Windows / Docker Desktop tips

- Keep the repo and `evidence/` inside the WSL2 filesystem (e.g. `\\wsl$\Ubuntu\home\<you>\...`).
  Mounting multi-GB images from `C:\` is very slow.
- Give WSL enough memory for large images in `%UserProfile%\.wslconfig` (`[wsl2]` /
  `memory=12GB`), then `wsl --shutdown`. The container limit is `FT_MEM_LIMIT` (default `8g`).
- volatility downloads Windows symbols from Microsoft the first time it sees a Windows build, so the
  first run needs internet. Symbols are cached afterwards; set `FT_VOL_OFFLINE=true` to forbid
  downloads.
- An AI server on the Windows host is reachable from the container at
  `http://host.docker.internal:<port>/v1`, not `localhost`.

### Configuration

All settings are `FT_`-prefixed environment variables in `.env`; every one is documented in
[.env.example](.env.example) and defined in `app/config.py`.

### Running without Docker (development)

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev,volatility]"
pytest -q
mkdir -p data symbols backups
FT_EVIDENCE_DIR=./evidence FT_DATA_DIR=./data FT_SYMBOLS_DIR=./symbols FT_BACKUP_DIR=./backups \
  uvicorn app.main:create_app --factory --reload
```

Team workflow, branch rules and guidance for AI coding assistants:
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md). Outstanding setup and hand-off work: [TODO.md](TODO.md).

## Features

> **Stub — to be completed by the team.** Infrastructure exists for each item below; the forensic
> content is still being written. Update each entry's status and description as it lands.

### Evidence handling
- **Status:** infrastructure done
- Scan the read-only evidence folder, per-image description and notes.
- **Integrity:** each image is hashed (SHA-256, MD5, SHA-1) before its first run, and checked for
  changes (size + modification time; optionally a full re-hash) before every run. Analysts can
  enter the hashes from the acquisition report; a mismatch blocks runs until it is fixed or
  acknowledged with a reason (`FT_INTEGRITY_MODE=warn` flags instead of blocking). Every run
  records the exact image hash it ran against; every hash computation is kept in a history.
- OS details are filled from `windows.info` by a post-run hook (EXAMPLE; under review).
- _TODO: describe OS detection and what is shown per image._

### Volatility plugins
- **Status:** TODO
- _TODO: list the supported plugins, what each is used for, and their allowed arguments._

| Plugin | Purpose | Arguments | Auto-enumerate |
|---|---|---|---|
| _e.g. `windows.pslist.PsList`_ | _TODO_ | _TODO_ | _TODO_ |

### Preset queries
- **Status:** TODO
- _TODO: describe the hardcoded suggested queries and when to use them._

### Recommended next (investigation guide)
- **Status:** infrastructure done, guide content EXAMPLE (forensics team)
- The image page's "Recommended next" panel suggests what to run: first the remaining
  **baseline** steps in order (the standard first pass: processes, network, ...), then
  follow-ups of the image's succeeded runs ("pslist found processes -> run pstree"), some only
  when a hook flagged rows. Each step has a reason; Run it, Edit its options first, Dismiss it
  for this image, or "Run remaining baseline". No AI involved.
- **Ask AI what to run next** (button on the same panel, optional focus such as "suspect
  credential theft"): the AI sees the investigation state (runs so far, hook findings, flagged
  rows, the guide's recommendations) and suggests 1-5 plugins with specific options and a short
  rationale. The answer appears in the AI chat; the panel shows its runnable suggestions. Runs
  started from any AI suggestion link back to the answer ("suggested by AI answer N"), and
  suggestions show when they already ran.
- The guide is data in `app/tools/volatility/guide.py`; `/guide` shows it, and
  `python -m app.tools.volatility.guide` prints it with any problems. How to extend it:
  [app/tools/volatility/README.md](app/tools/volatility/README.md#investigation-guide).

### Auto-enumeration
- **Status:** infrastructure done, plugin set TODO
- _TODO: list what runs when "Auto-enumerate" is clicked and why._

### Results browsing
- **Status:** infrastructure done
- Paged results tables with stable columns; tree output (e.g. process trees) is indented; each
  row has a citation key `R<run>:<row>`.
- Search across all columns, per-column filters (text contains, or `=`, `!=`, `>`, `>=`, `<`,
  `<=` with numbers compared as numbers) and click-to-sort headers. The view lives in the URL.
- **Export…** downloads the current view or all rows as CSV (Excel / Timeline Explorer) or JSON
  Lines, or the tool's raw output. Exports are recorded in the activity log.
- Fast up to ~1M rows per run; `FT_SEARCH_INDEX=true` adds a full-text index for near-instant
  search on huge runs (more storage). Measure with `python -m scripts.bench_rows`.
- _TODO: describe any per-plugin views or highlighting._

### Dumped files
- **Status:** infrastructure done; which plugins may dump is TODO (example: pslist `--dump`)
- Files a plugin writes (e.g. dumped processes) are hashed (SHA-256, MD5, SHA-1), typed, linked
  to the result row that names them, and listed on the run page. Downloads are an encrypted zip
  (password `infected`) by default, or the raw file after a warning; every download re-checks
  the hash and is recorded in the activity log. Each run may write at most 2 GiB
  (`FT_MAX_ARTIFACT_BYTES`); bigger runs are stopped, keeping what was written.

### Post-processing hooks
- **Status:** infrastructure done, hooks TODO
- After a run succeeds, plugin-specific hooks can flag rows (highlighted, filterable by tag),
  add run-level findings with row citations, record facts about the image, and queue follow-up
  runs (with loop guards). A failing hook shows a warning but never fails the run; hooks can be
  re-run from the run page. Findings and flags are passed to the AI as automated heuristics.
- _TODO: list the hooks and what each one flags._

### AI analysis
- **Status:** infrastructure done, prompts TODO (forensics team)
- Ask questions, summarise a run, cited claims with clickable row links, provenance dropdown,
  validated one-click query suggestions.
- **Give the AI a goal** (switch in the AI chat form, e.g. "find processes named xyz"): the AI
  agent works step by step on this image only. It searches existing results (list runs, search
  rows with text/column filters, read rows, read hook findings) and can ask to **run plugins**
  (`queue_run`, at most `FT_AGENT_MAX_RUNS`=5 per task). Each run request waits for your
  decision in the task card: **Approve**, **Deny** (optional note to the AI), **Edit options
  first**, or **Approve all remaining**; or tick **Yes to all** when giving the goal (nothing is
  excluded). The time limit is paused while waiting for you. Approved runs are queued as origin
  `agent` with an "AI task N" badge on the run list and run page (who approved it); the task
  waits for them, then reads their results. A run that already exists with the same options is
  refused and the AI is pointed to it. Cancelling a task also cancels its queued/running runs;
  pending requests expire when the task ends.
- The task card shows live status: current action, steps with the rows the AI looked at, step
  and run counts, elapsed time (and time paused for approval), the most time left, and per run
  its status and an estimate from earlier runs of the same plugin scaled by image size. Limits
  per task (steps, time, runs) default to `FT_AGENT_MAX_STEPS` / `FT_AGENT_MAX_SECONDS` /
  `FT_AGENT_MAX_RUNS`. Tool calls use native function calling or a text protocol for models
  without it (`FT_AI_TOOL_MODE=auto|native|text`).
- Reasoning models' `<think>` text is hidden from answers but saved: see "Model reasoning"
  under Provenance and in the case export.
- **Restarts:** AI tasks continue after an app restart from their last checkpoint: a task
  waiting for your approval keeps waiting (its requests stay valid), one waiting for runs waits
  for them, one interrupted during an AI call redoes that step. The card notes "resumed".
- **Checking a provider:** `python -m app.ai.probe` (in Docker: `docker compose exec app python
  -m app.ai.probe`) tests plain answers, native tool calls, the text protocol and reasoning
  output with tiny evidence-free requests and prints a JSON report; `python -m app.ai.probe task
  <id>` summarises a finished task (status, timing, steps, run decisions, citation checks).
- **Approach:** the AI never sees the memory image. It reads data the app already stored
  (parsed volatility rows, hook findings, notes) and answers as a *lead*, not evidence: every
  answer is labelled "AI-generated lead — not evidence" and must cite rows as `[R<run>:<row>]`,
  which become links to the row.
- **What is sent** (built in `app/ai/context.py`, for one image only, never across images or
  cases): image metadata (file name, size, SHA-256, integrity status, detected OS), that image's
  own notes (not case notes), rows the analyst selected, then each run with its hook findings and
  up to 50 rows (200 for "Summarise run"), capped at about 60,000 characters (`[truncated]`
  marks a cut; rows are never cut in half). The last 6 successful question/answer turns are
  included as chat history. The exact messages are stored with each answer (Provenance).
- **Citation checks:** a citation is checked at answer time in two steps: (1) the row exists;
  (2) typed values stated in the same sentence (IPs, paths, file names, hex addresses,
  quoted/backticked text and labelled numbers such as `PID 1234`) appear in the cited row(s),
  or in their direct parent/child for tree plugins. A cited row that doesn't contain such a
  value is flagged "cited row doesn't support this" in the answer, the case export and the
  evals. Answers saved before this check show as "not checked".
- **Suggestions:** suggested follow-up queries are validated against the plugin allowlist
  before they get a Run button.
- **Provider:** any OpenAI-compatible API (`FT_AI_BASE_URL`, `FT_AI_MODEL`, `FT_AI_API_KEY`).
  Context is sent to that provider: use a local model (e.g. Ollama) when evidence must not
  leave the machine. Each answer records the model, parameters and `PROMPT_VERSION`.
- **Known limitations:** the prompts are placeholders until the forensics team writes them;
  row selection is "first N rows per run" (no per-plugin selection yet), so large runs are only
  partly seen; the support check matches values, not meaning (it can't tell whether a claim
  about a row is *true*, bare numbers like counts are not checked, and a value mentioned only
  for contrast can be flagged); one image per conversation (no multi-image AI by design).

### AI evaluation (developers)
- `python -m evals.run` replays fixed questions against recorded tool output and scores the AI's
  answers (valid citations, expected rows cited, required/forbidden terms, valid suggestions,
  optional AI-judge grade), compared with a committed baseline. See
  [evals/README.md](evals/README.md).

### Cases (several images)
- **Status:** done (cases, sharing, indicators, comparison view)
- A **case** groups images investigated together, e.g. before/after snapshots of one machine,
  or several machines hit by the same actor. Create one on the home page and add images with an
  optional label ("before", "after", "laptop-2"). An image can be in several cases; cases are
  optional and images outside any case work as before.
- Images in a case stay **separate**: each keeps its own runs, rows, notes, hooks and AI
  history. Open an image *from its case* (case chips on the home page, or the case page) to work
  in that case: the breadcrumb shows the case, and a **Shared in case** panel lists what the
  other images shared.
- **Share** (on a result row, hook finding, image note or AI answer) points the other images of
  the active case to that item, with an optional comment. Shared items are pointers, shown as
  their source is *now* ("changed since shared" / "source gone" when it was edited or deleted),
  always naming the image they came from. AI answers are shared as labelled AI leads. Nothing
  shared is ever added to another image's runs, notes, hook input or AI context. Click
  "shared ✕" to un-share; removing an image from a case un-shares what it shared there.
- **Indicators:** each case has a watchlist (process names, file paths, IPs, domains, hashes,
  registry keys, other text). Add them on the case page or with **+IOC** on any result row (the
  type is guessed). Every image's own rows are searched; a hit always points to a row of that
  image, listed on the case page (hits per image), on the image page and as an **IOC** mark on
  the row. Matching is **exact** by default (case-insensitive, `\` and `/` alike for paths,
  canonical IPs; a process name also matches a path ending in it); **contains** and "only in
  column X" are per-indicator options. New runs are checked automatically as they finish;
  **Check all images** re-checks existing runs (on demand: it reads every row of every run).
- **Compare** two images of a case (case page → Compare…): pick a plugin with finished runs on
  both, and the rows are paired by the columns that identify "the same thing" (the catalog's
  `compare_keys`, e.g. process name; otherwise every non-volatile column). Results: **only in
  A**, **only in B**, **changed** (with the columns that differ, A → B) and a count of identical
  rows. PIDs, offsets, times and thread/handle counts are ignored by default; tick other columns
  to change that. Download everything as CSV, or **Save to case** to list it on the case page
  and in the case report (re-opened with current data).
- Each case has its own **case notes** (they replace the old investigation-wide notes; existing
  ones were moved into a "General" case containing every image).
- Exports: **Export case…** gives a case report (images and labels, case notes, everything
  shared, then each image's section). A single image's report gets a separate, labelled
  "Leads from linked evidence" section listing what other images in its cases shared.

### Notes and export
- **Status:** done
- Notes belong to one image or one case. Every note edit is kept; "history" on a note shows all
  versions, even after deletion.
- **Export…** on an evidence page (or **Export investigation…** on the home page) downloads a
  report: a Markdown file with hashes and integrity history, notes, every run with its exact
  command and findings, AI answers (labelled as leads, with model/prompt provenance) and the
  activity log. The ZIP option adds each run's rows as CSV, the raw tool output and a
  `manifest.json` with the SHA-256 of every file. Ticking "include dumped files" encrypts the ZIP
  (password `infected`, open with 7-Zip). Each export is recorded in the activity log with the
  report's SHA-256.

### Activity (audit) log
- **Status:** done
- Every action is recorded in an append-only, tamper-evident log: evidence scans and hashing,
  runs (queued, started, finished, cancelled, interrupted, deleted), backups, post-processing, notes, AI questions and answers,
  and (for now) every page and API request. "Activity" in the top bar shows and filters it;
  "Verify integrity" checks that nothing was edited or deleted. Evidence and run pages link to
  their own activity.

### Crash recovery and disk protection
- **Status:** done
- If the app stops while a run is in progress (crash, restart, `docker compose down`), the run
  is marked **interrupted** — not failed — on the next start. Any leftover `vol` process is
  stopped, and whatever the run wrote so far is kept and hashed. **Re-run** queues the same
  plugin and arguments again (also offered for failed runs). Queued runs simply start again.
- New runs are refused while the disk is nearly full (less than 5 GiB free by default, or over
  an optional cap on the data folder); queued runs wait until there is space. A run in progress
  is stopped if free space falls under 1 GiB, so the database is never the thing that runs out.
  See the `FT_*_DISK_BYTES` / `FT_MAX_DATA_BYTES` settings in `.env.example`.
- Each plugin in the catalog can have its own timeout (`timeout_seconds`); the default is
  `FT_RUN_TIMEOUT_SECONDS`.
- A run that shows no progress for 10 minutes (`FT_RUN_STALL_SECONDS`) — e.g. a post-processing
  hook stuck in a loop — is marked interrupted ("stalled") or its hooks failed, and the next
  queued run starts.

### Deleting runs
- **Status:** done
- **Delete…** on a finished run removes its rows, raw output and dumped files, with a required
  reason. The run stays listed as **deleted** with its command, its hashes and its audit
  history, so reports and the activity log still account for it; AI answers that cite it show
  the citation struck through. **Clean up…** on an evidence page does the same for all its
  failed, interrupted and cancelled runs at once. The System page lists the runs using the most
  disk. Re-run a deleted run to get its data back.

### Backups
- **Status:** done
- A backup is one ZIP in `FT_BACKUP_DIR` (the `forensics-backups` Docker volume): a consistent
  database snapshot plus every run's raw output, with a `manifest.json` of SHA-256 hashes.
  Dumped files are **not** included (possible malware, often large); after a restore, ones still
  on disk are reused if their hashes match, others can be re-dumped by re-running the plugin.
- Automatic every 24 h (`FT_BACKUP_INTERVAL_HOURS`), keeping the last 7 (`FT_BACKUP_KEEP`);
  **Back up now** and **Verify** on the System page; manual backups are never auto-deleted.
- Each backup also writes the audit log's latest hash to `audit-anchors.jsonl` next to the
  backups. The System page fails if the live audit log no longer contains it (log rebuilt, or
  the database swapped).
- Command line (safe while the app runs, except restore):

  ```bash
  docker compose exec app python -m app.backup create          # or: list, verify <name>
  docker compose cp app:/backups ./backups-copy                 # copy them off this machine
  # restore: stop the app first; the current data is moved to /data/pre-restore-<time>/
  docker compose stop app
  docker compose run --rm app python -m app.backup restore <name>
  docker compose start app
  ```

### System page
- **Status:** done
- **System** in the top bar (with a warning badge when something is wrong) checks disk space,
  the evidence/data/symbol folders, the run worker, the database, the audit chain, hooks, the
  plugin catalog, backups and the AI settings, and lists all active settings (API key hidden). **Test volatility** runs
  `vol -h` and checks every catalog plugin exists in the installed version; **Test AI** sends one
  tiny request to the provider. Start here when something does not work on a new machine.
  JSON: `GET /api/system/health` (`/health` stays a simple liveness check).
- **Settings** in the top bar: AI agent defaults (max steps, time limit, max plugin runs, tasks
  at once) and the AI tool-calling protocol can be changed in the app. A saved value overrides
  the `FT_*` environment value until **Reset**; every change is in the activity log. JSON:
  `GET/PUT /api/system/settings`, `DELETE /api/system/settings/{key}`.

## Limitations

- Single user, localhost only, no authentication — do not expose the port to a network.
- Windows memory images only for now (Linux/macOS need custom symbol tables).
- Data sent to the AI provider includes evidence-derived strings; only use a provider you are
  permitted to share case data with.
