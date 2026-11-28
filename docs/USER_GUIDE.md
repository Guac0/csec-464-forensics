# User guide

How to use the Forensics Tool to examine a Windows memory image. To install and start the app,
see the [README](../README.md). To change which plugins it offers, what it recommends, or what
the AI is told, see [forensics/README.md](../forensics/README.md).

Which plugins are available, and what each one does, changes as the forensics team works.
Open the **Content** page in the top bar for the current list.

## The basics

- **Evidence** is a memory image file in the `evidence/` folder. The app can only read it,
  never change it.
- A **run** is one volatility plugin run against one image, with the options you chose. Every
  run keeps its exact command, the volatility version, the image hash it ran against and its
  raw output.
- A **row** is one line of a run's output. Each row has a key like `R12:34` (run 12, row 34).
  Notes, AI answers and reports use these keys to point at the data.
- **AI answers are leads, not evidence.** They are always shown apart from tool output and must
  be checked against the rows they cite.

## Images

1. Copy the image into `evidence/` and click **Scan evidence folder** on the home page.
2. Open the image. Before its first run the app hashes it (SHA-256, MD5 and SHA-1). Before
   every later run it checks that the file hasn't changed (size and modification time; a full
   re-hash if `FT_VERIFY_ON_RUN` is on).
3. Optionally enter the hashes from the acquisition report. If they don't match, runs are
   blocked until the mismatch is fixed or acknowledged with a reason. (`FT_INTEGRITY_MODE=warn`
   shows a warning instead of blocking.) Every hash calculation is kept in a history.

When `windows.info` has run, the image page shows the Windows version it found.

## Running plugins

There are several ways to start a run. They all go through the same check: only plugins and
options the forensics team has allowed can run.

- **Run form:** pick a plugin, fill in its options and run it. Options that make the plugin
  write files (such as `--dump`) are marked, and you're asked to confirm.
- **Presets:** one-click queries some plugins offer, shown under the run form.
- **Auto-enumerate:** queues the plugins that identify the image (such as `windows.info`).
- **Recommended next:** a panel on the image page. It first lists the remaining *baseline*
  steps (the standard first pass), then follow-ups based on what already ran ("pslist found
  processes, so look at the process tree"). Some follow-ups only appear when a hook flagged
  something. Each suggestion says why. You can run it, edit its options first, dismiss it for
  this image, or run the whole remaining baseline. No AI is involved. The full list of rules is
  on the **Guide** page (`/guide`).
- **Ask AI what to run next** (same panel): see [AI analysis](#ai-analysis).

Runs are queued and start one at a time by default, because volatility can use a lot of memory.

## Reading results

- Results are shown in pages. Tree output, such as a process tree, is indented.
- Search across all columns, filter single columns (text contains, or `=`, `!=`, `>`, `>=`,
  `<`, `<=` where numbers are compared as numbers) and click a column header to sort. The view
  is part of the page address, so you can bookmark or share it.
- **Export…** downloads the current view or all rows as CSV (for Excel or Timeline Explorer)
  or JSON Lines, or the tool's raw output. Exports are recorded in the activity log.
- Up to about a million rows per run stay fast. For bigger runs, `FT_SEARCH_INDEX=true` adds a
  search index (more disk space).

## Dumped files

Some options make a plugin write files, for example dumped processes. The app hashes each file
(SHA-256, MD5, SHA-1), guesses its type, links it to the row that names it and lists it on the
run page.

Treat these files as live malware. Downloads come as an encrypted ZIP (password `infected`) by
default, or as the raw file after a warning. Every download re-checks the hash and is recorded.
A run may write at most 2 GiB (`FT_MAX_ARTIFACT_BYTES`); a bigger run is stopped and keeps what
it wrote.

## Flags and findings (hooks)

After a run succeeds, small checks written by the forensics team (hooks) can look at its rows.
They can:

- flag rows (highlighted and filterable by tag),
- add findings to the run page, with links to the rows,
- record facts about the image (such as its Windows version),
- queue a follow-up run.

A hook that fails shows a warning on the run page, but the run itself still counts as
successful. **Re-run post-processing** on the run page runs the hooks again without running
volatility again. Flags and findings are passed to the AI as automated hints.

## AI analysis

The AI never sees the memory image. It only reads data the app already stored: parsed rows,
hook findings and notes. Every answer is labelled "AI-generated lead — not evidence".

### Asking questions

- Ask a question in the AI panel on the image page, or click **Summarize with AI** on a run.
- Every claim must cite rows as `[R12:34]`, which become links to the row.
- Suggested follow-up queries get a **Run** button, but only after they pass the same check as
  the run form. Runs started this way link back to the answer that suggested them.
- **Provenance** under each answer shows the model, settings and the exact messages sent.
  Reasoning models' hidden "thinking" text is saved there too.

### What is sent to the AI

Only data from this one image, never from other images or cases:

- the image's details (file name, size, SHA-256, integrity status, detected OS),
- the image's own notes (not case notes),
- rows you selected,
- each run with its hook findings and some of its rows (by default the first 50, or 200 for
  "Summarize with AI"; the forensics team can change this per plugin), plus every flagged row,
- the last 6 questions and answers of the conversation.

The total is capped at about 60,000 characters. `[truncated]` marks a cut; rows are never cut
in half.

The AI provider is set with `FT_AI_BASE_URL`, `FT_AI_MODEL` and `FT_AI_API_KEY` and can be any
OpenAI-compatible service. Everything above leaves the machine. Use a local model (for example
Ollama) when evidence must stay on the machine.

### How citations are checked

When an answer arrives, each citation is checked in two steps:

1. The cited row exists.
2. Values stated in the same sentence (IP addresses, paths, file names, hex addresses, quoted
   text and numbers labelled like "PID 1234") appear in the cited rows, or in their direct
   parent or child for tree output.

A citation that fails step 2 is marked "cited row doesn't support this" in the answer and in
reports. The check compares values, not meaning: it can't tell whether a claim is true, it
ignores bare numbers such as counts, and a value mentioned only for contrast can be flagged.

### What should I run next?

**Ask AI what to run next** on the Recommended next panel (with an optional focus, such as
"suspected credential theft") sends the investigation so far: runs, findings, flagged rows and
the guide's suggestions. The AI suggests 1 to 5 runs with specific options and its reasons. The
answer appears in the chat, and its suggestions appear on the panel. Suggestions that already
ran are marked.

### Giving the AI a goal

Turn on **Give the AI a goal** in the chat form (for example "find processes named xyz"). The
AI then works step by step on this image: it lists runs, searches and reads rows and findings,
and can ask to run plugins.

- Each run request waits for you in the task card: **Approve**, **Deny** (with an optional note
  to the AI), **Edit options first** or **Approve all remaining**. Or tick **Yes to all** when
  you give the goal; it then approves everything, including plugins that write files.
- The time limit is paused while the task waits for you.
- Runs the AI started are marked with an "AI task" badge that says who approved them.
- The AI can't start a run that already exists with the same options; it is pointed to the
  existing one.
- Cancelling a task also cancels its queued and running runs.
- The card shows what the AI is doing, the rows it looked at, step and run counts, time used
  and time paused, and an estimate for each run.
- Limits per task (steps, time, runs) start from the values on the **Settings** page.
- After an app restart, tasks continue where they stopped. A task waiting for you keeps
  waiting, and a step that was interrupted is done again. The card says "resumed".

To check that a provider works: `docker compose exec app python -m app.ai.probe`. It sends tiny
test requests without evidence and prints a report. `python -m app.ai.probe task <id>`
summarizes a finished task.

### Limits of the AI

- The prompts are examples until the forensics team writes the real ones.
- On large runs the AI only sees part of the rows.
- One image per conversation, on purpose: mixing images makes models confuse their sources.

## Cases (several images)

A **case** groups images you investigate together, such as before and after snapshots of one
machine, or several machines hit by the same attacker. Create one on the home page and add
images with an optional label ("before", "after", "laptop-2"). An image can be in several
cases. Images outside any case work as normal.

Images in a case stay **separate**: each keeps its own runs, rows, notes, hooks and AI history.
Open an image from its case (the case chips on the home page, or the case page) to work in that
case. The breadcrumb then shows the case, and a **Shared in case** panel lists what the other
images shared.

- **Share** a result row, finding, image note or AI answer with the other images of the case,
  with an optional comment. A shared item is a pointer: it always shows the source as it is
  now, says if it changed or was deleted, and names the image it came from. Nothing shared is
  ever added to another image's runs, notes, hooks or AI context. Click "shared ✕" to stop
  sharing. Removing an image from a case stops sharing what it shared there.
- **Indicators:** each case has a watchlist of process names, file paths, IP addresses,
  domains, hashes, registry keys and other text. Add them on the case page, or with **+IOC** on
  any result row (the type is guessed). Every image's own rows are searched, and a hit always
  points to a row of that image: listed on the case page, on the image page, and as an **IOC**
  mark on the row. Matching is exact by default: upper and lower case count as the same, `\`
  and `/` count as the same in paths, IP addresses are compared by value, and a process name
  also matches a path ending in it. "Contains" and "only in column X" can be set per indicator.
  New runs are checked as they finish. **Check all images** re-checks existing runs; it reads
  every row, so it can take a while.
- **Compare** two images of a case (case page, **Compare…**): pick a plugin that ran on both.
  Rows are paired by the columns that identify "the same thing" (set per plugin by the
  forensics team, such as the process name). The result lists what is only in A, only in B, and
  what changed (with the columns that differ), plus a count of identical rows. PIDs, memory
  offsets, times and thread or handle counts are ignored by default; tick columns to change
  that. Download the result as CSV, or **Save to case** to list it on the case page and in the
  case report (it is recalculated with current data when opened).
- Each case has its own **case notes**.

## Notes and reports

- A note belongs to one image or one case. Every edit is kept: **history** on a note shows all
  versions, even after the note is deleted.
- **Export…** on an image page (or **Export investigation…** on the home page) downloads a
  report: hashes and integrity history, notes, every run with its exact command and findings,
  AI answers (labelled as leads, with model and prompt details) and the activity log.
- The ZIP option adds each run's rows as CSV, the raw tool output and a `manifest.json` with
  the SHA-256 of every file. Ticking "include dumped files" encrypts the ZIP (password
  `infected`; open it with 7-Zip).
- **Export case…** on a case page gives a case report: images and labels, case notes,
  everything shared, then a section per image. A single image's report lists what other images
  in its cases shared in a separate "Leads from linked evidence" section.
- Every export is recorded in the activity log with the report's SHA-256.

## Activity log

Every action is recorded in a log that can't be edited or deleted without it being noticed:
scans and hashing, runs, backups, hooks, notes, AI questions and answers, and (for now) every
page and API request. **Activity** in the top bar shows and filters it. **Verify integrity**
checks that nothing was changed. Image and run pages link to their own activity.

## Keeping data safe

- **Crashes and restarts:** a run that was in progress when the app stopped is marked
  **interrupted**, not failed. Any leftover volatility process is stopped, and whatever the run
  wrote so far is kept and hashed. **Re-run** queues the same plugin and options again (also
  offered for failed runs). Queued runs simply start again.
- **Stuck runs:** a run that shows no progress for 10 minutes (`FT_RUN_STALL_SECONDS`) is
  marked interrupted, and the next run starts.
- **Disk space:** new runs are refused when less than 5 GiB is free (queued runs wait for
  space), and a running plugin is stopped below 1 GiB, so the database never runs out of room.
  The limits are the `FT_*_DISK_BYTES` and `FT_MAX_DATA_BYTES` settings in `.env.example`.
- **Deleting runs:** **Delete…** on a finished run removes its rows, raw output and dumped
  files; a reason is required. The run stays listed as deleted with its command, hashes and
  history, so reports still account for it, and AI answers citing it show the citation struck
  through. **Clean up…** on an image page does this for all its failed, interrupted and
  cancelled runs. Re-run a deleted run to get its data back.
- **Backups:** one ZIP per backup in the `forensics-backups` Docker volume: a database snapshot
  plus every run's raw output, with SHA-256 hashes. Dumped files are not included (possible
  malware, often large). A backup is made every 24 hours (`FT_BACKUP_INTERVAL_HOURS`) and the
  last 7 are kept (`FT_BACKUP_KEEP`); backups you make yourself are never deleted
  automatically. Use **Back up now** and **Verify** on the System page, or the command line:

  ```bash
  docker compose exec app python -m app.backup create          # or: list, verify <name>
  docker compose cp app:/backups ./backups-copy                 # copy them off this machine
  # restore: stop the app first; the current data is moved to /data/pre-restore-<time>/
  docker compose stop app
  docker compose run --rm app python -m app.backup restore <name>
  docker compose start app
  ```

  Backups live on the same machine. Copy them elsewhere for real protection.

## System, Settings and Content pages

- **System** (top bar; shows a warning badge when something is wrong) checks disk space, the
  folders, the run worker, the database, the activity log, hooks, the plugin list, backups and
  the AI settings, and lists all settings (the API key is hidden). **Test volatility** checks
  that every allowed plugin exists in the installed volatility. **Test AI** sends one tiny
  request to the provider. Start here when something doesn't work on a new machine.
- **Settings:** the AI agent's default limits and the tool-calling mode. A saved value
  overrides the `FT_*` setting until you click **Reset**. Every change is logged.
- **Content:** what the forensics team has set up (plugins, guide, hooks, prompts) and what is
  still to do.

## Limitations

- Single user, no login. The app only listens on `127.0.0.1`: don't expose it to a network.
- Windows memory images only (Linux and macOS images need custom symbol files).
- Data sent to the AI provider includes text from the evidence. Only use a provider you are
  allowed to share case data with.
