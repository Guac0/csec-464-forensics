> Written mainly for AI coding assistants. People: start with README.md or forensics/README.md.

# Architecture and original design

Origin: the PoC design notes (`basic_version_notes.md`, removed during handoff cleanup). Each
section gives the original intent, then the current state where it changed. Module-level
contracts: `CONTRACTS.md`. Feature decisions: other files in `docs/design/`.

## Scope

- Single user, local analyst workstation, AI-assisted volatility3 analysis of RAM images.
- One app container: web GUI + volatility3 + in-process worker. Bound to `127.0.0.1`, no auth.
- RAM images placed manually in a host folder mounted read-only at `/evidence`.
- External OpenAI-compatible model; URL, key, model from env (`FT_AI_*`).
- Out of scope: authentication, multiple users, uploads, URL ingest, VirusTotal, tools other than
  volatility3, Linux/macOS images (need custom symbol tables).
- Changed: "groups/sharing" was out of scope; cases and sharing between images of one case now
  exist (see `multi-evidence.md`), still single-user.

## Runtime layout

```
docker compose
└── app  (FastAPI + volatility3 + Jinja/HTMX UI, 127.0.0.1:8000)
      volumes: ./evidence -> /evidence:ro   (RAM images)
               symbols    -> /symbols       (volatility symbol cache)
               data       -> /data          (SQLite DB, raw run output, dumped files)
               backups    -> /backups       (DB backups + audit anchors)
```

- Database: SQLite on `/data` via SQLAlchemy + Alembic. The optional Postgres container from the
  original notes was never built.
- Jobs: in-process worker runs `vol -r jsonl ...` as a subprocess, never through a shell.
  `FT_MAX_CONCURRENT_RUNS` default 1 (volatility is memory-heavy). Changed: on startup, runs left
  "running" become INTERRUPTED (re-runnable), not failed; queued runs resume. Stall watchdog
  `FT_RUN_STALL_SECONDS`.
- Frontend: server-rendered Jinja + HTMX, no JS build step. Static assets in `app/web/static`.

## Data model (current tables, `app/models.py`)

Schema: one Alembic migration `0001_initial` (0001-0017 squashed at the handoff; migration
numbers elsewhere in docs/design are historical). Pre-squash databases are refused, not upgraded.

- Evidence, IntegrityCheck: path, size, mtime, sha256 (cached by path+size+mtime), `os_info`
  filled by the `windows.info` hook.
- Run, ResultRow, DerivedArtifact: plugin, args, status, origin (`RunOrigin`: manual,
  preset, auto, ai, hook, recommended, agent), tool version, raw jsonl path, rows with stable `R{run_id}:{row_idx}` citation
  keys, dumped files hashed and linked to rows.
- Note, NoteVersion: per-image and per-case notes with edit history (global notes were replaced
  by case notes).
- AIMessage: role, content, model, parameters, exact context, citations (+ value-support
  results), suggestions, saved reasoning, finish reason.
- AITask, AITaskStep, AIRunRequest: goal-driven agent tasks, steps, run approvals.
- Case, CaseEvidence, SharedItem, Indicator, IndicatorHit, SavedComparison: multi-evidence.
- DismissedRecommendation: per-image dismissed guide steps.
- AuditEvent, AuditHead: hash-chained audit log. AppSetting: DB overrides for agent settings.

## Core flow (original -> current)

1. Find images: scan `/evidence`, hash once. Unchanged.
2. Auto-enumerate: originally a fixed list (info, pslist, pstree, cmdline, netscan, malfind,
   dlllist, svcscan). Current: catalog entries with `auto_enumerate=True` (identification only);
   the deeper first pass is the investigation guide BASELINE (`ai-investigation.md`).
3. Browse results: sortable/filterable tables; manual runs only with allowlisted args. Large runs
   are paged and optionally indexed (`FT_SEARCH_INDEX`).
4. Ask the AI: notes, image info, compact run summaries; never whole large outputs.
5. AI responses: shown apart from tool output; citations link to rows and are validated (rows
   exist + typed values appear in them); provenance (model, params, prompt) stored; suggested
   queries are checked against the allowlist and shown as Run buttons. Changed: the original rule
   "the AI never runs anything itself" now has one exception: the goal-driven agent can queue
   runs, each needing analyst approval (or an explicit "yes to all" at the start of the task).
   Every such run is marked as AI-initiated.
6. Export: originally markdown. Current: per-image and per-case export ZIP (markdown report +
   CSVs + manifest with hashes).

## Risks noted at design time (still valid)

- Docker Desktop on Windows: bind-mounting multi-GB images from `C:\` is slow (WSL2 file
  sharing); WSL2 memory cap may need raising. User-facing tips are in README.md.
- Symbols: Windows dumps need Microsoft symbol downloads on first use (internet). Cache persists;
  `FT_VOL_OFFLINE=true` forbids downloads. Pre-fetching for offline use is not built.
- Argument safety: argv built from the allowlist only; global vol flags refused (incl.
  `--plugin-dirs`, which loads arbitrary Python); dumped-file output dir is controlled. AI
  suggestions and agent requests go through the same validation.
- Context size: filescan/handles produce tens of thousands of rows; per-plugin row selection for
  the AI is forensics-team content.
- AI coding pitfall: models mix volatility2 and volatility3 syntax (`--profile`, missing
  `windows.` prefix). Humans own plugin names, flags and columns; real `-r jsonl` output is
  committed as fixtures.

## Extension points kept on purpose

Rows with stable IDs; read-only evidence mount; tool version + exact args per run; full AI
provenance; volatility hidden behind `ToolRunner` (`app/tools/base.py`, registry in
`app/tools/registry.py`). These allow login, multiple users and more tools (bulk_extractor,
sleuthkit, plaso) later without rewriting the core.
