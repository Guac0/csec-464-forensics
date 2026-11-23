# Basic Version (Proof of Concept) — Design Notes

## Scope

A minimal, single-user proof of concept for AI-assisted volatility3 analysis of RAM images, intended to run on an analyst's local workstation.

- One app container runs the web GUI and volatility3 analysis.
- RAM images are placed manually by the user in a host folder mounted into the container.
- Work is persistent across restarts (SQLite on a volume, or an optional Postgres container).
- An external OpenAI-compatible model analyzes output and suggests further queries.
- **Out of scope:** authentication, multiple users, groups/sharing, uploads, URL ingest, VirusTotal, tools other than volatility3, Linux/macOS memory images.

## Architecture

```
docker compose
├── app  (FastAPI + volatility3 + web UI, bound to 127.0.0.1)
│     volumes:  ./evidence  → /evidence:ro
│               symbols     → /symbols        (volatility symbol cache)
│               data        → /data           (raw outputs; DB if SQLite)
└── db   (Postgres, optional — see below)
```

- **Database:** SQLite on the `/data` volume is preferred for single-user use: persistent, no setup, and a backup is a file copy. Use Postgres only if moving to the multi-user version soon. Writing it with SQLAlchemy keeps switching cheap.
- **Job execution:** an in-process background worker (an asyncio task or thread pool) runs `vol -r jsonl ...` as a subprocess. Concurrency is capped at 1–2 because volatility runs can use a lot of memory. Job state lives in a DB table; on startup, any job still marked "running" is marked failed.
- **No authentication:** the port is bound to `127.0.0.1` only (document this in the README). The AI provider's URL, key and model come from environment variables.
- **Frontend:** server-rendered Jinja + HTMX with a small table library avoids a JS build step. Use React only if the team already knows it well.

## Data model

- `evidence`: path, size, mtime, sha256, detected OS/build (from `windows.info`), notes
- `runs`: evidence_id, plugin, args, status, volatility version, started/finished, raw jsonl path, error
- `rows`: run_id, row_idx, data (JSON). Stable row IDs are what AI citations point to.
- `notes`: global notes or notes per evidence item
- `ai_messages`: role, content, model, parameters, exact context sent, cited row IDs, suggested queries

## Core flow

1. **Find images:** the app scans `/evidence`. The user picks an image; SHA-256 is computed once and cached by path + size + mtime.
2. **Auto-enumerate:** one button runs a fixed set of plugins: `windows.info`, `pslist`, `pstree`, `cmdline`, `netscan`, `malfind`, `dlllist`, `svcscan`.
3. **Browse results:** each run shows a sortable, filterable table. Manual runs: pick a plugin and fill in allowlisted arguments.
4. **Ask the AI:** it receives notes, image info and compact run summaries. Large outputs are not sent whole: send row counts, sample rows, or rows the user selects.
5. **AI responses:**
   - Shown separately from tool output.
   - Citations are clickable links to specific rows; validate after the response that cited rows exist and quoted values appear in them.
   - A provenance dropdown shows model, parameters and prompt.
   - Suggested next queries are returned as structured JSON (`{plugin, args, reason}`), checked against the plugin allowlist, and shown as **"Run" buttons**. The user stays in control; the AI never runs anything itself.
6. **Export:** notes, runs, arguments, hashes and AI outputs to markdown.

## Things to watch

- **Docker Desktop on Windows:** bind-mounting multi-GB images from `C:\` into a Linux container is slow (WSL2 file sharing). Keep images in the WSL filesystem or a named volume. WSL2 gets about half the host RAM by default; raise it in `.wslconfig` if large dumps fail.
- **Symbols:** Windows dumps need symbol files downloaded from Microsoft on first use (internet required). Persist the symbol cache; pre-fill it for offline use. Linux dumps need custom symbol files, so the PoC is Windows-only.
- **Argument validation:** build the argument list from an allowlist; never use a shell. Block `--plugin-dirs` (loads arbitrary Python) and control where `-o` writes dumped files. AI-suggested queries go through the same check.
- **Context size:** `filescan` and `handles` can return tens of thousands of rows. Decide early what a "run summary" sent to the AI looks like.
- **AI coding pitfall:** models confuse volatility2 and volatility3 syntax (`--profile`, missing `windows.` prefix). Humans own the volatility layer; commit real `-r jsonl` output as test fixtures so parsers and UI are built against real data.
- **Slow test cycles:** use small public sample dumps and recorded fixtures for UI work.

## Keep for future extension

- Results stored as rows with stable IDs
- Evidence mount kept read-only
- Each run records volatility version and exact arguments
- Full AI provenance stored
- volatility3 hidden behind a small `ToolRunner` interface

These allow login, multiple users, groups and more tools (bulk_extractor, sleuthkit, plaso) to be added later without rewriting the core.

## Team focus

Core pipeline is roughly 2–3 days of work for four people. The main remaining risk is whether the AI analysis is useful, so once the basic pipeline runs (around day 2), put two people on prompt design, context building and citation checking.
