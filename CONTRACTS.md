# Module Contracts (Basic Version / PoC)

Single-user, local-workstation PoC: FastAPI + Jinja/HTMX UI + in-process job worker + SQLite,
running volatility3 against RAM images in a read-only `/evidence` mount.

**Infrastructure** (this scaffold) vs **forensics** (left to the human team, marked `TODO(forensics)`):
the scaffold provides the mechanisms (allowlist validation, argv building, subprocess execution,
generic output parsing, row storage, AI plumbing). The humans own the plugin catalog, presets,
auto-enumeration list, per-plugin parsing/summaries, OS detection and the analysis prompts.

## Frozen shared files (do not edit without team agreement)

- `app/config.py` — `Settings` / `get_settings()` (env prefix `FT_`)
- `app/db.py` — `Base`, `init_engine()`, `migrate()`, `alembic_config()`,
  `SessionLocal`, `get_session()`
- `app/migrations/versions/` — applied migrations are never edited; every change to
  `app/models.py` ships with a new migration in the same PR (see docs/DEVELOPMENT.md)
- `app/models.py` — `Evidence`, `Run`, `RunStatus`, `RunOrigin`, `ResultRow`, `Note`, `AIMessage`
- `app/tools/base.py` — `ToolRunner`, `PluginSpec`, `ArgSpec`, `ToolRequest`, `ParsedRow`,
  `ExecutionResult`, `ArgValidationError`
- `tests/conftest.py` — fixtures `settings`, `session`, `client`
- `pyproject.toml` dependencies

Citation key for a result row: `R{run_id}:{row_idx}` (e.g. `R12:34`).
HTML anchor for a row: `id="row-{run_id}-{row_idx}"`; link: `/runs/{run_id}?row={row_idx}#row-{run_id}-{row_idx}`.

## Ownership and public interfaces

### Backend core
- `app/main.py`: `create_app(start_worker: bool = True) -> FastAPI`. Lifespan: `init_engine()`,
  `migrate()`, recover stale runs, start/stop worker. Includes routers from
  `app.api.evidence`, `app.api.runs`, `app.api.notes`, `app.api.ai`, `app.web.pages`; mounts
  `app/web/static` at `/static`. `GET /health -> {"status": "ok"}`.
- `app/services/evidence.py`
  - `scan_evidence(session) -> list[Evidence]` — walk `settings.evidence_dir`, upsert by rel_path
  - `resolve_evidence_path(evidence: Evidence) -> Path` — safe join; raise `ValueError` on traversal
  - `hash_evidence(session, evidence_id) -> Evidence` — streaming SHA-256 (1 MiB chunks), cached
    by size+mtime; `start_hash_in_background(evidence_id) -> None`
- `app/services/runs.py`
  - `create_run(session, evidence_id, request: ToolRequest, origin: RunOrigin = MANUAL, tool="volatility3") -> Run`
    (validates via `get_runner(tool).validate`, raises `ArgValidationError`; status QUEUED)
  - `enqueue_auto(session, evidence_id) -> list[Run]` — one run per `PluginSpec.auto_enumerate`
  - `cancel_run(session, run_id) -> Run`
  - `create_run(..., *, parent_run_id=None, triggered_by_hook=None, chain_depth=0)` — follow-up
    provenance, used by hooks
  - `get_rows(session, run_id, offset=0, limit=100, q=None, annotated=False, tag=None) -> tuple[list[ResultRow], int]`
  - `annotation_tags(session, run_id) -> list[tuple[str, int]]`
- `app/services/notes.py`: `list_notes(session, evidence_id=None)`, `create_note(session, body, evidence_id=None)`,
  `update_note(session, note_id, body)`, `delete_note(session, note_id)`
- `app/jobs/worker.py`: `Worker` (start/stop, polls QUEUED runs, thread pool of
  `settings.max_concurrent_runs`, heartbeats, cancel via per-run `threading.Event`),
  `get_worker() -> Worker`, `recover_stale_runs(session) -> int`. Uses `app.tools.executor.execute`
  and `runner.parse_output`, inserting `ResultRow`s in batches, then `run_post_hooks()`.
- `app/api/{evidence,runs,notes}.py`: JSON API under `/api`.

### Tool runner (volatility mechanism)
- `app/tools/executor.py`:
  `execute(runner, evidence_path, request, run_dir, timeout, cancel_event, on_heartbeat=None) -> ExecutionResult`
  (no shell; stdout/stderr streamed to files in run_dir; kills process group on timeout/cancel)
- `app/tools/registry.py`: `get_runner(name: str = "volatility3") -> ToolRunner`, `available_tools() -> list[str]`
- `app/tools/volatility/runner.py`: `VolatilityRunner(ToolRunner)`
- `app/tools/volatility/plugins.py`: `PLUGINS: list[PluginSpec]` — **TODO(forensics)**; only example entries

### Derived artifacts (dumped files)
- `app/services/artifacts.py`: `register_run_outputs(session, run, output_dir)` (worker, after
  every run incl. failed ones), `list_for_run`, `get_artifact`, `artifact_path` (refuses paths
  outside `runs/<id>/output`), `guess_file_type`, `prepare_download(session, id, "zip"|"raw")`
  (re-checks SHA-256 -> `ArtifactIntegrityError`; audited as key_read).
- Model `DerivedArtifact` (+ `Run.artifacts`, `Run.artifact_count`); linked to the result row
  whose value names the file (`source_row_idx`).
- Executor: `execute(..., max_output_bytes=None)` stops the tool when `run_dir/output` grows past
  the limit (`ExecutionResult.output_limit_exceeded`); worker passes `FT_MAX_ARTIFACT_BYTES`.
- Hooks: `ctx.artifacts()`.
- API: `GET /api/runs/{id}/artifacts`, `GET /api/artifacts/{id}`,
  `GET /api/artifacts/{id}/download?format=zip|raw`. Settings `FT_MAX_ARTIFACT_BYTES`,
  `FT_ARTIFACT_ZIP_PASSWORD`.

### Evidence integrity
- `app/services/integrity.py`: `compute_hashes(path, should_stop, on_progress)`,
  `hash_evidence(session, evidence_id, *, kind, accept, run_id, ...)`, `status(ev)` (one of
  `not_hashed`, `hashed`, `matches_expected`, `mismatch`, `mismatch_acknowledged`, `changed`),
  `describe_problem(ev)`, `check_can_run(ev)`, `set_expected_hashes(...)`,
  `acknowledge_mismatch(session, evidence_id, reason)`, `list_checks(...)`,
  `prepare_for_run(session, run, ev, path, ...)`; exceptions `IntegrityError` (refused, -> 409),
  `IntegrityBlocked` (worker), `HashCancelled`.
- `runs.create_run` calls `check_can_run` (strict mode). The worker calls `prepare_for_run`
  before executing a tool; runs record `evidence_sha256/size_bytes/mtime`, `integrity_warning`,
  and `phase` while running.
- `evidence.hash_evidence(session, id)` = the analyst's "Verify" (accepts current content).
  Scans no longer clear hashes: they flag hashed images that changed (`changed_detected_at`).
- `integrity_checks` is append-only (triggers). Settings `FT_INTEGRITY_MODE` (strict|warn),
  `FT_VERIFY_ON_RUN`.
- API: `PATCH /api/evidence/{id}` (description, expected_*), `POST /api/evidence/{id}/verify`
  (alias `/hash`), `POST /api/evidence/{id}/acknowledge-mismatch`, `GET /api/evidence/{id}/integrity`.

### Audit log
- `app/services/audit.py` (frozen interface): `record(session, action, *, category, summary,
  object_type, object_id, evidence_id, details)`, `record_now(action, ...)`, `audit_context(...)`,
  `current_context()`, `list_events(...)`, `verify_chain(session)`, `verify_and_record(session)`,
  categories `CHANGE`/`KEY_READ`/`REQUEST`, `audit_requests_middleware`.
- **Rule:** every function that changes data calls `audit.record(...)` before its
  `session.commit()` (same transaction). Action names are `<object>.<verb>` (e.g. `note.edit`).
- Tables: `audit_events` and `note_versions` are append-only (DB triggers); `audit_head` holds the
  chain head. A migration that rebuilds these tables must recreate the triggers.
- `app/services/notes.py`: `list_versions(session, note_id)`; every create/edit/delete adds a
  `NoteVersion`.
- API: `GET /api/audit`, `GET /api/audit/verify`, `GET /api/notes/{id}/versions`.
  UI: `/activity`, `/notes/{id}/history`.
- Setting `FT_AUDIT_LEVEL` = `changes` | `key_reads` | `all` (temporary default `all`).

### Post-run hooks
- `app/tools/hooks.py` (engine, frozen interface): `@post_run(*plugins, tool, name, version)`,
  `HookContext` (`rows`, `latest_run`, `annotate`, `add_finding`, `update_evidence_metadata`,
  `queue_follow_up`), `run_hooks(session, run_id) -> list[dict]`, `load_hooks()`,
  `registered_hooks()`, `hooks_for(tool, plugin)`, `load_errors()`, `SEVERITIES`.
- `app/tools/volatility/hooks/*.py`: hook modules, auto-discovered — **TODO(forensics)**.
- Stored on `Run`: `hook_results`, `findings`, `parent_run_id`, `triggered_by_hook`, `chain_depth`;
  on `ResultRow`: `annotations`. `RunOrigin.HOOK` marks follow-up runs (not accepted from the API).
- API: `GET /api/hooks`, `POST /api/runs/{id}/hooks/rerun`, rows filter `?annotated=true&tag=`.

### AI layer
- `app/ai/client.py`: `AIClient(settings, transport=None).chat(messages, **overrides) -> AIResult`
- `app/ai/context.py`: `build_context(session, evidence_id, run_ids=None, row_refs=None) -> tuple[str, dict]`
- `app/ai/prompts.py`: system prompt templates — **TODO(forensics)** refine
- `app/ai/citations.py`: `extract_citations(text) -> list[str]`, `validate_citations(session, text) -> list[dict]`
- `app/ai/suggestions.py`: `parse_suggestions(text) -> list[dict]`, `validate_suggestions(list) -> list[dict]`
- `app/ai/service.py`: `ask(session, evidence_id, question, run_ids=None, row_refs=None) -> AIMessage`,
  `summarize_run(session, run_id) -> AIMessage`
- `app/api/ai.py`: `/api/ai/...`

### Web UI (temporary)
- `app/web/pages.py`: `router` (HTML pages, HTMX fragments), templates in `app/web/templates`,
  static in `app/web/static`. Calls the service functions above directly.

### DevOps
- `Dockerfile`, `docker-compose.yml`, `.dockerignore`, `.gitignore`, `.env.example`,
  `.pre-commit-config.yaml`, `.github/**`, `README.md`

## Additions agreed during implementation

- `app.main` also exposes a module-level `app = create_app()`; the Dockerfile uses `--factory`.
- Services raise `LookupError` for missing records (API -> 404) and `ValueError` for invalid input (-> 422).
- Extra service helpers: evidence `get_evidence`, `list_evidence`, `update_description`, `is_hashing`;
  runs `get_run`, `list_runs`; notes `get_note`. `list_notes(evidence_id=None)` returns ALL notes.
- `app.ai.service.get_messages(session, evidence_id) -> list[AIMessage]`; `NotFoundError` -> 404.
- Evidence context is sent to the model as a `user` message framed as data (never system role).
- `Settings.vol_offline` (`FT_VOL_OFFLINE`) passes `--offline` to volatility3.
- volatility3 global flags must precede the plugin name; the runner refuses catalog flags that collide
  with vol global flags (e.g. `--plugin-dirs`).
- UI POST endpoints reject cross-site requests (`Sec-Fetch-Site` / `Origin` check) since there is no login.
