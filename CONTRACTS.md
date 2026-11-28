> Written mainly for AI coding assistants. People: start with README.md or forensics/README.md.

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
  - `get_rows(session, run_id, offset=0, limit=100, q=None, annotated=False, tag=None,
    filters=None, sort=None, desc=False) -> tuple[list[ResultRow], int]` (delegates to results)
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
- `app/tools/volatility/guide.py`: `BASELINE: list[Step]`, `NEXT: dict[plugin, list[Step]]` —
  **TODO(forensics)**; EXAMPLE content. `Step` = `app.tools.base.GuideStep(plugin, reason,
  args={}, when="succeeded"|"has_rows"|"has_flags"|"tag:<tag>", priority=0)`.

### Investigation guide and recommendations
- `ToolRunner.guide() -> InvestigationGuide(baseline, next)` (default empty).
- `app/tools/guide.py`: `check_guide(runner) -> (valid guide with normalised args, [GuideProblem])`
  (invalid steps skipped), `to_markdown(runner)`, `main()` (CLI `python -m
  app.tools.volatility.guide`, exit 1 on problems), `describe_when`, `args_key`.
- `app/services/recommendations.py`: `recommend(session, evidence_id) -> Recommendations`
  (`items` best first, `dismissed`, `baseline_total/done`, `identified`, `guide_problems`;
  `as_dict()`), `dismiss` / `restore` (table `dismissed_recommendations`, migration 0012),
  `run_recommendation` (origin `RunOrigin.RECOMMENDED`), `run_baseline`, `step_key`.
  A step is done while a queued/running/succeeded run has the same plugin + normalised args.
- API `GET /api/evidence/{id}/recommendations`. UI: panel `#recommendations` on the image page
  (`/ui/evidence/{id}/recommendations[?all=1]`, POST `.../run|baseline|dismiss|restore`), page
  `/guide`. HTMX events: `runs-changed` (panel queued runs -> runs list reloads),
  `recommendations-changed` (runs queued from the query form -> panel reloads).
- Audit: `recommendation.dismiss|restore`, `evidence.run_baseline`, plus the usual `run.create`.
- System page check `guide`.

### Run recovery, limits and health
- `RunStatus.INTERRUPTED`: the app stopped during the run (startup recovery or graceful
  shutdown). User cancel stays `CANCELLED`. `Run.pid` (tool pid while running), `Run.rerun_of_id`.
- `app/jobs/worker.py`: `recover_interrupted_runs(session) -> int` (at startup: kill orphaned
  tool process group if its cwd is the run dir, keep/hash partial stdout and dumped files, audit
  `run.interrupted`; SUCCEEDED runs stuck in post-processing get a hook error + audit
  `run.hooks_interrupted`). Queued runs are left queued.
- `app/services/runs.py`: `rerun(session, run_id) -> Run`; `create_run`/`enqueue_auto` raise
  `DiskSpaceError` (API 507). `POST /api/runs/{id}/rerun`, UI `/ui/runs/{id}/rerun`.
- `app/services/resources.py`: `disk_status()`, `check_can_start_run()`, `hard_floor_problem()`.
  Settings `FT_MIN_FREE_DISK_BYTES`, `FT_MAX_DATA_BYTES`, `FT_HARD_MIN_FREE_DISK_BYTES`. The
  worker does not claim queued runs while `disk_status().problem` is set.
- `executor.execute(..., on_start=(pid, argv), should_stop=() -> reason|None)`;
  `ExecutionResult.stop_reason`. `PluginSpec.timeout_seconds` overrides `FT_RUN_TIMEOUT_SECONDS`.
- `app/services/health.py`: `quick_checks(session) -> list[Check]`, `run_volatility_test()`,
  `run_ai_test()`, `badge(session)`, `settings_summary()`. `app/api/system.py`:
  `GET /api/system/health`, `POST /api/system/health/{volatility,ai}`; UI `/system`.

### Catalog check, stall watchdog, run deletion, backups
- `ArgSpec.writes_files`, `PluginSpec.writes_files`, `PluginSpec.may_write_files`.
  `app/tools/volatility/runner.py`: `catalog_problems(plugins) -> {name: [problem]}`;
  `VolatilityRunner.plugins()` returns only valid entries, `.catalog_problems()` the rest
  (`ToolRunner.catalog_problems()` defaults to `{}`).
- Worker: one thread per run; `Worker.touch(run_id)` records progress (executor heartbeat, row
  ingest, before each hook via `hooks.run_hooks(..., on_progress=)`); `_watchdog()` gives up on
  runs idle for `FT_RUN_STALL_SECONDS` (audit `run.stalled` / `run.hooks_stalled`). `_finish`
  only updates a run that is still RUNNING.
- `Run.deleted_at`, `Run.delete_reason` (migration 0008). `app/services/run_deletion.py`:
  `preview`, `delete_run(session, run_id, reason)`, `delete_runs(session, evidence_id, reason,
  statuses)`, `cleanup_candidates`, `biggest_runs`. Audit `run.delete`. API
  `GET /api/runs/{id}/delete-preview`, `POST /api/runs/{id}/delete`,
  `POST /api/evidence/{id}/cleanup`; raw export of a deleted run is 410. Deleted runs are
  excluded from AI context, hook `latest_run`, follow-up and auto-enumerate de-duplication.
- `app/services/backup.py`: `create_backup(trigger)`, `list_backups`, `verify_backup`,
  `restore_backup`, `prune`, `last_anchor`, `BackupScheduler`, `hold_app_lock`. CLI
  `python -m app.backup`. Settings `FT_BACKUP_DIR`, `FT_BACKUP_INTERVAL_HOURS`,
  `FT_BACKUP_KEEP`. API `GET/POST /api/system/backups`, `POST /api/system/backups/{name}/verify`,
  `GET /api/system/biggest-runs`. Audit `backup.create|failed|prune|restore`.

### AI evaluation harness
- `evals/` (dev tooling, not shipped in the image): `python -m evals.run` (CLI), `evals/cases/*.yaml`
  (cases), `evals/scoring.py` (pure scoring/aggregation/baseline comparison), `evals/judge.py`
  (optional AI judge), `evals/baselines/<model>.json` (committed), `evals/reports/` (ignored).
- `app/ai/prompts.PROMPT_VERSION`: bump on any prompt/context change; stored in
  `AIMessage.params["prompt_version"]`, the `ai.*.request` audit event and eval reports.
- Manual GitHub workflow `.github/workflows/evals.yml` (provider from repo secrets).

### Large results
- `app/services/results.py`: `RowView` (q, annotated, tag, filters {column: expr}, sort, desc;
  `from_params` / `to_params` with URL keys `q`, `tag` ("*" = any annotation), `sort`, `desc`,
  `f.<column>`), `query_rows(session, run, view, offset, limit)`, `iter_view`,
  `export_rows(session, run, view, "csv"|"jsonl")`, `store_rows(...)` (worker ingest: columns +
  optional index), `index_run(session, run_id)`, `ColumnTracker`, `parse_filter`.
- `Run.columns` ([{name, type}] recorded at ingest), `Run.search_indexed`. FTS5 table
  `result_rows_fts` (rowid = result_rows.id) is created by migration 0006 and ignored by the ORM
  (`app/migrations/env.py` UNMANAGED_TABLE_PREFIXES).
- API: `GET /api/runs/{id}/rows` (+ `sort`, `desc`, `f.<column>`), `GET /api/runs/{id}/export?
  format=csv|jsonl|raw` (+ view params; audited key_read), `POST /api/runs/{id}/search-index`.
  UI: `/ui/runs/{id}/export?choice=csv:view|csv:all|jsonl:view|jsonl:all|raw`.
- Setting `FT_SEARCH_INDEX` (default false). Benchmark: `python -m scripts.bench_rows`.

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

### Case export
- `app/services/export.py`: `build_report(session, evidence_id=None) -> str` (deterministic
  Markdown; all evidence-sourced text escaped or fenced), `build_bundle(session, evidence_id=None,
  include_dumped=False) -> BundleResult` (ZIP: `report.md`, `manifest.json` with SHA-256 of every
  file, per-run `rows.csv` / `raw-output.jsonl` / optional `dumped/`; AES-encrypted with
  `artifact_zip_password` when dumped files are included), `record_export(...)` (audit
  `case.export`, KEY_READ, includes the report SHA-256).
- `app/api/export.py`: `GET /api/export?evidence_id=&format=md|zip&include_dumped=` ; UI `/ui/export`.
- `evidence_id=None` exports the whole investigation (all evidence + every case section);
  `case_id=` exports one case (`build_report/build_bundle(..., case_id=)`). Per-image reports add
  a labelled "Leads from linked evidence" section when the image is in a case.

### Cases and sharing
- Models `Case`, `CaseEvidence` (case_id, evidence_id, label; many-to-many), `SharedItem`
  (case_id, kind row|finding|note|ai_answer, source_evidence_id, source_key "R12:3"/"F12:hook/
  title"/"N7"/"A9", comment, source_sha256 at share time). `Note.case_id` (a note has exactly one
  of evidence_id / case_id), `NoteVersion.case_id`. Migration `0009_cases` moves global notes
  into a "General" case.
- `app/services/cases.py`: create/update/delete (empty only)/list, add_evidence, set_label,
  remove_evidence (un-shares its items), cases_for_evidence, member_evidence, labels.
- `app/services/sharing.py`: `share(session, case_id, kind, ...)`, `unshare`, `list_items`,
  `resolve(item) -> Resolved` (latest state: ok | changed | gone), `resolved_for_case`,
  `shared_keys`. Shared items are never part of AI context, hooks or another image's data.
- API `/api/cases` (CRUD, `/{id}/evidence`, `/{id}/shared`); notes API takes `case_id`.
- Indicators (migration `0010_indicators`): `Indicator` (case_id, type process|path|ip|domain|
  hash|registry|text, value, normalized, match_mode exact|contains, column, comment, source_key,
  checked_at) and `IndicatorHit` (indicator_id, run_id, evidence_id, row_idx, column, cell).
  `app/services/indicators.py`: `normalize`, `validate`, `guess_type`, `Matcher` (add new match
  modes/types here), `add_indicator`, `remove_indicator`, `match_run` (worker, after rows are
  stored), `check_case` / `start_case_check` (on demand, background), `hits`, `hit_counts`,
  `row_hits`. API `/api/cases/{id}/indicators` (GET/POST, DELETE `/{ind}`, POST `/check`,
  GET `/hits`). Hits are removed with their run's data, indicator or case membership; they never
  enter AI context or hooks.
- Comparison: `PluginSpec.compare_keys` / `compare_ignore` (catalog). `app/services/compare.py`:
  `default_settings`, `compare(session, run_a, run_b, keys=None, ignore=None) -> Comparison`
  (only_a, only_b, changed [(a, b, columns)], same, warnings), `to_csv`, `save` /
  `list_saved` / `delete_saved` / `recompute` (`SavedComparison`, migration `0011_comparisons`).
  UI `/cases/{id}/compare` (+ `.csv`); API `POST /api/cases/{id}/compare`,
  `/api/cases/{id}/comparisons` (GET/POST/DELETE). Both images must be in the case.
- UI: `/cases/{id}`; image and run pages take `?case=<id>` (active case; HTMX fragments read it
  from HX-Current-URL via `pages.request_case_id`); `/ui/share`, `/ui/shared/{id}/remove`.

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
  - Each citation dict (stored in `AIMessage.citations`): `key`, `run_id`, `row_idx`, `url`,
    `valid` (row exists), `support` (`supported` | `unsupported` | `unchecked` | `not_found`),
    `checked` and `unsupported_values` (typed values from the same sentence, see
    `extract_values`). Answers stored before this field have no `support`:
    `citation_status(c)` returns `not_checked` for them. Audit `ai.*.response` details include
    `unsupported_citations`; evals metric `citation_support`.
- `app/ai/suggestions.py`: `parse_suggestions(text) -> list[dict]`, `validate_suggestions(list) -> list[dict]`
- `app/ai/service.py`: `ask(session, evidence_id, question, run_ids=None, row_refs=None) -> AIMessage`,
  `summarize_run(session, run_id) -> AIMessage`,
  `recommend_next(session, evidence_id, focus="") -> AIMessage` ("what should I run next?";
  context `build_state_context`: runs, hook tags/findings, the guide's static and dismissed
  recommendations, up to 30 flagged rows; `context_refs["kind"] == "recommend"`; audit
  `ai.recommend.request|response`), `latest_recommendation(session, evidence_id)`.
- `Run.ai_message_id` (migration `0013_run_ai_message`): the AI answer whose suggestion started the
  run; only with origin `ai`, same evidence, assistant message (`runs.create_run(...,
  ai_message_id=)`, UI form field `ai_message_id`, API `RunCreate.ai_message_id`).
- `app/api/ai.py`: `/api/ai/...` (incl. `POST /api/ai/recommend {evidence_id, focus}`,
  `POST /api/ai/tasks {evidence_id, goal, max_steps?, max_seconds?}`, `GET /api/ai/tasks?evidence_id=`,
  `GET /api/ai/tasks/{id}`, `POST /api/ai/tasks/{id}/cancel`)
- `AIClient.chat(messages, tools=None)`: `AIResult.tool_calls` ([`ToolCall(id, name, arguments,
  raw_arguments)`]), `AIResult.reasoning` (`<think>` / `reasoning_content`, stripped from
  `content`), `AIError.status_code`.

### AI agent (goal tasks)
- `app/ai/agent.py`: `start_task(session, evidence_id, goal, max_steps=None, max_seconds=None,
  max_runs=None, approve_all=False) -> AITask` (background daemon thread,
  `FT_AGENT_MAX_CONCURRENT` at once; the slot is released while waiting), `run_task(task_id,
  client=None, slot=None)`, `cancel_task` (also cancels the task's queued/running runs and
  expires pending requests), `recover_tasks` (startup: active -> interrupted), `decide(session,
  request_id, "approve"|"edit"|"deny", args=None, note="")`, `approve_all_remaining`,
  `expire_requests`, `estimate_run_seconds(session, run) -> (seconds | None, samples)`,
  `run_requests_view`, `view(task, session=None) -> TaskView` (elapsed, paused, at-most-left,
  runs, `pending`, `polling`, `as_dict()`), `get_task`, `list_tasks`, `describe_call`,
  `QUEUE_RUN` tool spec. Protocol `FT_AI_TOOL_MODE` auto|native|text.
- Statuses: queued, running, awaiting_approval (clock paused), waiting_for_runs, done, failed,
  cancelled, interrupted. Limits `{"max_steps", "max_seconds", "max_runs"}`
  (`FT_AGENT_MAX_RUNS`=5; 0 = no queue_run tool).
- `queue_run` -> `AIRunRequest` (status pending | approved | edited | auto | denied | expired |
  failed; `final_args`, `note`, `decided_by`, `run_id`). Redundant runs (same plugin +
  normalised args queued/running/succeeded on the image) and over-limit requests are refused
  (not stored). Runs: `RunOrigin.AI_AGENT` ("agent", reserved: `POST /api/runs` refuses it) +
  `Run.ai_task_id` (`runs.create_run(..., ai_task_id=)`).
- `app/ai/agent_tools.py`: read-only `TOOLS` (`list_runs`, `search_rows`, `get_rows`,
  `get_findings`), `run_tool`, `describe_tools_for_text_protocol(extra)`.
- Models `AITask` / `AITaskStep` (0014), `AIRunRequest` + `AITask.approve_all` /
  `paused_seconds` + `Run.ai_task_id` + `AIMessage.reasoning` (0015).
- Audit: `ai.agent.start|tool (key_read)|approval|approve_all|answer|cancel|finish|interrupted`,
  plus `run.create` with `ai_task_id`.
- UI: chat form `mode=goal` (+ `max_steps`, `max_minutes`, `max_runs`, `approve_all`); card
  `/ui/ai/tasks/{id}` (polls every 2 s while active, not while showing approval forms),
  `POST /ui/ai/tasks/{id}/cancel`, `POST /ui/ai/tasks/{id}/approve-all`,
  `POST /ui/ai/run-requests/{id}/decide` (`action`, `note`, `arg_<name>` for edit). API:
  `POST /api/ai/tasks/{id}/approve-all`, `POST /api/ai/run-requests/{id} {action, args, note}`.
- `AIMessage.reasoning`: the model's `<think>` / reasoning text, saved for every AI answer,
  shown under Provenance and in the case export.
- `AIMessage.finish_reason` (migration `0017_ai_message_finish_reason`) / `AIResult.finish_reason`;
  `.truncated` = "length" (cut off by `FT_AI_MAX_TOKENS`): warning on the answer, in the export,
  as an agent step, and in `python -m app.ai.probe` reports.
- Restart: `AITask.state` checkpoint (messages, counters, the step in progress with its run
  requests) saved at each step; `recover_tasks(session, resume=True)` at startup re-queues
  active tasks and relaunches them (`resumed_count`, audit `ai.agent.resumed`);
  `create_app(start_worker=False)` uses `resume=False` (interrupted, requests expire).
- `app/ai/probe.py`: `python -m app.ai.probe` (provider check: plain answer, native tool call +
  round trip, text protocol, reasoning; JSON report, API key never printed), `python -m
  app.ai.probe task <id> [--with-reasoning]` (task summary).

### App settings
- `app/services/app_settings.py`: `EDITABLE` (`agent_max_steps`, `agent_max_seconds` (UI in
  minutes), `agent_max_runs`, `agent_max_concurrent`, `ai_tool_mode`), `get_value(key,
  session=None)` (database override else `get_settings()`), `list_settings`, `update(session,
  {key: ui_value})` (validates all first; audit `settings.update`), `reset` (audit
  `settings.reset`). Table `app_settings` (migration `0016_app_settings_task_state`).
- UI `/settings` (+ `POST /settings`, `POST /settings/{key}/reset`); API
  `GET/PUT /api/system/settings`, `DELETE /api/system/settings/{key}`.
- Evals: `goal:` cases (`agent`, `available_runs`; expectations `queue_plugins`,
  `forbid_plugins`, `max_queued`; metrics `expected_run_recall`, `runs_queued`, `agent_steps`).

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
