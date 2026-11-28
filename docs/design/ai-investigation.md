> Written mainly for AI coding assistants. People: start with README.md or forensics/README.md.

# AI-assisted investigation: decisions

Three features, all built: (1) static "recommended next" plugins, (2) "Ask AI what to run next",
(3) goal-driven AI agent. Contracts: CONTRACTS.md "Investigation guide and recommendations",
"AI layer", "AI agent", "App settings".

## 1. Investigation guide (PR #19, migration 0012)
- BASELINE (ordered first pass) is SEPARATE from `auto_enumerate` (identification only).
- NEXT steps: "after plugin X succeeded, suggest Y", conditions `succeeded` / `has_rows` /
  `has_flags` / `tag:<tag>`, ranked by priority then number of suggesting runs.
- A step disappears once the same plugin+args is queued/running/succeeded; failed attempts keep it
  ("last attempt failed"). Other-OS steps hidden once the OS is known. Per-image dismiss.
- Content is EXAMPLE only; real content is forensics-team work. Checks: CLI, CI test, System and
  Guide pages; invalid steps skipped.

## 2. AI recommend button (PR #22, migration 0013)
- Dynamic plugin + exact options; validated like manual input; shown IN the AI chat history as
  an AI message with Run buttons.

## Value-level citation checks (PR #21, no migration)
- Check TYPED values only: IPs, paths, file names with extension, hex, quoted/backticked text,
  labelled numbers (PID/PPID/TID/port). Bare numbers ignored (usually counts/times).
- Per sentence, against all rows it cites + their direct tree parent/children.
- Separate "unsupported" warning state (link kept, wavy underline + note). Checked at answer time
  only, stored in the citations JSON. Evals metric `citation_support`.
- On a double error the template shows only the error; stored content is unchanged (audit hash /
  API compatibility).

## 3. Goal-driven agent (PRs #23, #24, then feat/ai-goal-misc; migrations 0014-0017)
- 3a read-only (searches past results); 3b queues runs with approvals; 3c settings page, restart
  resume, agent evals, provider probe.
- Native tool calling + text fallback (provider RIT GCCIS GenAI Manager, qwen3.6, emits
  `<think>`). Tasks live in the AI chat panel.
- Every agent run is marked `RunOrigin.AI_AGENT`. Approvals: Approve, Deny (optional note), Edit
  options first, Approve all remaining, or yes-to-all at task start. Yes-to-all excludes NOTHING
  (incl. `writes_files` plugins).
- Cancel task -> cancels its runs. Approval waiting does NOT count against the time limit;
  waiting for RUNS does. At the time limit, queued runs keep going. Pending approvals expire when
  the task ends. Redundant re-runs refused with a pointer to the existing run. Runs limit default
  5. Refused requests are not stored. "Start again" carries max_runs but not yes-to-all.
- Reasoning hidden in the UI but SAVED for all AI answers (provenance + export).
- Settings page `/settings`: agent defaults, concurrent tasks, tool protocol. DB overrides env,
  audited, Reset. Env stays authoritative for paths, provider and security settings.
- Restart = RESUME automatically: awaiting approval keeps waiting, waiting for runs keeps waiting,
  an AI call in progress is redone.
- Agent eval cases (`goal:`) use recorded fixtures per plugin (`available_runs`), auto-approved;
  expectations `queue_plugins` / `forbid_plugins` / `max_queued`.
- Not yet done: test against the real provider (`python -m app.ai.probe`, a real goal,
  `python -m app.ai.probe task <id>`); real eval cases and prompts (forensics team).

Code: `app/ai/agent.py`, `app/ai/agent_tools.py`, `app/ai/probe.py`,
`app/services/app_settings.py`, `app/web/agent_pages.py`, `app/web/settings_pages.py`.
Tests: test_ai_agent*.py, test_app_settings.py, test_ai_probe.py, test_evals.py.
