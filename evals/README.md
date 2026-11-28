# AI evaluation harness

Replays a fixed set of questions against **recorded** tool output and scores the AI's answers, so
prompt, context or model changes can be compared objectively instead of by feel.

Each attempt builds a throwaway database from the case's fixtures and goes through the **real**
pipeline (volatility output parser, context builder, prompts, AI client, citation and suggestion
validation), exactly as the app does. Nothing touches your real data.

## Running

```bash
pip install -e ".[dev]"
export FT_AI_BASE_URL=http://localhost:11434/v1 FT_AI_MODEL=llama3.1   # or put them in .env
python -m evals.run                          # all cases, 3 attempts each
python -m evals.run --cases pstree-parent-example --repeat 5
python -m evals.run --judge                  # also grade with an AI judge (see below)
python -m evals.run --model other-model      # try another model
```

Reports are written to `evals/reports/<time>-<model>.md` and `.json` (git-ignored) and the summary
is printed. Exit codes: 0 ok, 1 regression (with `--fail-on-regression`), 2 no matching cases,
3 every attempt failed with a provider error.

**GitHub:** the manual "AI evaluation" workflow (Actions tab > AI evaluation > Run workflow) runs
the same command with the provider from repository secrets. It first checks the provider
(`python -m app.ai.probe`, fails fast if unreachable), then runs the cases you pick (e.g. `agent`,
`recommend`, or all), puts the summary table on the run page and attaches the reports. Options:
model, cases, repeats, agent tool protocol, AI judge, fail on regression, and "save baseline"
(the new baseline is attached as an artifact: commit it to `forensics/evals/baselines/` in a PR). It never
runs on pull requests. Setup: secrets `FT_AI_BASE_URL`, `FT_AI_API_KEY`; variables `FT_AI_MODEL`,
optional `FT_AI_MAX_TOKENS` (default 8000 there) and `EVAL_RUNNER` (a self-hosted runner label
if the provider is only reachable from your network). Normal CI only unit-tests the scoring code
(`tests/test_evals.py`).

## What is measured

Deterministic checks (always), per attempt:

| Metric | Meaning |
|---|---|
| `pass` | every check below passed |
| `citation_validity` | cited row keys that exist / all citations (invented rows = 0) |
| `citation_support` | checked citations whose row(s) contain the values stated in the same sentence (PIDs, names, paths, IPs, ...) / checked citations |
| `expected_row_recall` | expected rows cited / expected rows |
| `cited_sentence_ratio` | sentences carrying a citation / sentences (rough: claims should be cited) |
| `mention_recall` | required terms present / required terms |
| `suggestion_validity` | suggested queries that pass the plugin allowlist / suggestions |
| `expected_query_recall` | expected queries (plugin + options) suggested / expected queries (`suggest_queries`) |
| `latency_s`, `total_tokens` | cost |

Checks that fail a case: an invented citation, a cited row that doesn't contain a value stated
next to it (see `forensics/citations.py`), an expected row not cited, too few citations, a
required term missing, a forbidden term present, no valid suggestion of an expected plugin, any
invalid suggestion.

**AI judge (optional, `--judge`):** a second model grades the answer 1-5 against the case's rubric,
seeing the question, the rows the answer cited, and the answer. It is noisier than the rule-based
checks and is reported separately as `judge_score`. Use `--judge-model` to use a different model
(ideally a stronger one) than the one under test.

Model output varies between runs, so every case runs several times (`--repeat`, default 3); the
report shows mean/min/max/stdev.

## Baselines and regressions

```bash
python -m evals.run --save-baseline          # writes forensics/evals/baselines/<model>.json
python -m evals.run --fail-on-regression     # exit 1 if a metric dropped vs that baseline
```

A **regression** is a quality metric whose mean dropped by more than `--threshold` (default 0.10,
i.e. 10 points; for `judge_score` 0.4 on the 1-5 scale). Reports also list new cases and cases
missing from the baseline. Save a new baseline when a change is an intended improvement, in the
same PR, so reviewers can see the before/after.

Every AI answer in the app and every report records a prompt version such as `p-3fa9c2d1`. It is
worked out automatically from the prompt files in `forensics/prompts/` and the app's fixed rules,
so it changes by itself whenever a prompt changes. Use it to tie scores and answers to the prompt
that produced them.

## Writing a case

One YAML file per case in `forensics/evals/cases/`. Use **real** captured `vol -r jsonl` output
from `forensics/fixtures/` (see the README there); the `*_example.yaml` cases use synthetic
fixtures and only demonstrate the format.

```yaml
id: pslist-unusual-parent          # unique; defaults to the file name
description: What this case checks
tags: [processes]                  # select with --cases processes
evidence:                          # optional
  rel_path: case.raw
  description: Workstation image from the CTF
  os_info: {os: windows, build: "19041"}
notes:                             # optional analyst notes (sent to the AI like in the app)
  - User reported a pop-up at login.
runs:                              # recorded tool output, in order (run index 0, 1, ...)
  - plugin: windows.pslist.PsList
    fixture: tests/fixtures/real/win10_pslist.jsonl
    args: {}
question: Which processes have a parent that is not in the list?   # or: summarize_run: 0
                                   # or: recommend: true / recommend: "<focus>" ("what next?")
                                   # or: goal: "<goal>" (AI agent; see "Agent cases" below)
expect:
  cite_rows: ["0:5"]               # "<run index>:<row index>" that must be cited
  must_mention: ["explorer.exe"]   # case-insensitive substrings
  must_not_mention: ["mimikatz"]   # e.g. things NOT in the data (would be invented)
  suggest_plugins: ["windows.pstree.PsTree"]   # optional: a valid suggestion must use one
  suggest_queries:                 # optional: each must be suggested (given args must match)
    - {plugin: windows.cmdline.CmdLine, args: {pid: [2000]}}
  min_citations: 1
judge:
  rubric: What a good answer contains and must not claim (used only with --judge).
```

Row indexes are the citation numbers you see in the app (`R<run>:<row>`) for a run of that
fixture: open the fixture in the app or count rows depth-first through `__children`.

Good cases are small and specific: one clear question, the rows that prove the answer, and terms
that would only appear if the model invented something.

## Agent cases (`goal:`)

A `goal:` case runs the AI agent with "yes to all". When the agent queues a plugin run, the
harness completes it at once from the case's recorded output in `available_runs` (matched by
plugin, and by the fixture's `args` if it gives any); a plugin not listed there fails with
"not available in this evaluation case". Extra keys:

```yaml
goal: Find out how explorer.exe (the process whose parent is missing) was started.
agent: {max_steps: 8, max_runs: 2, max_seconds: 600}   # optional limits
available_runs:                    # recorded output the agent may get by queuing a run
  - plugin: windows.cmdline.CmdLine
    fixture: tests/fixtures/real/win10_cmdline.jsonl
expect:
  queue_plugins: [windows.cmdline.CmdLine]   # must be queued
  forbid_plugins: [windows.pslist.PsList]    # must not be queued (e.g. already ran)
  max_queued: 2
  must_mention: ["explorer.exe"]             # plus the usual answer checks
```

Agent metrics: `expected_run_recall` (quality) and `runs_queued`, `agent_steps` (cost). The
JSON report also lists `queued_runs` per attempt. See `cases/agent_goal_example.yaml`.
