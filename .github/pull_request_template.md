## What / why

<!-- One or two sentences. Link the issue: "Closes #123". -->

## How was this tested?

<!-- Commands you ran, screenshots of the UI if relevant. -->

## Checklist

- [ ] `pre-commit run --all-files` and `pytest -q` pass locally
- [ ] Tests use the fake `vol` fixture / recorded outputs in `tests/fixtures/` - **no real memory images**
- [ ] If fixtures were added: they are real volatility3 output (note image, plugin, vol version) and contain no sensitive data
- [ ] Touches the **argument allowlist / plugin catalog** (`app/tools/volatility/`)? If yes, a forensics owner reviewed it and every plugin/flag exists in the installed volatility3 version (`vol <plugin> -h`)
- [ ] Touches AI prompts (`app/ai/prompts.py`)? If yes, a forensics owner reviewed it
- [ ] New `FT_*` setting? Added to `.env.example` and the README config table
- [ ] No evidence, memory images, dumps, `.env` or secrets/API keys committed
- [ ] AI output provenance preserved: AI text stays labelled as AI-generated, citations (`R{run_id}:{row_idx}`) still link to stored result rows, AI output is never stored as tool output
- [ ] Frozen contract files (see `CONTRACTS.md`) unchanged, or the change was agreed by the team

## AI assistance

<!-- Optional: which parts were AI-generated and how you reviewed them. -->
