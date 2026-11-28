# Captured volatility output

One file per plugin, named like the plugin file: the output of `windows.pslist.PsList` goes in
`windows/pslist.jsonl` (next to `plugins/windows/pslist.py`). The checks in
`tests/test_forensics_content.py` parse every file here and fail if a plugin's `compare_keys`
or `ai_context` columns don't appear in its output. Evaluation cases (`../evals/cases/`) load
these files as run output.

To capture one, run this on a test image that holds no real case data:

```bash
docker compose run --rm app vol -q -r jsonl -f /evidence/<image> windows.pslist.PsList \
    > forensics/fixtures/windows/pslist.jsonl
```

Then add a line below with the volatility version and where the image came from.

| File | Source | volatility3 |
|---|---|---|
| `windows/pstree.jsonl` | SYNTHETIC example, hand-written to mirror the format. TODO(forensics): replace with real output. | — |
| `windows/cmdline.jsonl` | SYNTHETIC example, hand-written to mirror the format. TODO(forensics): replace with real output. | — |
