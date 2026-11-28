> Written mainly for AI coding assistants. People: start with README.md or forensics/README.md.

# Test fixtures (tool runner)

- `fake_vol.py` — executable stand-in for `vol` used by executor tests (see its docstring).
- `sample_pstree.jsonl` — **SYNTHETIC** data in the shape of volatility3's `-r jsonl` renderer
  (leading blank line, one object per root, nested `__children`). It is NOT real volatility
  output; column names/values are made up.

- `sample_cmdline.jsonl` — SYNTHETIC, same idea.

These are infrastructure test data only. Real captured output belongs to the forensics team in
`forensics/fixtures/<os>/<module>.jsonl`, checked by tests/test_forensics_content.py.
