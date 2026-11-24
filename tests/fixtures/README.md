# Test fixtures (tool runner)

- `fake_vol.py` — executable stand-in for `vol` used by executor tests (see its docstring).
- `sample_pstree.jsonl` — **SYNTHETIC** data in the shape of volatility3's `-r jsonl` renderer
  (leading blank line, one object per root, nested `__children`). It is NOT real volatility
  output; column names/values are made up.

TODO(forensics): add real captured outputs, e.g. `real_windows_pslist.jsonl`, produced with
`vol -q -r jsonl -f <image> <plugin> > file.jsonl` on a non-sensitive test image, and add parser
tests for them (see app/tools/volatility/README.md).
