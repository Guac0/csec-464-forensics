> Written mainly for AI coding assistants. People: start with README.md or forensics/README.md.

# Multi-evidence (cases, sharing, indicators, comparison): decisions

Goal: investigations spanning several RAM images (before/after snapshots of one device, or
several devices hit by one actor). HARD RULE: each evidence item stays separate so
investigations are not poisoned; only deliberately chosen findings cross between images.

Principle: share POINTERS and INDICATORS, never data. Anything crossing between images carries
its origin (image, run, row, hash) and never enters another image's runs, rows, hook input, AI
context or report unless explicitly and visibly labelled.

## Options considered
- A. Don't build (global notes + two tabs). Rejected: tedious, invites uncontrolled copy-paste.
- B. Cases. BUILT (PR #15, migration 0009).
- C. Promoted/shared items within a case. BUILT (PR #15).
- D. Indicator watchlist per case. BUILT (PR #16, migration 0010).
- E. Comparison (diff) view. BUILT (PR #17, migration 0011).
- F. Multi-image AI session. NOT BUILT by decision: models conflate sources (poisoning risk).
  Only acceptable variant would be AI over shared items and indicator hits, never raw rows.
- G. Separate database per image. Rejected: large refactor.

## Cases (B)
- Optional; images outside any case work as before. An image can be in several cases (source
  images are read-only, so safe). Membership IS the link (no pairwise links). Optional per-case
  label per image ("before", "after", "laptop-2").
- Active case = how the image was opened: `?case=<id>` on image/run pages; HTMX fragments read it
  from HX-Current-URL.
- Global notes REPLACED by case notes (migration moved existing global notes into a "General"
  case containing every image, only if global notes existed).
- Cases can only be deleted when empty. AI context uses only the image's own notes.

## Sharing (C)
- Shareable: result rows, hook findings, image notes, AI answers (shown as labelled AI leads).
- Shares go to the ACTIVE case only; outside a case the dialog lists the image's cases.
- Shared items are pointers shown in their LATEST state ("changed since shared" / "source gone").
- Removing an image from a case un-shares what it shared there.
- Per-image reports get a separate labelled "Leads from linked evidence" section; there is also a
  case report.

## Indicators (D)
- One watchlist per case. Types: process, path, ip, domain, hash, registry, text.
- EXACT match by default, type-normalised (case-insensitive, `\`=`/` in paths, canonical IPs incl.
  zero-padded octets, a process name also matches a path ending in it). Per-indicator CONTAINS and
  "only in column X". Extensible via a Matcher class.
- New runs are checked automatically after rows are stored. Existing runs only on demand ("Check
  all images", background) because a full check reads every row.
- "+IOC" from any result row (type guessed). IOC marks on rows only for the active case.
- Hits removed with run deletion, image removal from the case, or indicator removal.

## Comparison (E)
- Two images of the SAME case, same plugin; default each image's latest succeeded run.
- Rows paired by key columns: catalog `compare_keys` + analyst override; without keys, all
  non-volatile columns. Volatile columns: built-in list (PID, PPID, offsets, times, threads,
  handles...) + catalog `compare_ignore`, overridable.
- Output: only in A, only in B, CHANGED (field diffs A->B), count of same. Computed live; CSV
  download; "Save to case" stores settings + counts + pinned runs, recomputed when opened.

## Known gaps
Real `compare_keys`/`compare_ignore` per plugin (forensics team); comparison is exact-value and
holds both runs' keys in memory (heavy for multi-million-row runs); indicators have no regex mode,
no watchlist import/export, and don't use per-plugin column knowledge.
