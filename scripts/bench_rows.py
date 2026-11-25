"""Benchmark result-row storage and querying on a large synthetic run.

Usage (from the repo root, no Docker or volatility needed):

    python -m scripts.bench_rows --rows 200000

Creates a throwaway database in a temp dir, ingests SYNTHETIC filescan-like output through the
real parser and worker ingest code, then times typical results-page operations. Use it to check
that changes to ingest/search/paging don't make big runs slow.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path


def _timed(label: str, fn: Callable[[], object], results: list[tuple[str, float, str]]) -> object:
    start = time.perf_counter()
    out = fn()
    elapsed = time.perf_counter() - start
    note = ""
    if isinstance(out, tuple) and len(out) == 2 and isinstance(out[1], int):
        note = f"{out[1]} bytes" if label.startswith("CSV") else f"{out[1]} matching"
    results.append((label, elapsed, note))
    return out


def _export(session: object, run_id: int) -> tuple[None, int]:
    from app.models import Run
    from app.services import results as results_service

    run = session.get(Run, run_id)  # type: ignore[attr-defined]
    size = sum(
        len(c) for c in results_service.export_rows(session, run, results_service.RowView(), "csv")
    )  # type: ignore[arg-type]
    return None, size


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--rows", type=int, default=200_000)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument(
        "--search-index", action="store_true", help="store rows with FT_SEARCH_INDEX=true"
    )
    args = parser.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="ft-bench-"))
    for sub in ("evidence", "data", "symbols"):
        (tmp / sub).mkdir()
    (tmp / "evidence" / "bench.raw").write_bytes(b"\0" * 1024)
    os.environ.update(
        FT_EVIDENCE_DIR=str(tmp / "evidence"),
        FT_DATA_DIR=str(tmp / "data"),
        FT_SYMBOLS_DIR=str(tmp / "symbols"),
        FT_AUDIT_LEVEL="changes",
        FT_SEARCH_INDEX="true" if args.search_index else "false",
    )

    from app import db
    from app.jobs.worker import Worker
    from app.models import Run, RunStatus
    from app.services import evidence as evidence_service
    from app.services import runs as runs_service
    from app.tools.volatility.runner import VolatilityRunner

    db.init_engine()
    db.migrate()
    rng = random.Random(args.seed)  # noqa: S311 - synthetic data
    stdout = tmp / "stdout.jsonl"
    with stdout.open("w") as f:
        f.write("\n")
        for i in range(args.rows):
            row = {
                "Offset": 0xFFFF_A000_0000_0000 + i * 0x100,
                "Name": f"\\Device\\HarddiskVolume3\\Windows\\System32\\drv{i:06d}"
                f"\\{rng.choice(['svchost', 'lsass', 'explorer', 'notepad'])}.dll",
                "Size": rng.randint(0, 10_000_000),
                "__children": [],
            }
            f.write(json.dumps(row) + "\n")

    results: list[tuple[str, float, str]] = []
    with db.SessionLocal() as s:
        (ev,) = evidence_service.scan_evidence(s)
        run = Run(evidence_id=ev.id, plugin="windows.filescan.FileScan", status=RunStatus.RUNNING)
        s.add(run)
        s.commit()
        count = _timed(
            f"ingest {args.rows} rows",
            lambda: Worker._store_rows(s, run.id, VolatilityRunner(), stdout),
            results,
        )
        run.row_count = count  # type: ignore[assignment]
        run.status = RunStatus.SUCCEEDED
        s.commit()

        get_rows = runs_service.get_rows
        last_page = max(0, args.rows - 100)
        rid = run.id
        checks: list[tuple[str, Callable[[], object]]] = [
            ("first page", lambda: get_rows(s, rid, 0, 100)),
            ("last page (offset)", lambda: get_rows(s, rid, last_page, 100)),
            ("search 'svchost' (common)", lambda: get_rows(s, rid, 0, 100, q="svchost")),
            ("search 'drv123456' (rare)", lambda: get_rows(s, rid, 0, 100, q="drv123456")),
            ("search 'zz' (2 chars, scan)", lambda: get_rows(s, rid, 0, 100, q="zz")),
            (
                "filter Size > 9,900,000",
                lambda: get_rows(s, rid, 0, 100, filters={"Size": ">9900000"}),
            ),
            (
                "filter Name contains lsass",
                lambda: get_rows(s, rid, 0, 100, filters={"Name": "lsass"}),
            ),
            ("sort by Size desc", lambda: get_rows(s, rid, 0, 100, sort="Size", desc=True)),
            ("sort by Size, last page", lambda: get_rows(s, rid, last_page, 100, sort="Size")),
            ("CSV export, all rows", lambda: _export(s, rid)),
        ]
        for label, fn in checks:
            _timed(label, fn, results)

    size = (tmp / "data" / "forensics.db").stat().st_size
    width = max(len(r[0]) for r in results)
    print(f"\n{'operation':<{width}}  seconds  notes")
    for label, elapsed, note in results:
        print(f"{label:<{width}}  {elapsed:7.3f}  {note}")
    print(f"\ndatabase size: {size / 1e6:.1f} MB  ({tmp})")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    sys.exit(main())
