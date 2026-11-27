"""Command line for backups: ``python -m app.backup create|list|verify|restore``.

In Docker (backups go to the forensics-backups volume at /backups):

    docker compose exec app python -m app.backup create
    docker compose exec app python -m app.backup list
    docker compose exec app python -m app.backup verify <name>
    # restore needs the app stopped:
    docker compose stop app
    docker compose run --rm app python -m app.backup restore <name>
    docker compose start app
"""

from __future__ import annotations

import argparse
import sys

from app.services import backup
from app.services.resources import fmt_bytes


def _setup() -> None:
    from app import db

    db.init_engine()
    db.migrate()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m app.backup", description=__doc__.split("\n")[0]
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("create", help="make a backup now (safe while the app is running)")
    sub.add_parser("list", help="list backups in FT_BACKUP_DIR")
    v = sub.add_parser("verify", help="check a backup's hashes, database and audit chain")
    v.add_argument("backup", help="backup file name (in FT_BACKUP_DIR) or path")
    r = sub.add_parser("restore", help="replace the case data with a backup (app stopped)")
    r.add_argument("backup", help="backup file name (in FT_BACKUP_DIR) or path")
    r.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    args = parser.parse_args(argv)

    try:
        if args.cmd == "create":
            _setup()
            info = backup.create_backup("cli")
            print(f"created {info.path} ({fmt_bytes(info.size_bytes)})")
        elif args.cmd == "list":
            items = backup.list_backups()
            if not items:
                print(f"no backups in {backup.backup_dir()}")
            for b in items:
                print(f"{b.name}  {fmt_bytes(b.size_bytes):>10}  {b.trigger}")
        elif args.cmd == "verify":
            report = backup.verify_backup(args.backup)
            print(f"{report.name}: {'OK' if report.ok else 'FAILED'}")
            print(f"  files checked: {report.files}, audit events: {report.audit_events}")
            for p in report.problems:
                print(f"  problem: {p}")
            return 0 if report.ok else 1
        elif args.cmd == "restore":
            if not args.yes:
                answer = input(
                    f"Replace the case data with {args.backup}? The current database and raw "
                    "outputs are moved to a pre-restore-* folder. [y/N] "
                )
                if answer.strip().lower() not in ("y", "yes"):
                    print("cancelled")
                    return 1
            res = backup.restore_backup(args.backup)
            print(f"restored {res.backup}: {res.files_restored} files")
            if res.moved_aside_to:
                print(f"  previous data moved to {res.moved_aside_to}")
            print(
                f"  dumped files: {res.dumped_ok} ok, {res.dumped_missing} missing "
                f"(re-run the plugin), {res.dumped_mismatch} changed (downloads refused)"
            )
    except (backup.BackupError, LookupError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
