"""Consistent backups of the database and audit log, safe to run while the app is live.

    python -m app.backup [--dest /data/backups] [--keep 14]

Uses SQLite's backup API rather than copying the file, which could capture a half-written state.
Backups contain password hashes and encrypted MFA secrets, so they're owner-only. The MFA key is
deliberately not included: store it separately, because a backup is useless for MFA without it.
"""
import argparse
import os
import shutil
import sqlite3
import time
from pathlib import Path

from . import db
from .audit import LOG_PATH


def run(dest, keep):
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    target = dest / f"soc-{stamp}.db"
    source = sqlite3.connect(db.DB_PATH, timeout=30)
    copy = sqlite3.connect(target)
    with copy:
        source.backup(copy)
    source.close()
    copy.close()
    target.chmod(0o600)
    check = sqlite3.connect(target).execute("PRAGMA integrity_check").fetchone()[0]
    if check != "ok":
        target.unlink()
        raise SystemExit(f"Backup failed its integrity check: {check}")
    if LOG_PATH.exists():
        audit = dest / f"audit-{stamp}.jsonl"
        shutil.copy2(LOG_PATH, audit)
        audit.chmod(0o600)
    for pattern in ("soc-*.db", "audit-*.jsonl"):  # names sort by date, so the oldest come first
        for old in sorted(dest.glob(pattern))[:-keep]:
            old.unlink()
    return target


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dest", default=os.environ.get("SOC_BACKUP_DIR", "backups"))
    parser.add_argument("--keep", type=int, default=14, help="how many backups to keep")
    args = parser.parse_args()
    print(f"Saved {run(args.dest, max(args.keep, 1))}")


if __name__ == "__main__":
    main()
