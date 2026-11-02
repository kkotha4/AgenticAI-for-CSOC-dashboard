"""Idempotent containment actions: the same action in the same run takes effect at most once.

Job delivery is at-least-once (step 3), so a retry can ask for an action that already happened.
Two layers handle the cases, because a worker can die at any moment:

    1. Our record: a finished action returns its saved result, with no approval and no new call.
    2. The downstream key: if a worker dies after the firewall acted but before we recorded it,
       our record is stuck at "started", so we must call again. Sending the same idempotency key
       lets the firewall recognize the repeat and do nothing. external_effects simulates that;
       real integrations need a vendor API that accepts such a key, or an action that's safe to repeat.

The key ignores the free-text reason, which a model may word differently on a retry.
"""
import hashlib
import json
import time

from . import db, tools

SCHEMA = """
CREATE TABLE IF NOT EXISTS actions (
    key        TEXT PRIMARY KEY,
    run_id     TEXT NOT NULL,
    tool       TEXT NOT NULL,
    target     TEXT NOT NULL,
    reason     TEXT,
    status     TEXT NOT NULL,     -- started | done | failed
    result     TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_actions_run ON actions(run_id, created_at);
CREATE TABLE IF NOT EXISTS external_effects (   -- stands in for the real firewall / EDR / identity system
    key        TEXT PRIMARY KEY,
    tool       TEXT NOT NULL,
    target     TEXT NOT NULL,
    applied_at REAL NOT NULL
);
"""


def init():
    db.executescript(SCHEMA)


def _target(args):
    return "|".join(str(v).strip().lower() for k, v in sorted(args.items()) if k != "reason")


def make_key(run_id, name, args):
    return hashlib.sha256(f"{run_id}|{name}|{_target(args)}".encode()).hexdigest()[:32]


def find_done(run_id, name, args):
    """The saved result if this action already finished in this run, else None."""
    rows = db.query("SELECT result FROM actions WHERE key=? AND status='done'", (make_key(run_id, name, args),))
    return json.loads(rows[0]["result"]) if rows else None


def _apply_downstream(key, name, target):
    """The simulated external system: a repeated idempotency key changes nothing."""
    db.execute("INSERT OR IGNORE INTO external_effects (key, tool, target, applied_at) VALUES (?, ?, ?, ?)",
               (key, name, target, time.time()))


def execute(run_id, name, args):
    key, target, now = make_key(run_id, name, args), _target(args), time.time()
    db.execute("""INSERT INTO actions (key, run_id, tool, target, reason, status, created_at, updated_at)
                  VALUES (?, ?, ?, ?, ?, 'started', ?, ?)
                  ON CONFLICT(key) DO UPDATE SET status='started', updated_at=excluded.updated_at WHERE status != 'done'""",
               (key, run_id, name, target, args.get("reason"), now, now))
    try:
        result = tools.run_tool(name, args)
        _apply_downstream(key, name, target)
    except Exception:
        db.execute("UPDATE actions SET status='failed', updated_at=? WHERE key=?", (time.time(), key))
        raise
    _mark_done(key, result)
    return result


def _mark_done(key, result):
    db.execute("UPDATE actions SET status='done', result=?, updated_at=? WHERE key=?",
               (json.dumps(result, sort_keys=True), time.time(), key))


def done_for_run(run_id):
    return [{"action": r["tool"], "target": r["target"], "reason": r["reason"]}
            for r in db.query("SELECT tool, target, reason FROM actions WHERE run_id=? AND status='done' ORDER BY created_at", (run_id,))]
