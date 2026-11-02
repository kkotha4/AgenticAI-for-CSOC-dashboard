"""Durable state: runs, their events, and approval decisions.

The database is the only thing the web server and the workers share. They run as
separate processes and never call each other directly: the server writes jobs and
approval decisions, workers write events, and each side reads what the other wrote.

SQLite now; the SQL is plain enough to move to Postgres for many concurrent writers.
The audit log (audit.py) stays separate: it is an append-only compliance record,
while these tables are operational state the app queries and updates.
"""
import json
import os
import sqlite3
import threading
import time
from pathlib import Path

# SOC_DB_PATH lets tests use their own database and never touch real data.
DB_PATH = Path(os.environ.get("SOC_DB_PATH", Path(__file__).resolve().parent.parent / "soc.db"))
_lock = threading.Lock()  # serializes writers inside one process; busy_timeout covers other processes

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id          TEXT PRIMARY KEY,
    alert_id    TEXT NOT NULL,
    mode        TEXT NOT NULL,
    status      TEXT NOT NULL,          -- queued | running | completed | failed
    verdict     TEXT,
    severity    TEXT,
    cost_usd    REAL NOT NULL DEFAULT 0, -- Claude spend for this run
    started_by  TEXT,                    -- the analyst who started it
    architecture TEXT NOT NULL DEFAULT 'single',  -- single | multi
    created_at  REAL NOT NULL,
    finished_at REAL
);
CREATE TABLE IF NOT EXISTS events (
    run_id  TEXT NOT NULL REFERENCES runs(id),
    seq     INTEGER NOT NULL,
    ts      REAL NOT NULL,
    kind    TEXT NOT NULL,
    data    TEXT NOT NULL,              -- full event as JSON
    PRIMARY KEY (run_id, seq)
);
CREATE TABLE IF NOT EXISTS approvals (
    run_id       TEXT NOT NULL REFERENCES runs(id),
    tool_use_id  TEXT NOT NULL,
    tool         TEXT NOT NULL,
    input        TEXT NOT NULL,
    status       TEXT NOT NULL,         -- pending | approved | denied | timed_out
    requested_at REAL NOT NULL,
    decided_at   REAL,
    decided_by   TEXT,                  -- the analyst who decided; NULL for a timeout
    PRIMARY KEY (run_id, tool_use_id)
);
CREATE TABLE IF NOT EXISTS checkpoints (
    run_id     TEXT PRIMARY KEY,
    step       INTEGER NOT NULL,    -- the last fully completed loop
    identity   TEXT NOT NULL,       -- provider, model and prompt it belongs to
    state      TEXT NOT NULL,       -- the conversation so far; deleted when the run ends
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS generated_alerts (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    id            TEXT UNIQUE,
    title         TEXT NOT NULL,
    source        TEXT NOT NULL,
    severity_hint TEXT NOT NULL,
    entities      TEXT NOT NULL,
    description   TEXT NOT NULL,
    fingerprint   TEXT NOT NULL,        -- identifies repeats of the same incident
    occurrences   INTEGER NOT NULL DEFAULT 1,
    scenario      TEXT,                 -- ground truth: never shown to the agent
    facts         TEXT NOT NULL,        -- ground truth: never shown to the agent
    created_at    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_generated_alerts_fp ON generated_alerts(fingerprint, created_at);
CREATE TABLE IF NOT EXISTS generated_logs (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    data       TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS generated_intel (
    kind TEXT NOT NULL,                 -- ip | domain | host
    key  TEXT NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (kind, key)
);
CREATE TABLE IF NOT EXISTS delegations (   -- finished specialist work, reused if the run retries
    key        TEXT PRIMARY KEY,
    run_id     TEXT NOT NULL,
    specialist TEXT NOT NULL,
    findings   TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_delegations_run ON delegations(run_id);
CREATE INDEX IF NOT EXISTS idx_runs_created ON runs(created_at DESC);
"""


def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)  # wait up to 10s if another process holds the write lock
    conn.row_factory = sqlite3.Row
    return conn


# --- generic helpers -------------------------------------------------------

def execute(sql, params=()):
    """Run one write. Returns the number of rows changed."""
    with _lock, _connect() as conn:
        return conn.execute(sql, params).rowcount


def execute_returning(sql, params=()):
    """Run one write with a RETURNING clause; returns the row as a dict, or None."""
    with _lock, _connect() as conn:
        row = conn.execute(sql, params).fetchone()
    return dict(row) if row else None


def executescript(sql):
    with _lock, _connect() as conn:
        conn.executescript(sql)


def query(sql, params=()):
    with _connect() as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


def init():
    with _lock, _connect() as conn:
        conn.execute("PRAGMA journal_mode=WAL")  # readers don't block the writer
        conn.executescript(SCHEMA)
    add_column_if_missing("runs", "cost_usd", "REAL NOT NULL DEFAULT 0")
    add_column_if_missing("runs", "started_by", "TEXT")
    add_column_if_missing("runs", "architecture", "TEXT NOT NULL DEFAULT 'single'")
    add_column_if_missing("approvals", "decided_by", "TEXT")


def add_column_if_missing(table, column, decl):
    """Tiny schema migration: CREATE TABLE IF NOT EXISTS never changes an existing table,
    so databases created by an earlier version need new columns added explicitly."""
    if column not in {r["name"] for r in query(f"PRAGMA table_info({table})")}:
        try:
            execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
        except sqlite3.OperationalError as e:
            if "duplicate column" not in str(e):  # another process starting up got there first
                raise


# --- runs ------------------------------------------------------------------

def create_run(run_id, alert_id, mode, started_by=None, architecture="single"):
    execute("INSERT INTO runs (id, alert_id, mode, status, started_by, architecture, created_at) VALUES (?, ?, ?, 'queued', ?, ?, ?)",
            (run_id, alert_id, mode, started_by, architecture, time.time()))


def set_run_status(run_id, status):
    execute("UPDATE runs SET status=? WHERE id=?", (status, run_id))


def finish_run(run_id, status, report=None):
    report = report or {}
    execute("UPDATE runs SET status=?, verdict=?, severity=?, finished_at=? WHERE id=?",
            (status, report.get("verdict"), report.get("severity"), time.time(), run_id))
    # A checkpoint holds tool output and model reasoning, so keep it no longer than it's useful.
    execute("DELETE FROM checkpoints WHERE run_id=?", (run_id,))
    execute("DELETE FROM delegations WHERE run_id=?", (run_id,))


def save_checkpoint(run_id, step, identity, state):
    execute("INSERT OR REPLACE INTO checkpoints (run_id, step, identity, state, updated_at) VALUES (?, ?, ?, ?, ?)",
            (run_id, step, identity, json.dumps(state), time.time()))


def load_checkpoint(run_id, identity):
    """Returns (step, state), or None. One from another model or prompt can't be resumed safely."""
    rows = query("SELECT step, state FROM checkpoints WHERE run_id=? AND identity=?", (run_id, identity))
    return (rows[0]["step"], json.loads(rows[0]["state"])) if rows else None


def add_run_cost(run_id, usd):
    execute("UPDATE runs SET cost_usd = cost_usd + ? WHERE id=?", (usd, run_id))


def spend_since(ts):
    return query("SELECT COALESCE(SUM(cost_usd), 0) AS s FROM runs WHERE created_at >= ?", (ts,))[0]["s"]


def list_runs(limit=50):
    return query("SELECT * FROM runs ORDER BY created_at DESC LIMIT ?", (limit,))


def get_run(run_id):
    rows = query("SELECT * FROM runs WHERE id=?", (run_id,))
    return rows[0] if rows else None


# --- events ----------------------------------------------------------------

def add_event(run_id, event):
    execute("INSERT INTO events (run_id, seq, ts, kind, data) VALUES (?, ?, ?, ?, ?)",
            (run_id, event["seq"], event["ts"], event["kind"], json.dumps(event, default=str)))


def next_seq(run_id):
    """A retried run continues numbering after the events its earlier attempt wrote."""
    return query("SELECT COALESCE(MAX(seq) + 1, 0) AS n FROM events WHERE run_id=?", (run_id,))[0]["n"]


def get_events(run_id, after=-1):
    rows = query("SELECT data FROM events WHERE run_id=? AND seq>? ORDER BY seq", (run_id, after))
    return [json.loads(r["data"]) for r in rows]


# --- approvals -------------------------------------------------------------

def request_approval(run_id, tool_use_id, tool, args):
    # REPLACE: if a retried attempt asks again, the old decision does not carry over - a human must re-approve.
    execute("INSERT OR REPLACE INTO approvals (run_id, tool_use_id, tool, input, status, requested_at) "
            "VALUES (?, ?, ?, ?, 'pending', ?)", (run_id, tool_use_id, tool, json.dumps(args), time.time()))


def decide_approval(run_id, tool_use_id, status, decided_by=None):
    """Returns True if a pending approval was found and decided."""
    return execute("UPDATE approvals SET status=?, decided_at=?, decided_by=? "
                   "WHERE run_id=? AND tool_use_id=? AND status='pending'",
                   (status, time.time(), decided_by, run_id, tool_use_id)) == 1


def get_approval(run_id, tool_use_id):
    rows = query("SELECT * FROM approvals WHERE run_id=? AND tool_use_id=?", (run_id, tool_use_id))
    return rows[0] if rows else None


def approval_status(run_id, tool_use_id):
    rows = query("SELECT status FROM approvals WHERE run_id=? AND tool_use_id=?", (run_id, tool_use_id))
    return rows[0]["status"] if rows else None
