"""A durable job queue on top of the database.

Producer (the web server) enqueues; consumers (worker processes) claim jobs with a
time-limited lease and keep it alive with heartbeats. If a worker dies, its lease
expires and another worker picks the job up. Delivery is therefore at-least-once.

Swapping this for Redis/SQS/RabbitMQ means re-implementing these five functions.
"""
import os
import time

from . import db

LEASE_SECONDS = float(os.environ.get("LEASE_SECONDS", 30))  # how long a claim is valid without a heartbeat
MAX_ATTEMPTS = 3     # after this many failed attempts the job goes to the dead-letter state
MAX_DEFERRALS = 30   # how many times an outage can postpone a job before someone must look at it

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id           TEXT NOT NULL UNIQUE REFERENCES runs(id),
    alert_id         TEXT NOT NULL,
    mode             TEXT NOT NULL,
    status           TEXT NOT NULL,     -- queued | leased | done | dead
    priority         INTEGER NOT NULL DEFAULT 2,  -- 0 = most urgent; workers take lowest first
    attempts         INTEGER NOT NULL DEFAULT 0,
    deferrals        INTEGER NOT NULL DEFAULT 0,
    available_at     REAL NOT NULL,     -- earliest time a worker may claim it (used for retry backoff)
    lease_owner      TEXT,
    lease_expires_at REAL,
    last_error       TEXT,
    created_at       REAL NOT NULL,
    updated_at       REAL NOT NULL
);
"""


def init():
    db.executescript(SCHEMA)
    db.add_column_if_missing("jobs", "priority", "INTEGER NOT NULL DEFAULT 2")  # migrate before indexing it
    db.add_column_if_missing("jobs", "deferrals", "INTEGER NOT NULL DEFAULT 0")
    db.executescript("CREATE INDEX IF NOT EXISTS idx_jobs_claim ON jobs(status, priority, created_at);")


def depth():
    """Jobs waiting for a worker - the number backpressure decisions are based on."""
    return db.query("SELECT COUNT(*) AS n FROM jobs WHERE status='queued'")[0]["n"]


def enqueue(run_id, alert_id, mode, priority=2):
    now = time.time()
    db.execute("INSERT INTO jobs (run_id, alert_id, mode, status, priority, available_at, created_at, updated_at) "
               "VALUES (?, ?, ?, 'queued', ?, ?, ?, ?)", (run_id, alert_id, mode, priority, now, now, now))


def claim(worker_id):
    """Atomically take the oldest available job: queued, or leased by a worker that stopped heartbeating."""
    now = time.time()
    return db.execute_returning("""
        UPDATE jobs
           SET status='leased', lease_owner=?, lease_expires_at=?, attempts=attempts+1, updated_at=?
         WHERE id = (SELECT id FROM jobs
                      WHERE (status='queued' AND available_at <= ?)
                         OR (status='leased' AND lease_expires_at < ? AND attempts < ?)
                      ORDER BY priority, created_at LIMIT 1)   -- most urgent first, then oldest
        RETURNING *""", (worker_id, now + LEASE_SECONDS, now, now, now, MAX_ATTEMPTS))


def reap_poison():
    """Jobs whose workers died on every attempt. Without this, a job that kills workers would loop forever."""
    now, reaped = time.time(), []
    for row in db.query("SELECT id, run_id, alert_id, mode, attempts FROM jobs "
                        "WHERE status='leased' AND lease_expires_at < ? AND attempts >= ?", (now, MAX_ATTEMPTS)):
        if db.execute("UPDATE jobs SET status='dead', lease_owner=NULL, lease_expires_at=NULL, last_error=?, updated_at=? "
                      "WHERE id=? AND status='leased' AND attempts=?",
                      ("Workers died on every attempt.", now, row["id"], row["attempts"])) == 1:
            reaped.append(row)
    return reaped


def owns(job_id, worker_id, attempt):
    """Fencing check. The attempt number tells a stale worker apart even if it has the same name as the new one."""
    return bool(db.query("SELECT 1 FROM jobs WHERE id=? AND status='leased' AND lease_owner=? AND attempts=?",
                         (job_id, worker_id, attempt)))


def heartbeat(job_id, worker_id, attempt):
    """Extend the lease. Returns False if another worker has taken the job over."""
    now = time.time()
    return db.execute("UPDATE jobs SET lease_expires_at=?, updated_at=? WHERE id=? AND lease_owner=? AND attempts=? AND status='leased'",
                      (now + LEASE_SECONDS, now, job_id, worker_id, attempt)) == 1


def complete(job, worker_id):
    """Returns False if this worker no longer owns the job, so it must not record a result."""
    return db.execute("UPDATE jobs SET status='done', lease_owner=NULL, lease_expires_at=NULL, updated_at=? "
                      "WHERE id=? AND lease_owner=? AND attempts=?", (time.time(), job["id"], worker_id, job["attempts"])) == 1


def defer(job, worker_id, delay, error):
    """Put a job back until an outage may be over, without using an attempt. False once it's been postponed too often."""
    if job["deferrals"] >= MAX_DEFERRALS:
        return False
    now = time.time()
    db.execute("""UPDATE jobs SET status='queued', attempts=attempts-1, deferrals=deferrals+1, available_at=?,
                  lease_owner=NULL, lease_expires_at=NULL, last_error=?, updated_at=? WHERE id=? AND lease_owner=? AND attempts=?""",
               (now + delay, error[:500], now, job["id"], worker_id, job["attempts"]))
    return True


def fail(job, worker_id, error, force_dead=False):
    """Retry with backoff, or dead-letter the job once it has used all its attempts."""
    dead = force_dead or job["attempts"] >= MAX_ATTEMPTS
    backoff = 2 ** job["attempts"]  # visible again after 2s, 4s, ...
    db.execute("""UPDATE jobs SET status=?, available_at=?, lease_owner=NULL, lease_expires_at=NULL,
                  last_error=?, updated_at=? WHERE id=? AND lease_owner=? AND attempts=?""",
               ("dead" if dead else "queued", time.time() + backoff, error[:500], time.time(), job["id"], worker_id, job["attempts"]))
    return dead


def stats():
    now = time.time()
    rows = db.query("SELECT status, COUNT(*) AS n FROM jobs GROUP BY status")
    workers = db.query("SELECT DISTINCT lease_owner FROM jobs WHERE status='leased' AND lease_expires_at > ? AND lease_owner IS NOT NULL", (now,))
    counts = {r["status"]: r["n"] for r in rows}
    return {s: counts.get(s, 0) for s in ("queued", "leased", "done", "dead")} | {"busy_workers": [w["lease_owner"] for w in workers]}
