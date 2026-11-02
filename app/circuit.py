"""Circuit breaker for model providers, shared by all workers through the database.

    closed     normal. Consecutive failures are counted.
    open       after too many failures: calls fail at once, without touching the provider.
    half_open  after a cooldown: one trial call decides. Success closes it; failure reopens
               it with a longer cooldown.

A provider outage then costs one short pause instead of every worker burning its retries,
quota and job attempts against a service that can't answer. Jobs caught by an open circuit
are deferred without using up an attempt, because the outage isn't their fault.
"""
import os
import time

from . import db, obs

THRESHOLD = int(os.environ.get("CIRCUIT_THRESHOLD", 3))           # consecutive failed calls before opening
COOLDOWN = float(os.environ.get("CIRCUIT_COOLDOWN", 30))          # seconds; doubles each failed trial
MAX_COOLDOWN = float(os.environ.get("CIRCUIT_MAX_COOLDOWN", 300))
PROBE_SECONDS = 180                                               # if a trial call's worker dies, allow another

SCHEMA = """
CREATE TABLE IF NOT EXISTS circuits (
    name         TEXT PRIMARY KEY,
    state        TEXT NOT NULL,    -- closed | open | half_open
    failures     INTEGER NOT NULL,
    cooldown     REAL NOT NULL,
    opened_until REAL NOT NULL,
    updated_at   REAL NOT NULL
);
"""


class CircuitOpen(Exception):
    def __init__(self, name, retry_after):
        super().__init__(f"{name} is unavailable; pausing calls for {retry_after:.0f}s")
        self.name, self.retry_after = name, retry_after


def init():
    db.executescript(SCHEMA)


def _ensure(name):
    db.execute("INSERT OR IGNORE INTO circuits (name, state, failures, cooldown, opened_until, updated_at) "
               "VALUES (?, 'closed', 0, ?, 0, ?)", (name, COOLDOWN, time.time()))


def before_call(name):
    """Raises CircuitOpen unless this call may go ahead."""
    _ensure(name)
    now = time.time()
    # Atomic, so exactly one caller becomes the trial when the cooldown ends.
    probe = db.execute_returning("""UPDATE circuits SET state='half_open', opened_until=?, updated_at=?
                                    WHERE name=? AND state IN ('open', 'half_open') AND opened_until <= ? RETURNING name""",
                                 (now + PROBE_SECONDS, now, name, now))
    if probe:
        obs.inc("circuit_transitions", circuit=name, to="half_open")
        return
    row = db.query("SELECT state, opened_until FROM circuits WHERE name=?", (name,))[0]
    if row["state"] != "closed":
        raise CircuitOpen(name, max(row["opened_until"] - now, 1))


def on_failure(name):
    _ensure(name)
    now = time.time()
    before = db.query("SELECT state FROM circuits WHERE name=?", (name,))[0]["state"]
    row = db.execute_returning("""
        UPDATE circuits SET
            failures = failures + 1,
            cooldown = CASE WHEN state='half_open' THEN MIN(cooldown * 2, :max) ELSE cooldown END,
            opened_until = CASE
                WHEN state='half_open' THEN :now + MIN(cooldown * 2, :max)
                WHEN state='closed' AND failures + 1 >= :limit THEN :now + cooldown
                ELSE opened_until END,
            state = CASE WHEN state='half_open' OR failures + 1 >= :limit THEN 'open' ELSE state END,
            updated_at = :now
        WHERE name = :name RETURNING state""",
        {"max": MAX_COOLDOWN, "now": now, "limit": THRESHOLD, "name": name})
    if row and row["state"] == "open" and before != "open":
        obs.inc("circuit_transitions", circuit=name, to="open")


def on_success(name):
    """Any answer from the provider, including a refusal or a rejected request, shows it's reachable."""
    _ensure(name)
    before = db.query("SELECT state FROM circuits WHERE name=?", (name,))[0]["state"]
    db.execute("UPDATE circuits SET state='closed', failures=0, cooldown=?, opened_until=0, updated_at=? WHERE name=?",
               (COOLDOWN, time.time(), name))
    if before != "closed":
        obs.inc("circuit_transitions", circuit=name, to="closed")


def states():
    return db.query("SELECT name, state, failures, cooldown, opened_until FROM circuits ORDER BY name")
