"""Token-bucket rate limiter, shared by every process through the database.

A bucket holds up to `burst` tokens and refills at `rate` tokens per second.
Each request spends one token; with none left, the caller is told how long to wait.
This allows short bursts while enforcing an average rate.

Because the bucket lives in the database and is updated in one atomic statement,
the limit holds across all workers and server processes - a *distributed* rate limit.
(In production this is usually a Redis Lua script; the arithmetic is the same.)
"""
import time

from . import db

SCHEMA = """
CREATE TABLE IF NOT EXISTS rate_buckets (
    name       TEXT PRIMARY KEY,   -- e.g. "client:127.0.0.1", "origin:lookup_ip_reputation"
    tokens     REAL NOT NULL,
    updated_at REAL NOT NULL
);
"""


class RateLimited(Exception):
    def __init__(self, retry_after):
        super().__init__(f"rate limited, retry after {retry_after:.1f}s")
        self.retry_after = retry_after


def init():
    db.executescript(SCHEMA)


def try_acquire(name, rate, burst, cost=1.0):
    """Take `cost` tokens if available. Returns 0.0 on success, else seconds until enough tokens exist."""
    now = time.time()
    db.execute("INSERT OR IGNORE INTO rate_buckets (name, tokens, updated_at) VALUES (?, ?, ?)", (name, burst, now))
    # Refill-and-spend in ONE statement, so two processes can never both spend the last token.
    took = db.execute_returning("""
        UPDATE rate_buckets
           SET tokens = MIN(:burst, tokens + (:now - updated_at) * :rate) - :cost, updated_at = :now
         WHERE name = :name AND MIN(:burst, tokens + (:now - updated_at) * :rate) >= :cost
        RETURNING tokens""", {"burst": burst, "now": now, "rate": rate, "cost": cost, "name": name})
    if took is not None:
        return 0.0
    row = db.query("SELECT tokens, updated_at FROM rate_buckets WHERE name=?", (name,))[0]
    available = min(burst, row["tokens"] + (now - row["updated_at"]) * rate)
    return (cost - available) / rate


def acquire(name, rate, burst, max_wait=30.0):
    """Block until a token is available (outbound calls: wait our turn). Returns seconds waited."""
    start = time.time()
    while True:
        wait = try_acquire(name, rate, burst)
        if wait == 0.0:
            return time.time() - start
        if time.time() - start + wait > max_wait:
            raise RateLimited(wait)
        time.sleep(min(wait, 1.0))
