"""Two-level cache for slow, read-only tool calls (cache-aside pattern).

    L1  in-process dict      ~microseconds   private to one worker, lost on restart
    L2  shared DB table      ~milliseconds   shared by every worker, survives restarts
    origin (the real API)    ~hundreds of ms, costs money, rate-limited

Lookup order: L1 -> L2 -> origin. A miss fills both levels on the way back.

Invalidation: POST /api/cache/invalidate deletes matching L2 rows and publishes
"cache.invalidate"; every process drops its whole L1 when it hears it. If that
notification is lost (broker down), an L1 entry can be stale for at most
L1_MAX_TTL - the staleness is bounded by design.
"""
import json
import threading
import time
from collections import OrderedDict

from . import db, ratelimit, tools
from .bus import bus

L1_MAX_ENTRIES = 256   # LRU eviction beyond this
L1_MAX_TTL = 60        # cap on L1 lifetime, bounds staleness if an invalidation is missed

SCHEMA = """
CREATE TABLE IF NOT EXISTS tool_cache (
    key        TEXT PRIMARY KEY,         -- tool + normalized arguments
    tool       TEXT NOT NULL,
    value      TEXT NOT NULL,            -- JSON result
    expires_at REAL NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS cache_stats (
    tool    TEXT NOT NULL,
    outcome TEXT NOT NULL,               -- l1 | l2 | miss
    n       INTEGER NOT NULL DEFAULT 0,
    saved_s REAL NOT NULL DEFAULT 0,     -- origin latency avoided by hits
    PRIMARY KEY (tool, outcome)
);
"""

_l1: OrderedDict[str, tuple[float, dict]] = OrderedDict()  # key -> (expires_at, value)
_l1_lock = threading.Lock()
_inflight: dict[str, threading.Lock] = {}                   # single-flight: one origin call per key
_inflight_lock = threading.Lock()
_listener_started = False


def init():
    db.executescript(SCHEMA)


def make_key(name, args):
    # Normalize so "185.220.101.45" and " 185.220.101.45 " share an entry; sort_keys keeps it deterministic.
    norm = {k: v.strip().lower() if isinstance(v, str) else v for k, v in args.items()}
    return f"{name}:{json.dumps(norm, sort_keys=True)}"


def call(name, args):
    """Run a tool through the cache.

    Returns (result, meta). meta: cache = l1 | l2 | miss | None, ms = total time,
    throttled_ms = time spent waiting for the external API's rate limit.
    """
    start = time.perf_counter()
    policy = tools.CACHE_POLICY.get(name)
    if policy is None:  # not cacheable: always go to the source
        value, throttled = _origin(name, args)
        return value, {"cache": None, "ms": _ms(start), "throttled_ms": throttled}

    _ensure_listener()
    key = make_key(name, args)

    value = _l1_get(key)
    if value is not None:
        _count(name, "l1", tools.EXTERNAL_LATENCY[name])
        return value, {"cache": "l1", "ms": _ms(start), "throttled_ms": 0}

    # Single-flight: if three runs ask for the same IP at once, one fetches and two wait.
    with _key_lock(key):
        value, expires_at = _l2_get(key)
        if value is not None:
            _l1_put(key, value, expires_at)
            elapsed = _ms(start)
            # If we waited behind another caller's fetch (single-flight), we saved the API call but not the time.
            _count(name, "l2", max(0.0, tools.EXTERNAL_LATENCY[name] - elapsed / 1000))
            return value, {"cache": "l2", "ms": elapsed, "throttled_ms": 0}

        value, throttled = _origin(name, args)  # the expensive call
        ttl = policy["negative_ttl"] if tools.is_negative(value) else policy["ttl"]
        expires_at = time.time() + ttl
        _l2_put(key, name, value, expires_at)
        _l1_put(key, value, expires_at)
        _count(name, "miss", 0)
        return value, {"cache": "miss", "ms": _ms(start), "throttled_ms": throttled}


def _origin(name, args):
    """Call the real system, first waiting for its shared rate limit if it has one."""
    waited = 0.0
    if name in tools.ORIGIN_RATE_LIMITS:
        rate, burst = tools.ORIGIN_RATE_LIMITS[name]
        waited = ratelimit.acquire(f"origin:{name}", rate, burst)
    return tools.run_tool(name, args), round(waited * 1000)


def invalidate(indicator=None):
    """Drop cached entries mentioning `indicator` (or everything), in every process."""
    if indicator:
        term = indicator.strip().lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        n = db.execute("DELETE FROM tool_cache WHERE key LIKE ? ESCAPE '\\'", (f"%{term}%",))
    else:
        n = db.execute("DELETE FROM tool_cache")
    _l1_clear()
    bus.publish("cache.invalidate", {"indicator": indicator})
    return n


def stats():
    rows = db.query("SELECT tool, outcome, n, saved_s FROM cache_stats")
    by_outcome = {"l1": 0, "l2": 0, "miss": 0}
    saved = 0.0
    for r in rows:
        by_outcome[r["outcome"]] += r["n"]
        saved += r["saved_s"]
    lookups = sum(by_outcome.values())
    hits = by_outcome["l1"] + by_outcome["l2"]
    entries = db.query("SELECT tool, COUNT(*) AS n FROM tool_cache WHERE expires_at > ? GROUP BY tool", (time.time(),))
    return {**by_outcome, "lookups": lookups, "hit_ratio": round(hits / lookups, 2) if lookups else None,
            "origin_calls_avoided": hits, "seconds_saved": round(saved, 1),
            "entries": {e["tool"]: e["n"] for e in entries}}


# --- L1 (in-process LRU with TTL) ------------------------------------------

def _l1_get(key):
    with _l1_lock:
        item = _l1.get(key)
        if item is None:
            return None
        expires_at, value = item
        if expires_at < time.time():
            del _l1[key]
            return None
        _l1.move_to_end(key)  # mark as recently used
        return value


def _l1_put(key, value, expires_at):
    with _l1_lock:
        _l1[key] = (min(expires_at, time.time() + L1_MAX_TTL), value)
        _l1.move_to_end(key)
        while len(_l1) > L1_MAX_ENTRIES:
            _l1.popitem(last=False)  # evict least recently used


def _l1_clear():
    with _l1_lock:
        _l1.clear()


# --- L2 (shared table) -----------------------------------------------------

def _l2_get(key):
    rows = db.query("SELECT value, expires_at FROM tool_cache WHERE key=? AND expires_at > ?", (key, time.time()))
    return (json.loads(rows[0]["value"]), rows[0]["expires_at"]) if rows else (None, None)


def _l2_put(key, name, value, expires_at):
    db.execute("INSERT OR REPLACE INTO tool_cache (key, tool, value, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
               (key, name, json.dumps(value, sort_keys=True), expires_at, time.time()))


# --- helpers ---------------------------------------------------------------

def _key_lock(key):
    with _inflight_lock:
        return _inflight.setdefault(key, threading.Lock())


def _count(name, outcome, saved_s):
    db.execute("""INSERT INTO cache_stats (tool, outcome, n, saved_s) VALUES (?, ?, 1, ?)
                  ON CONFLICT(tool, outcome) DO UPDATE SET n = n + 1, saved_s = saved_s + excluded.saved_s""",
               (name, outcome, saved_s))


def _ms(start):
    return round((time.perf_counter() - start) * 1000, 1)


def _ensure_listener():
    """Background thread: drop L1 whenever any process invalidates."""
    global _listener_started
    with _l1_lock:
        if _listener_started:
            return
        _listener_started = True

    def listen():
        sub = bus.subscribe("cache.invalidate")
        while True:
            if sub.wait(timeout=None):
                sub.clear()
                _l1_clear()

    threading.Thread(target=listen, daemon=True, name="cache-invalidation").start()
