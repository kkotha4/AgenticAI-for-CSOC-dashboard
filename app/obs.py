"""Observability: structured logs, metrics and traces.

    Logs     what happened, as JSON lines tagged with the run they belong to (logs/<component>.jsonl)
    Metrics  how much and how often: counters in hourly buckets, exported at /metrics
    Traces   where one investigation's time went: spans sharing the run id as their trace id

Two rules:
- Telemetry must never break the agent, so every write swallows and logs its own errors.
- Telemetry holds names and numbers only. Tool arguments, tool output and prompts stay out,
  because emails and logs contain attacker text and personal data. The events table and
  audit log are the access-controlled record of content.

Metric labels must have a small, fixed set of values (never users, IPs or raw model output),
or storage and dashboards blow up. In production this would be OpenTelemetry exporting to
Prometheus and Grafana; the concepts and span shape carry over.
"""
import json
import logging
import logging.handlers
import os
import re
import statistics
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

from . import db

log = logging.getLogger("obs")
LOG_DIR = Path(os.environ.get("SOC_LOG_DIR", Path(__file__).resolve().parent.parent / "logs"))
RETENTION_SECONDS = 30 * 86400
QUEUE_STALL_SECONDS = float(os.environ.get("QUEUE_STALL_SECONDS", 60))

_run = ContextVar("obs_run", default=None)
_span = ContextVar("obs_span", default=None)
SECRET = re.compile(r"(AIza[\w-]{20,}|sk-ant-[\w-]+|soc_svc_[\w-]+|soc_inv_[\w-]+|(?<=key=)[\w-]{10,})")

SCHEMA = """
CREATE TABLE IF NOT EXISTS metrics (
    name   TEXT NOT NULL,
    labels TEXT NOT NULL,          -- sorted JSON
    hour   INTEGER NOT NULL,       -- start of the hour; buckets give "last 24h" views and easy retention
    value  REAL NOT NULL,
    PRIMARY KEY (name, labels, hour)
);
CREATE TABLE IF NOT EXISTS spans (
    span_id   TEXT PRIMARY KEY,
    run_id    TEXT NOT NULL,       -- trace id: everything in one investigation shares it
    parent_id TEXT,
    name      TEXT NOT NULL,
    start_ts  REAL NOT NULL,
    end_ts    REAL NOT NULL,
    status    TEXT NOT NULL,       -- ok | error
    attrs     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_spans_run ON spans(run_id, start_ts);
CREATE INDEX IF NOT EXISTS idx_spans_time ON spans(name, start_ts);
"""


def init(prune=False):
    db.executescript(SCHEMA)
    if prune:
        cutoff = time.time() - RETENTION_SECONDS
        db.execute("DELETE FROM spans WHERE start_ts < ?", (cutoff,))
        db.execute("DELETE FROM metrics WHERE hour < ?", (cutoff,))


# --- metrics ---------------------------------------------------------------

def inc(name, value=1, /, **labels):
    try:
        db.execute("""INSERT INTO metrics (name, labels, hour, value) VALUES (?, ?, ?, ?)
                      ON CONFLICT(name, labels, hour) DO UPDATE SET value = value + excluded.value""",
                   (name, json.dumps(labels, sort_keys=True, default=str), int(time.time()) // 3600 * 3600, value))
    except Exception:
        log.exception("could not record metric %s", name)


# --- traces ----------------------------------------------------------------

def set_run(run_id):
    """Tag everything this thread does from now on with this run: spans and log lines."""
    _run.set(run_id)
    _span.set(None)


def record_span(name, start_ts, end_ts, run_id=None, status="ok", **attrs):
    run_id = run_id or _run.get()
    if not run_id:
        return
    try:
        db.execute("INSERT INTO spans (span_id, run_id, parent_id, name, start_ts, end_ts, status, attrs) "
                   "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                   (uuid.uuid4().hex[:12], run_id, _span.get(), name, start_ts, end_ts, status,
                    json.dumps(attrs, default=str)))
    except Exception:
        log.exception("could not record span %s", name)


@contextmanager
def span(name, **attrs):
    """Time a block. Yields attrs so the block can add results. Exceptions are recorded and re-raised."""
    span_id, parent, start, status = uuid.uuid4().hex[:12], _span.get(), time.time(), "ok"
    token = _span.set(span_id)
    try:
        yield attrs
    except Exception as e:
        status = "error"
        attrs["error"] = type(e).__name__
        raise
    finally:
        _span.reset(token)
        run_id = _run.get()
        if run_id:
            try:
                db.execute("INSERT INTO spans (span_id, run_id, parent_id, name, start_ts, end_ts, status, attrs) "
                           "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                           (span_id, run_id, parent, name, start, time.time(), status, json.dumps(attrs, default=str)))
            except Exception:
                log.exception("could not record span %s", name)


def trace(run_id):
    rows = db.query("SELECT * FROM spans WHERE run_id=? ORDER BY start_ts", (run_id,))
    for row in rows:
        row["attrs"] = json.loads(row["attrs"])
    return rows


# --- logs ------------------------------------------------------------------

def redact(text):
    return SECRET.sub("[REDACTED]", str(text))


class JsonFormatter(logging.Formatter):
    def __init__(self, component):
        super().__init__()
        self.component = component

    def format(self, record):
        entry = {"ts": round(record.created, 3), "level": record.levelname, "component": self.component,
                 "logger": record.name, "msg": redact(record.getMessage()), "run_id": _run.get(), "span_id": _span.get()}
        if record.exc_info:
            entry["exception"] = redact(self.formatException(record.exc_info))
        return json.dumps(entry)


def configure_logging(component, console=True):
    """JSON lines to a per-process file for machines, readable lines on the console for people."""
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(LOG_DIR / f"{component}.jsonl", maxBytes=5_000_000, backupCount=3)
    handler.setFormatter(JsonFormatter(component))
    root.addHandler(handler)
    if console:
        stream = logging.StreamHandler()
        stream.setFormatter(logging.Formatter(f"%(asctime)s [{component}] %(message)s", datefmt="%H:%M:%S"))
        root.addHandler(stream)
    else:  # uvicorn keeps its own console output and doesn't pass records to the root logger
        for name in ("uvicorn", "uvicorn.access"):
            logging.getLogger(name).addHandler(handler)


# --- reading ---------------------------------------------------------------

def _percentile(values, p):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * p))]


def _latency(name, since):
    rows = db.query("SELECT end_ts - start_ts AS d FROM spans WHERE name=? AND start_ts >= ?", (name, since))
    values = [r["d"] for r in rows]
    return {"count": len(values), "p50": _percentile(values, 0.5), "p95": _percentile(values, 0.95)}


def _counters(since):
    rows = db.query("SELECT name, labels, SUM(value) AS v FROM metrics WHERE hour >= ? GROUP BY name, labels",
                    (int(since) // 3600 * 3600,))
    out = {}
    for row in rows:
        out.setdefault(row["name"], []).append({"labels": json.loads(row["labels"]), "value": row["v"]})
    return out


def _sum(counters, name, **match):
    return sum(c["value"] for c in counters.get(name, [])
               if all(c["labels"].get(k) == v for k, v in match.items()))


def _models(since):
    """Per-model totals from saved run events, so runs from before tracing was added still count."""
    rows = db.query("""SELECT run_id, json_extract(data, '$.model') AS model, COUNT(*) AS calls,
                                SUM(json_extract(data, '$.input')) AS input, SUM(json_extract(data, '$.output')) AS output,
                                SUM(json_extract(data, '$.cost_usd')) AS cost
                         FROM events WHERE kind='usage' AND ts >= ? GROUP BY run_id, model""", (since,))
    models = {}
    for row in rows:
        m = models.setdefault(row["model"] or "unknown", {"model": row["model"] or "unknown", "runs": 0, "calls": 0, "max_loops": 0,
                                                          "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0})
        m["runs"] += 1
        m["calls"] += row["calls"]
        m["max_loops"] = max(m["max_loops"], row["calls"])
        m["input_tokens"] += row["input"] or 0
        m["output_tokens"] += row["output"] or 0
        m["cost_usd"] += row["cost"] or 0
    for m in models.values():
        m["avg_loops"] = m["calls"] / m["runs"]  # each model call drives one loop iteration
    return sorted(models.values(), key=lambda m: -m["calls"])


def _agents(since):
    """Each agent's share of the work in multi-agent runs. Older runs carry no agent label."""
    rows = db.query("""SELECT json_extract(data, '$.agent') AS agent, COUNT(*) AS calls, COUNT(DISTINCT run_id) AS runs,
                                SUM(json_extract(data, '$.input')) AS input, SUM(json_extract(data, '$.output')) AS output,
                                SUM(json_extract(data, '$.cost_usd')) AS cost
                         FROM events WHERE kind='usage' AND ts >= ? AND json_extract(data, '$.agent') IS NOT NULL
                         GROUP BY agent ORDER BY calls DESC""", (since,))
    tools_used = {r["agent"]: r["n"] for r in db.query(
        """SELECT json_extract(data, '$.agent') AS agent, COUNT(*) AS n FROM events
           WHERE kind='act' AND ts >= ? AND json_extract(data, '$.agent') IS NOT NULL GROUP BY agent""", (since,))}
    return [{"agent": r["agent"], "runs": r["runs"], "calls": r["calls"], "tool_calls": tools_used.get(r["agent"], 0),
             "input_tokens": r["input"] or 0, "output_tokens": r["output"] or 0, "cost_usd": r["cost"] or 0} for r in rows]


def _architectures(since):
    """Single vs multi-agent, on completed runs only. Duration excludes time waiting for humans."""
    runs = db.query("SELECT id, architecture, mode, cost_usd, created_at, finished_at FROM runs "
                    "WHERE status='completed' AND created_at >= ? AND finished_at IS NOT NULL", (since,))
    calls = {r["run_id"]: r for r in db.query(
        "SELECT run_id, SUM(kind='usage') AS model_calls, SUM(kind='act') AS tool_calls FROM events WHERE ts >= ? GROUP BY run_id", (since,))}
    waits = {r["run_id"]: r["w"] or 0 for r in db.query(
        "SELECT run_id, SUM(end_ts - start_ts) AS w FROM spans WHERE name='approval.wait' AND start_ts >= ? GROUP BY run_id", (since,))}
    groups = {}
    for run in runs:
        g = groups.setdefault((run["architecture"], run["mode"]), {"architecture": run["architecture"], "mode": run["mode"], "runs": 0, "model_calls": 0, "tool_calls": 0, "cost_usd": 0.0, "seconds": 0.0})
        c = calls.get(run["id"], {})
        g["runs"] += 1
        g["model_calls"] += c.get("model_calls") or 0
        g["tool_calls"] += c.get("tool_calls") or 0
        g["cost_usd"] += run["cost_usd"] or 0
        g["seconds"] += max(run["finished_at"] - run["created_at"] - waits.get(run["id"], 0), 0)
    return [{**g, "avg_model_calls": g["model_calls"] / g["runs"], "avg_tool_calls": g["tool_calls"] / g["runs"],
             "avg_cost_usd": g["cost_usd"] / g["runs"], "avg_seconds": g["seconds"] / g["runs"]}
            for _, g in sorted(groups.items())]


def _recent_runs(limit=50):
    runs = db.query("SELECT id, alert_id, mode, status, verdict, cost_usd, started_by, architecture, created_at, finished_at "
                    "FROM runs ORDER BY created_at DESC LIMIT ?", (limit,))
    if not runs:
        return runs
    marks = ",".join("?" for _ in runs)
    ids = [r["id"] for r in runs]
    counts = {r["run_id"]: r for r in db.query(
        f"SELECT run_id, SUM(kind='step') AS loops, SUM(kind='start') AS attempts FROM events WHERE run_id IN ({marks}) GROUP BY run_id", ids)}
    models = {}
    for r in db.query(f"SELECT DISTINCT run_id, json_extract(data, '$.model') AS model FROM events WHERE kind='usage' AND run_id IN ({marks})", ids):
        models.setdefault(r["run_id"], []).append(r["model"])  # more than one if a fallback model took over
    for run in runs:
        count = counts.get(run["id"], {})
        run["loops"] = count.get("loops") or 0
        run["attempts"] = count.get("attempts") or 0
        run["models"] = sorted(m for m in models.get(run["id"], []) if m)
    _add_alert_details(runs)
    executed = _executed_modes(ids)
    waits = {r["run_id"]: r["w"] or 0 for r in db.query(
        f"SELECT run_id, SUM(end_ts - start_ts) AS w FROM spans WHERE name='approval.wait' AND run_id IN ({marks}) GROUP BY run_id", ids)}
    for run in runs:
        # "auto" only becomes live or demo when a worker starts the run, so this stays None until then.
        run["executed_mode"] = executed.get(run["id"]) or (run["mode"] if run["mode"] != "auto" else None)
        run["human_wait_seconds"] = waits.get(run["id"], 0)
    return runs


def _add_alert_details(runs):
    """Each run's alert title and severity, from the fixed scenarios or the generated alerts."""
    from . import tools

    ids = sorted({r["alert_id"] for r in runs})
    marks = ",".join("?" for _ in ids)
    generated = {r["id"]: r for r in db.query(f"SELECT id, title, severity_hint FROM generated_alerts WHERE id IN ({marks})", ids)}
    for run in runs:
        alert = tools.ALERTS.get(run["alert_id"]) or generated.get(run["alert_id"]) or {}
        run["alert_title"] = alert.get("title")
        run["alert_severity"] = alert.get("severity_hint")


def _executed_modes(run_ids=None, since=None):
    """What each run really did. A run's own mode can say "auto", so its start events decide.
    Any demo attempt makes the run demo, the same test alerts.accuracy uses."""
    if run_ids is not None:
        where, params = f"run_id IN ({','.join('?' for _ in run_ids)})", list(run_ids)
    else:
        where, params = "ts >= ?", [since]
    modes = {}
    for row in db.query(f"SELECT run_id, json_extract(data, '$.mode') AS mode FROM events WHERE kind='start' AND {where}", params):
        if row["mode"] == "demo" or row["run_id"] not in modes:
            modes[row["run_id"]] = row["mode"]
    return modes


def _triage(since, now):
    """What an analyst asks first: what's waiting, how did investigations end, how fast, and are we keeping up.
    Demo and live stay apart throughout, because demo verdicts and timings are scripted, not results."""
    from . import tools

    waiting = db.query("""SELECT a.id, a.title, a.severity_hint, a.occurrences, a.created_at FROM generated_alerts a
                          WHERE NOT EXISTS (SELECT 1 FROM runs r WHERE r.alert_id = a.id)""")
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for alert in waiting:
        by_severity[alert["severity_hint"]] = by_severity.get(alert["severity_hint"], 0) + 1
    worst_first = sorted(waiting, key=lambda a: (tools.PRIORITY.get(a["severity_hint"], 9), a["created_at"]))
    next_up = [{"id": a["id"], "title": a["title"], "severity": a["severity_hint"], "occurrences": a["occurrences"],
                "age_seconds": max(now - a["created_at"], 0)} for a in worst_first[:5]]

    runs = db.query("SELECT id, mode, status, verdict, finished_at FROM runs WHERE created_at >= ?", (since,))
    executed = _executed_modes(since=since)
    outcomes = {mode: {"true_positive": 0, "false_positive": 0, "needs_escalation": 0, "no_verdict": 0, "failed": 0} for mode in ("live", "demo")}
    in_progress = 0
    for run in runs:
        if run["status"] not in ("completed", "failed"):
            in_progress += 1
            continue
        mode = "demo" if (executed.get(run["id"]) or run["mode"]) == "demo" else "live"
        if run["status"] == "failed":
            outcomes[mode]["failed"] += 1
        else:
            outcomes[mode][run["verdict"] if run["verdict"] in outcomes[mode] else "no_verdict"] += 1

    return {"waiting_by_severity": by_severity, "next_up": next_up,
            "outcomes": {**outcomes, "in_progress": in_progress, "awaiting": len(waiting)},
            "time_to_triage": _time_to_triage(since), "activity": _activity(now)}


def _time_to_triage(since):
    """From a generated alert being raised to its first completed run, approval waits included."""
    rows = db.query("""SELECT r.id, r.mode, r.finished_at - a.created_at AS seconds FROM runs r JOIN generated_alerts a ON a.id = r.alert_id
                       WHERE r.status='completed' AND r.finished_at IS NOT NULL AND r.finished_at >= ?
                         AND r.finished_at = (SELECT MIN(f.finished_at) FROM runs f WHERE f.alert_id = r.alert_id AND f.status='completed')""", (since,))
    executed = _executed_modes([r["id"] for r in rows]) if rows else {}
    values = {"live": [], "demo": []}
    for row in rows:
        values["demo" if (executed.get(row["id"]) or row["mode"]) == "demo" else "live"].append(max(row["seconds"], 0))
    return {mode: {"count": len(v), "median_seconds": statistics.median(v) if v else None} for mode, v in values.items()}


def _activity(now, hours=24):
    """Alerts raised and runs started per hour, oldest first. The last bucket is the current, partial hour."""
    current = int(now) // 3600 * 3600
    first = current - (hours - 1) * 3600
    buckets = {first + i * 3600: {"hour": first + i * 3600, "alerts": 0, "critical": 0, "runs": 0} for i in range(hours)}
    for row in db.query("""SELECT CAST(created_at AS INTEGER) / 3600 * 3600 AS hour, COUNT(*) AS n, SUM(severity_hint='critical') AS critical
                           FROM generated_alerts WHERE created_at >= ? GROUP BY hour""", (first,)):
        if row["hour"] in buckets:
            buckets[row["hour"]].update(alerts=row["n"], critical=row["critical"])
    for row in db.query("SELECT CAST(created_at AS INTEGER) / 3600 * 3600 AS hour, COUNT(*) AS n FROM runs WHERE created_at >= ? GROUP BY hour", (first,)):
        if row["hour"] in buckets:
            buckets[row["hour"]]["runs"] = row["n"]
    return list(buckets.values())


def summary(daily_budget, window=86400):
    from . import alerts, cache, circuit, queue  # imported here to avoid an import cycle: these record metrics through obs

    now = time.time()
    since = now - window
    counters = _counters(since)
    rows = db.query("SELECT status, COUNT(*) AS n, SUM(cost_usd) AS cost FROM runs WHERE created_at >= ? GROUP BY status", (since,))
    by_status = {r["status"]: r["n"] for r in rows}
    cost = sum(r["cost"] or 0 for r in rows)
    finished = by_status.get("completed", 0) + by_status.get("failed", 0)

    tools = []
    for row in db.query("SELECT name, COUNT(*) AS n, SUM(status='error') AS errors FROM spans "
                        "WHERE name LIKE 'tool.%' AND start_ts >= ? GROUP BY name ORDER BY n DESC", (since,)):
        latency = _latency(row["name"], since)
        tools.append({"tool": row["name"][5:], "calls": row["n"], "errors": row["errors"],
                      "p50": latency["p50"], "p95": latency["p95"]})

    latency = {key: _latency(key, since) for key in ("queue.wait", "agent.attempt", "llm.call", "approval.wait")}
    stats = queue.stats()
    oldest = db.query("SELECT MIN(available_at) AS t FROM jobs WHERE status='queued' AND available_at <= ?", (now,))[0]["t"]
    dead = db.query("SELECT COUNT(*) AS n FROM jobs WHERE status='dead' AND updated_at >= ?", (since,))[0]["n"]
    result = {
        "window_hours": window / 3600,
        "runs": {"by_status": by_status, "finished": finished,
                 "success_rate": by_status.get("completed", 0) / finished if finished else None},
        "cost_usd": cost, "daily_budget_usd": daily_budget,
        "cost_per_completed_run": cost / by_status["completed"] if by_status.get("completed") else None,
        "latency": latency,
        "tools": tools,
        "models": _models(since),
        "agents": _agents(since),
        "architectures": _architectures(since),
        "max_steps": _max_steps(),
        "model": {"http": counters.get("llm_http", []), "errors": counters.get("llm_errors", []),
                  "turns": _sum(counters, "llm_turns"), "refusals": _sum(counters, "llm_turns", stop="refusal"),
                  "input_tokens": _sum(counters, "llm_tokens", kind="input"),
                  "output_tokens": _sum(counters, "llm_tokens", kind="output"),
                  "cache_read_tokens": _sum(counters, "llm_tokens", kind="cache_read")},
        "safety": {"injection_flags": _sum(counters, "injection_flags"),
                   "policy": {c["labels"].get("decision"): 0 for c in counters.get("policy_decisions", [])},
                   "approvals": counters.get("approvals", []), "auth": counters.get("auth_events", [])},
        "queue": {**stats, "dead_in_window": dead, "oldest_ready_age": now - oldest if oldest else 0},
        "circuits": circuit.states(),
        "alert_queue": {"waiting": alerts.open_count(), "generated": _sum(counters, "alerts_generated"), "deduplicated": _sum(counters, "alerts_deduplicated"),
                   "oldest_critical_age": _oldest_critical(now), "accuracy": alerts.accuracy(since)},
        "reliability": {"resumed": _sum(counters, "runs_resumed"), "idempotent_replays": _sum(counters, "idempotent_replays"),
                        "deferred": _sum(counters, "runs_deferred"), "leases_lost": _sum(counters, "lease_lost"),
                        "retries": _sum(counters, "job_failures", outcome="retry")},
        "cache": cache.stats(),
        "recent_runs": _recent_runs(),
        "triage": _triage(since, now),
    }
    for decision in result["safety"]["policy"]:
        result["safety"]["policy"][decision] = _sum(counters, "policy_decisions", decision=decision)
    result["alerts"] = _alerts(result, counters)
    return result


def _oldest_critical(now):
    rows = db.query("""SELECT MIN(a.created_at) AS t FROM generated_alerts a WHERE a.severity_hint='critical'
                         AND NOT EXISTS (SELECT 1 FROM runs r WHERE r.alert_id = a.id)""")
    return now - rows[0]["t"] if rows and rows[0]["t"] else 0


def _max_steps():
    from . import policy  # imported here so policy stays free of telemetry concerns
    return policy.MAX_STEPS


def _alerts(s, counters):
    """Symptoms someone should act on. Thresholds are starting points to tune from real traffic."""
    alerts = []

    def add(level, title, detail):
        alerts.append({"level": level, "title": title, "detail": detail})

    for item in s["circuits"]:
        if item["state"] != "closed":
            add("serious", "Model provider paused", f"{item['name']}: circuit is {item['state'].replace('_', '-')} after repeated failures. Affected jobs wait and retry automatically.")
    if s["alert_queue"]["oldest_critical_age"] > 900:
        add("critical", "A critical alert isn't being triaged", f"Oldest has waited {s['alert_queue']['oldest_critical_age'] / 60:.0f} minutes without a run.")
    if s["alert_queue"]["waiting"] >= 25:
        add("warning", "Alert backlog is growing", f"{s['alert_queue']['waiting']} alerts are waiting for triage.")
    age = s["queue"]["oldest_ready_age"]
    if age > QUEUE_STALL_SECONDS:
        add("critical", "Jobs are waiting and not being picked up",
            f"Oldest ready job has waited {age:.0f}s. Check that workers are running.")
    if s["queue"]["dead_in_window"]:
        add("serious", "Investigations failed permanently",
            f"{s['queue']['dead_in_window']} job(s) used all their attempts. They need a person to look at them.")
    quota = _sum(counters, "llm_errors", kind="QuotaError")
    if quota:
        add("serious", "Model quota exhausted", f"{quota:.0f} request(s) were refused by the provider's quota. Live runs can't finish.")
    overloaded = _sum(counters, "llm_http", status="503")
    if overloaded:
        add("warning", "Model provider overloaded", f"{overloaded:.0f} response(s) with HTTP 503. Retries handle short spikes.")
    server_errors = sum(c["value"] for c in counters.get("http_responses", []) if str(c["labels"].get("status", "")).startswith("5"))
    if server_errors:
        add("serious", "API errors", f"{server_errors:.0f} HTTP 5xx response(s) from this app.")
    rate = s["runs"]["success_rate"]
    if rate is not None and s["runs"]["finished"] >= 4 and rate < 0.75:
        add("serious", "Low run success rate", f"{rate:.0%} of finished runs produced a report.")
    budget = s["daily_budget_usd"]
    if budget and s["cost_usd"] >= budget:
        add("critical", "Daily model budget used", f"${s['cost_usd']:.2f} of ${budget:.2f}. Live runs are being refused.")
    elif budget and s["cost_usd"] >= 0.8 * budget:
        add("warning", "Daily model budget nearly used", f"${s['cost_usd']:.2f} of ${budget:.2f}.")
    denied = _sum(counters, "auth_events", kind="approval_forbidden") + _sum(counters, "auth_events", kind="forbidden")
    throttled = _sum(counters, "auth_events", kind="login_throttled")
    if throttled:
        add("warning", "Possible password guessing", f"{throttled:.0f} login attempt(s) were throttled.")
    code_failures = _sum(counters, "auth_events", kind="mfa_failed") + _sum(counters, "auth_events", kind="mfa_throttled")
    if code_failures >= 5:
        add("warning", "Repeated MFA failures", f"{code_failures:.0f} failed code attempts. Someone may have a stolen password: check the audit log.")
    if denied >= 5:
        add("warning", "Repeated permission refusals", f"{denied:.0f} refused actions. Check the audit log.")
    return alerts


def prometheus():
    """Counters in Prometheus text format. Since all buckets are kept for 30 days, totals rise until pruned."""
    lines = []
    for name, series in sorted(_counters(0).items()):
        metric = f"soc_{name}_total"
        lines.append(f"# TYPE {metric} counter")
        for item in series:
            labels = ",".join(
                '{}="{}"'.format(k, str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " "))
                for k, v in sorted(item["labels"].items()))
            lines.append(f"{metric}{{{labels}}} {item['value']:g}" if labels else f"{metric} {item['value']:g}")
    depth = db.query("SELECT COUNT(*) AS n FROM jobs WHERE status='queued'")[0]["n"]
    lines += ["# TYPE soc_queue_depth gauge", f"soc_queue_depth {depth}"]
    return "\n".join(lines) + "\n"
