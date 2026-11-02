"""The dashboard's triage data: what's waiting, outcomes, time to triage, hourly activity and run details.

    .venv/bin/python tests/test_dashboard_data.py
"""
import json, os, random, shutil, sys, tempfile, time, uuid
TMP = tempfile.mkdtemp(prefix="soc-dash-test-")
os.environ.update(SOC_DB_PATH=f"{TMP}/t.db", SOC_AUDIT_PATH=f"{TMP}/a.jsonl", SOC_LOG_DIR=f"{TMP}/logs", SOC_MFA_KEY_PATH=f"{TMP}/k", BROKER_PORT="1", MFA_REQUIRED="0", MAX_OPEN_ALERTS="500")
for k in ("ANTHROPIC_API_KEY", "GEMINI_API_KEY", "LLM_PROVIDER"):
    os.environ.pop(k, None)
sys.path.insert(0, ".")
from app import actions, agent, alerts, auth, cache, circuit, db, obs, queue, ratelimit
db.init(); queue.init(); cache.init(); ratelimit.init(); obs.init(); actions.init(); circuit.init()
agent.Run.wait_for_approval = lambda self, *a, **k: True
failures = 0


def check(label, ok, detail=""):
    global failures
    failures += not ok
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{f'  ({detail})' if detail != '' else ''}")


def demo_run(alert_id, architecture="single", mode="demo"):
    rid = uuid.uuid4().hex[:8]
    db.create_run(rid, alert_id, mode, started_by="kashish", architecture=architecture)
    run = agent.execute_job(rid, alert_id, "demo", 1)
    db.finish_run(rid, "completed", run.report)  # a worker does this in production
    return rid


def live_row(alert_id, verdict=None, status="completed"):
    """A finished live run, written directly so no model is ever called."""
    rid = uuid.uuid4().hex[:8]
    db.create_run(rid, alert_id, "live", started_by="kashish")
    db.execute("INSERT INTO events (run_id, seq, ts, kind, data) VALUES (?, 0, ?, 'start', ?)", (rid, time.time(), json.dumps({"kind": "start", "mode": "live"})))
    if status == "completed":
        db.finish_run(rid, "completed", {"verdict": verdict, "severity": "low"})
    elif status == "failed":
        db.execute("UPDATE runs SET status='failed', finished_at=? WHERE id=?", (time.time(), rid))
    return rid


print("An empty database")
s = obs.summary(20)["triage"]
check("every section is present and empty", s["next_up"] == [] and s["outcomes"]["awaiting"] == 0 and s["time_to_triage"]["live"] == {"count": 0, "median_seconds": None} and sum(h["alerts"] + h["runs"] for h in s["activity"]) == 0)
check("activity always has 24 hourly buckets, ending at the current hour",
      len(s["activity"]) == 24 and s["activity"][-1]["hour"] == int(time.time()) // 3600 * 3600 and all(b["hour"] - a["hour"] == 3600 for a, b in zip(s["activity"], s["activity"][1:])))

print("What's waiting")
made = {name: alerts.generate(name, random.Random(i))[0] for i, name in enumerate(("phishing", "brute_force", "malware", "benign_lockout"))}
older, _ = alerts.generate("malware", random.Random(50))
db.execute("UPDATE generated_alerts SET created_at = created_at - 600 WHERE id=?", (older["id"],))
result = obs.summary(20)
s = result["triage"]
check("waiting counts add up to the queue's total", sum(s["waiting_by_severity"].values()) == result["alert_queue"]["waiting"] == 5, s["waiting_by_severity"])
check("severities are counted", s["waiting_by_severity"] == {"critical": 2, "high": 2, "medium": 1, "low": 0})
check("next up is worst first, then oldest", [a["severity"] for a in s["next_up"]][:2] == ["critical", "critical"] and s["next_up"][0]["id"] == older["id"] and s["next_up"][-1]["severity"] == "medium")
check("waited time is reported", s["next_up"][0]["age_seconds"] >= 600)
check("next up is capped", len(s["next_up"]) <= 5)
blob = json.dumps(s["next_up"])
check("only public alert fields leave the server", set(s["next_up"][0]) == {"id", "title", "severity", "occurrences", "age_seconds"} and "facts" not in blob and "_positive" not in blob and "description" not in blob)
check("activity counts the new alerts", sum(h["alerts"] for h in s["activity"]) == 5 and sum(h["critical"] for h in s["activity"]) == 2, sum(h["alerts"] for h in s["activity"]))

print("Old alerts fall out of the activity chart, not the queue")
stale, _ = alerts.generate("phishing", random.Random(77))
db.execute("UPDATE generated_alerts SET created_at = ? WHERE id=?", (time.time() - 30 * 3600, stale["id"]))
s = obs.summary(20)["triage"]
check("a 30-hour-old alert isn't in the chart", sum(h["alerts"] for h in s["activity"]) == 5)
check("but it still counts as waiting", s["outcomes"]["awaiting"] == 6)

print("Demo runs stay apart from live results")
tp = demo_run(made["brute_force"]["id"])
fp = demo_run(made["benign_lockout"]["id"])
multi = demo_run(made["malware"]["id"], "multi", mode="auto")  # "auto" that fell back to demo must still count as demo
result = obs.summary(20)
out = result["triage"]["outcomes"]
check("demo verdicts count as demo", out["demo"]["true_positive"] == 2 and out["demo"]["false_positive"] == 1, out["demo"])
check("nothing leaks into live", not any(out["live"].values()), out["live"])
check("no live time to triage from demo runs", result["triage"]["time_to_triage"]["live"]["count"] == 0)
ttt = result["triage"]["time_to_triage"]["demo"]
check("demo time to triage is reported separately", ttt["count"] == 3 and ttt["median_seconds"] >= 0, ttt)
check("runs started are charted", sum(h["runs"] for h in result["triage"]["activity"]) == 3)
check("the waiting count dropped", out["awaiting"] == result["alert_queue"]["waiting"] == 3)

print("Live outcomes")
live_tp = live_row(made["phishing"]["id"], "true_positive")
escalate = live_row(older["id"], "needs_escalation")
failed = live_row(stale["id"], status="failed")
queued_alert = alerts.generate("phishing", random.Random(91))[0]
pending = uuid.uuid4().hex[:8]
db.create_run(pending, queued_alert["id"], "auto", started_by="kashish")
result = obs.summary(20)
out = result["triage"]["outcomes"]
check("live verdicts are counted", out["live"]["true_positive"] == 1 and out["live"]["needs_escalation"] == 1 and out["live"]["failed"] == 1, out["live"])
check("a queued run is in progress, in neither group", out["in_progress"] == 1, out["in_progress"])
total_runs = sum(out["live"].values()) + sum(out["demo"].values()) + out["in_progress"]
check("every run in the window is counted once", total_runs == sum(result["runs"]["by_status"].values()), (total_runs, result["runs"]["by_status"]))
ttt = result["triage"]["time_to_triage"]
check("time to triage covers only the first completed live run", ttt["live"]["count"] == 2 and ttt["live"]["median_seconds"] >= 0, ttt["live"])
check("a re-run doesn't count twice", (live_row(made["phishing"]["id"], "false_positive"), obs.summary(20)["triage"]["time_to_triage"]["live"]["count"])[1] == 2)
check("accuracy still counts live runs only", result["alert_queue"]["accuracy"]["runs"] == 2)

print("Run details for the table")
result = obs.summary(20)
runs = {r["id"]: r for r in result["recent_runs"]}
check("alert severity and title are included", runs[tp]["alert_severity"] == "high" and runs[tp]["alert_title"] == made["brute_force"]["title"], runs[tp]["alert_title"])
fixed = demo_run("ALERT-1002")
check("a fixed scenario has them too", (lambda r: r["alert_severity"] == "critical" and bool(r["alert_title"]))(next(r for r in obs._recent_runs() if r["id"] == fixed)))
check("the mode that really ran is reported", runs[multi]["mode"] == "auto" and runs[multi]["executed_mode"] == "demo" and runs[live_tp]["executed_mode"] == "live")
check("an auto run nobody has started yet has no mode", runs[pending]["executed_mode"] is None)
check("approval wait is reported", all("human_wait_seconds" in r for r in runs.values()))
check("the original fields are all still there", {"id", "alert_id", "mode", "status", "verdict", "cost_usd", "started_by", "architecture", "created_at", "finished_at", "loops", "attempts", "models"} <= set(runs[tp]))
for i in range(60):
    db.create_run(f"bulk{i}", "ALERT-1001", "demo")
check("the table gets the newest 50", len(obs._recent_runs()) == 50)
db.execute("DELETE FROM runs WHERE id LIKE 'bulk%'")
db.create_run("gone", "ALERT-DELETED", "demo")
check("a run whose alert is gone doesn't break the table", next(r for r in obs._recent_runs() if r["id"] == "gone")["alert_severity"] is None)
db.execute("DELETE FROM runs WHERE id='gone'")

print("Existing summary fields keep working")
result = obs.summary(20)
check("all the older keys remain", {"alerts", "alert_queue", "architectures", "recent_runs", "runs", "latency", "tools", "safety", "circuits", "reliability", "models", "agents", "queue", "model", "cost_usd", "daily_budget_usd", "max_steps", "cache"} <= set(result))
trace = obs.trace(multi)
check("a multi-agent demo trace labels its agents", any(s["attrs"].get("agent") for s in trace), sorted({s["attrs"].get("agent") or "-" for s in trace}))

print("Telemetry stays clean")
metrics_before = {r["name"] for r in db.query("SELECT DISTINCT name FROM metrics")}
obs.summary(20)
check("reading the dashboard records no new metrics", {r["name"] for r in db.query("SELECT DISTINCT name FROM metrics")} == metrics_before)
triage_blob = json.dumps(obs.summary(20)["triage"])
check("the new section has no usernames, emails or tool arguments", "kashish" not in triage_blob and "@" not in triage_blob and "powershell" not in triage_blob.lower() and not any(v in triage_blob for v in ("203.0.113", "198.51.100")))

print("The API")
from fastapi.testclient import TestClient
from app import server
with TestClient(server.app) as web:
    for user, role in (("kashish", "tier1"), ("look", "viewer")):
        auth.set_user(user, role, "a-long-password-1")
    def login(u):
        c = TestClient(server.app); c.post("/api/auth/login", json={"username": u, "password": "a-long-password-1"}); return c
    body = login("kashish").get("/api/obs/summary")
    check("the summary serializes with the new section", body.status_code == 200 and "triage" in body.json() and len(body.json()["triage"]["activity"]) == 24)
    check("viewers can't read it", login("look").get("/api/obs/summary").status_code == 403)

shutil.rmtree(TMP, ignore_errors=True)
print(f"\n{'ALL PASSED' if not failures else f'{failures} FAILED'}")
sys.exit(1 if failures else 0)
