"""Reliability tests: idempotency, resume, circuit breaker, fencing, and a real kill -9.

    .venv/bin/python tests/test_reliability.py

Runs on temporary data and its own ports, and stops only the processes it started.
"""
import json, os, re, signal, sqlite3, subprocess, sys, tempfile, time, urllib.error, urllib.request, http.cookiejar, uuid
from types import SimpleNamespace as NS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix="soc-rel-test-")
os.environ.update(SOC_DB_PATH=f"{TMP}/test.db", SOC_AUDIT_PATH=f"{TMP}/audit.jsonl", SOC_LOG_DIR=f"{TMP}/logs", BROKER_PORT="7094",
                  LLM_PROVIDER="gemini", GEMINI_API_KEY="fake", CIRCUIT_THRESHOLD="3", CIRCUIT_COOLDOWN="0.5", CIRCUIT_MAX_COOLDOWN="2")
os.environ.pop("ANTHROPIC_API_KEY", None)
sys.path.insert(0, ROOT)
from google import genai
from google.genai import types
from app import actions, agent, cache, circuit, db, llm, obs, queue, ratelimit, tools, worker
db.init(); queue.init(); cache.init(); ratelimit.init(); obs.init(); actions.init(); circuit.init()
failures = 0


def check(label, ok, detail=""):
    global failures
    failures += not ok
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{f'  ({detail})' if detail != '' else ''}")


def effects(target=None):
    return db.query("SELECT COUNT(*) AS n FROM external_effects WHERE (? IS NULL OR target=?)", (target, target))[0]["n"]


def new_run(mode="live", alert="ALERT-1001"):
    rid = uuid.uuid4().hex[:8]
    db.create_run(rid, alert, mode)
    return rid


print("Idempotency")
rid = new_run()
args = {"ip": "1.2.3.4", "reason": "first wording"}
first = actions.execute(rid, "block_ip", args)
check("first call has one effect", effects("1.2.3.4") == 1)
check("a finished action is found, even with a different reason or spacing",
      actions.find_done(rid, "block_ip", {"ip": " 1.2.3.4 ", "reason": "reworded"}) == first)
check("another target is a separate action", actions.find_done(rid, "block_ip", {"ip": "9.9.9.9", "reason": "x"}) is None)
check("another run is separate", actions.find_done(new_run(), "block_ip", args) is None)

rid = new_run()
real_done = actions._mark_done
def crash(*a):
    raise KeyboardInterrupt("worker died right after the firewall acted")
actions._mark_done = crash
try:
    actions.execute(rid, "block_ip", {"ip": "5.5.5.5", "reason": "x"})
except KeyboardInterrupt:
    pass
actions._mark_done = real_done
check("crash window: the effect happened but isn't marked done", effects("5.5.5.5") == 1 and actions.find_done(rid, "block_ip", {"ip": "5.5.5.5", "reason": "x"}) is None)
actions.execute(rid, "block_ip", {"ip": "5.5.5.5", "reason": "x"})
check("retry after that crash doesn't apply it twice", effects("5.5.5.5") == 1 and len(actions.done_for_run(rid)) == 1)

rid = new_run()
real_run = tools.run_tool
tools.run_tool = lambda *a: (_ for _ in ()).throw(RuntimeError("firewall down"))
try:
    actions.execute(rid, "block_ip", {"ip": "6.6.6.6", "reason": "x"})
except RuntimeError:
    pass
tools.run_tool = real_run
check("a failed call has no effect and isn't reported as done", effects("6.6.6.6") == 0 and actions.done_for_run(rid) == [])
actions.execute(rid, "block_ip", {"ip": "6.6.6.6", "reason": "x"})
check("a failed call can be tried again", effects("6.6.6.6") == 1)

print("Resume through a real SDK conversation (fake model)")
SIG = b"\xff\x00binary-signature\x80"
REPORT = {"verdict": "true_positive", "severity": "high", "mitre_techniques": ["T1110"], "summary": "s", "recommendations": ["r"], "limitations": ["l"]}
script, seen = [], []


def fc(name, args, cid):
    return types.Part(function_call=types.FunctionCall(id=cid, name=name, args=args), thought_signature=SIG)


def reply(parts):
    return types.GenerateContentResponse(candidates=[types.Candidate(content=types.Content(role="model", parts=parts), finish_reason="STOP")],
                                         model_version="gemini-3.8-flash",
                                         usage_metadata=types.GenerateContentResponseUsageMetadata(prompt_token_count=20000, candidates_token_count=2000))


class FakeModels:
    def generate_content(self, model, contents, config):
        seen.append(list(contents))
        item = script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


genai.Client = lambda **kw: NS(models=FakeModels())
overloaded = lambda: genai.errors.ServerError(503, {"error": {"message": "high demand", "status": "UNAVAILABLE"}})
asked = []
real_wait = agent.Run.wait_for_approval
agent.Run.wait_for_approval = lambda self, tid, name, args, reason, **k: asked.append(name) or True

rid = new_run()
script[:] = [reply([fc("get_alert", {"alert_id": "ALERT-1001"}, "a1")]),
             reply([fc("block_ip", {"ip": "185.220.101.45", "reason": "bad"}, "a2")]),
             overloaded()]
try:
    agent.execute_job(rid, "ALERT-1001", "live", 1); check("attempt 1 fails", False)
except agent.AgentFailed:
    pass
spent_1 = db.get_run(rid)["cost_usd"]
check("progress is saved after each loop", db.query("SELECT step FROM checkpoints WHERE run_id=?", (rid,))[0]["step"] == 2)
calls_before, seen[:] = len(seen), []
script[:] = [reply([fc("block_ip", {"ip": "185.220.101.45", "reason": "worded differently"}, "b1")]),
             reply([fc("submit_triage_report", REPORT, "b2")])]
run = agent.execute_job(rid, "ALERT-1001", "live", 2)
events = db.get_events(rid)
check("attempt 2 resumes from loop 3", any(e["kind"] == "resume" and e["from_step"] == 3 for e in events))
check("earlier model calls aren't repeated", len(seen) == 2, f"{calls_before} then {len(seen)}")
sigs = [p.thought_signature for c in seen[0] if c.role == "model" for p in c.parts]
check("restored history keeps binary thought signatures exact", sigs == [SIG, SIG])
check("history order is intact", [c.role for c in seen[0]] == ["user", "model", "user", "model", "user"])
check("model asks for the same block again: no second effect", effects("185.220.101.45") == 1)
check("and no second approval", asked == ["block_ip"], asked)
check("an 'already done' event explains it", any(e["kind"] == "idempotent" for e in events))
check("report lists the action exactly once", run.report == REPORT and [a["action"] for a in run.actions] == ["block_ip"])
check("budget carries across attempts", db.get_run(rid)["cost_usd"] > spent_1 > 0)
db.finish_run(rid, "completed", run.report)
check("the checkpoint is deleted when the run ends", not db.query("SELECT 1 FROM checkpoints WHERE run_id=?", (rid,)))

rid = new_run()
script[:] = [reply([fc("get_alert", {"alert_id": "ALERT-1001"}, "a1")]), overloaded()]
try:
    agent.execute_job(rid, "ALERT-1001", "live", 1)
except agent.AgentFailed:
    pass
real_model = llm.GEMINI_MODEL
llm.GEMINI_MODEL = "another-model"
seen[:] = []
script[:] = [reply([fc("submit_triage_report", REPORT, "z1")])]
agent.execute_job(rid, "ALERT-1001", "live", 2)
llm.GEMINI_MODEL = real_model
check("a checkpoint from another model isn't reused: it starts fresh", len(seen[0]) == 1)
circuit.on_success("llm:gemini:gemini-3.8-flash")

rid = new_run()
db.add_run_cost(rid, 5.0)
script[:] = []
agent.execute_job(rid, "ALERT-1001", "live", 2)
check("a retry can't get past the run budget", any("run budget" in e.get("message", "") for e in db.get_events(rid)))

print("Circuit breaker")
name = "test-circuit"
for _ in range(2):
    circuit.before_call(name); circuit.on_failure(name)
check("stays closed below the threshold", db.query("SELECT state FROM circuits WHERE name=?", (name,))[0]["state"] == "closed")
circuit.before_call(name); circuit.on_failure(name)
try:
    circuit.before_call(name); check("opens at the threshold", False)
except circuit.CircuitOpen as e:
    check("opens at the threshold and fails fast", 0 < e.retry_after <= 1)
time.sleep(0.6)
circuit.before_call(name)
try:
    circuit.before_call(name); check("only one trial call", False)
except circuit.CircuitOpen:
    check("after the cooldown exactly one trial call goes through", True)
circuit.on_failure(name)
row = db.query("SELECT state, cooldown FROM circuits WHERE name=?", (name,))[0]
check("a failed trial reopens with a longer cooldown", (row["state"], row["cooldown"]) == ("open", 1.0), row)
time.sleep(1.1)
circuit.before_call(name); circuit.on_success(name)
row = db.query("SELECT state, failures, cooldown FROM circuits WHERE name=?", (name,))[0]
check("a successful trial closes it and resets", (row["state"], row["failures"], row["cooldown"]) == ("closed", 0, 0.5), row)
check("an open circuit raises a dashboard alert", (circuit.on_failure(name), circuit.on_failure(name), circuit.on_failure(name)) and
      "Model provider paused" in [a["title"] for a in obs.summary(20)["alerts"]])
circuit.on_success(name)

print("Outage: the agent loop and queue together")
breaker = "llm:gemini:gemini-3.8-flash"
circuit.on_success(breaker)
for _ in range(3):
    circuit.on_failure(breaker)
seen[:] = []
rid = new_run()
queue.enqueue(rid, "ALERT-1001", "live", 1)
job = queue.claim("w")
worker.process(job, "w")
row = db.query("SELECT status, attempts, deferrals FROM jobs WHERE run_id=?", (rid,))[0]
check("no provider call during an outage", seen == [])
check("job is deferred and keeps its attempts", (row["status"], row["attempts"], row["deferrals"]) == ("queued", 0, 1), row)
check("the run explains the pause", any(e["kind"] == "deferred" for e in db.get_events(rid)))
circuit.on_success(breaker)

print("Fencing and poison jobs")
rid = new_run()
try:
    agent.execute_job(rid, "ALERT-1001", "live", 1, fence=lambda: False); check("a stale worker stops", False)
except agent.LeaseLost:
    check("a worker that lost its job stops before acting", effects("185.220.101.45") == 1)
rid = new_run()
queue.enqueue(rid, "ALERT-1001", "demo", 0)
stale = queue.claim("same-name")
db.execute("UPDATE jobs SET lease_expires_at=0 WHERE id=?", (stale["id"],))
fresh = queue.claim("same-name")
check("the attempt number exposes a stale worker with the same name", not queue.owns(stale["id"], "same-name", stale["attempts"]) and queue.owns(fresh["id"], "same-name", fresh["attempts"]))
check("a stale worker can't record completion", queue.complete(stale, "same-name") is False)
check("or heartbeat", queue.heartbeat(stale["id"], "same-name", stale["attempts"]) is False)
db.execute("UPDATE jobs SET attempts=?, lease_expires_at=0 WHERE id=?", (queue.MAX_ATTEMPTS, stale["id"]))
check("a job that keeps killing workers isn't claimed again", queue.claim("w2") is None)
check("it's dead-lettered instead", [r["run_id"] for r in queue.reap_poison()] == [rid] and db.query("SELECT status FROM jobs WHERE run_id=?", (rid,))[0]["status"] == "dead")
agent.Run.wait_for_approval = real_wait

print("Real crash: kill -9 a worker between two approvals")
PORT = 8795
DB2 = f"{TMP}/e2e.db"
ENV = {**os.environ, "SOC_DB_PATH": DB2, "SOC_AUDIT_PATH": f"{TMP}/e2e.jsonl", "SOC_LOG_DIR": f"{TMP}/e2e-logs", "MFA_REQUIRED": "0", "SOC_MFA_KEY_PATH": f"{TMP}/mfa.key", "LEASE_SECONDS": "2", "RUN_BURST": "100", "PYTHONUNBUFFERED": "1"}
ENV.pop("GEMINI_API_KEY", None)
python = sys.executable
quiet = dict(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=ROOT, env=ENV)
procs = [subprocess.Popen([python, "-m", "app.broker"], **quiet)]
time.sleep(0.5)
log = open(f"{TMP}/server.log", "w")
procs.append(subprocess.Popen([python, "-m", "uvicorn", "app.server:app", "--port", str(PORT)], cwd=ROOT, env=ENV, stdout=log, stderr=log))


def wait_for(fn, timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        value = fn()
        if value:
            return value
        time.sleep(0.1)
    raise TimeoutError(fn)


def sql(q, *p):
    c = sqlite3.connect(DB2, timeout=10)
    with c:
        rows = c.execute(q, p).fetchall()
    c.close()
    return rows


try:
    wait_for(lambda: "Uvicorn running" in open(f"{TMP}/server.log").read())
    password = dict(re.findall(r"^\s+(viewer|tier1|tier2|admin)\s+(\S+)$", open(f"{TMP}/server.log").read(), re.M))["tier2"]
    http_ = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(path, body):
        req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", json.dumps(body).encode(), {"content-type": "application/json"})
        return json.load(http_.open(req, timeout=10))

    call("/api/auth/login", {"username": "tier2", "password": password})
    rid = call("/api/runs", {"alert_id": "ALERT-1002", "mode": "demo"})["run_id"]
    first_worker = subprocess.Popen([python, "-m", "app.worker", "--id", "crash-me", "--concurrency", "1"], **quiet)
    procs.append(first_worker)

    def pending(tool):
        rows = sql("SELECT tool_use_id FROM approvals WHERE run_id=? AND tool=? AND status='pending'", rid, tool)
        return rows[0][0] if rows else None

    tid = wait_for(lambda: pending("isolate_host"))
    call(f"/api/runs/{rid}/approve", {"tool_use_id": tid, "approved": True})
    wait_for(lambda: pending("block_ip"))
    check("isolate_host took effect before the crash", sql("SELECT COUNT(*) FROM external_effects WHERE tool='isolate_host'")[0][0] == 1)
    first_worker.send_signal(signal.SIGKILL)
    first_worker.wait()
    procs.append(subprocess.Popen([python, "-m", "app.worker", "--id", "take-over", "--concurrency", "1"], **quiet))
    # Wait for the new attempt to ask again. An approval given to a dead attempt deliberately doesn't carry over.
    wait_for(lambda: sql("SELECT 1 FROM events WHERE run_id=? AND kind='idempotent'", rid))
    tid = wait_for(lambda: (lambda rows: rows[0][0] if rows else None)(
        sql("SELECT tool_use_id FROM approvals WHERE run_id=? AND tool='block_ip' AND status='pending' AND requested_at > (SELECT MAX(ts) FROM events WHERE run_id=? AND kind='idempotent')", rid, rid)))
    call(f"/api/runs/{rid}/approve", {"tool_use_id": tid, "approved": True})
    wait_for(lambda: sql("SELECT 1 FROM runs WHERE id=? AND status='completed'", rid))
    events = [json.loads(r[0]) for r in sql("SELECT data FROM events WHERE run_id=? ORDER BY seq", rid)]
    kinds = [e["kind"] for e in events]
    acts = [e["tool"] for e in events if e["kind"] == "act"]
    check("second worker resumed instead of restarting", "resume" in kinds and acts.count("get_alert") == 1, acts)
    check("no containment action ran twice", sql("SELECT COUNT(*) FROM external_effects WHERE tool='isolate_host'")[0][0] == 1 and sql("SELECT COUNT(*) FROM external_effects WHERE tool='block_ip'")[0][0] == 1)
    check("the finished action wasn't re-approved", sum(1 for e in events if e["kind"] == "approval_request" and e["tool"] == "isolate_host") == 1)
    check("the trace says so", any(e["kind"] == "idempotent" and e["tool"] == "isolate_host" for e in events))
    final = next(e for e in events if e["kind"] == "final")
    check("report lists both actions once", sorted(a["action"] for a in final["actions"]) == ["block_ip", "isolate_host"])
finally:
    for p in procs:
        if p.poll() is None:
            p.terminate()
    for p in procs:
        try:
            p.wait(timeout=15)
        except subprocess.TimeoutExpired:  # a worker waits for its job on shutdown, which may be a pending approval
            p.kill()
            p.wait()

print(f"\n{'ALL PASSED' if not failures else f'{failures} FAILED'}")
sys.exit(1 if failures else 0)
