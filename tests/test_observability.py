"""End-to-end observability test against a real server, worker and broker.

    .venv/bin/python tests/test_observability.py

Runs on its own ports with temporary data, and stops only the processes it started.
"""
import http.cookiejar, http.server, json, os, re, sqlite3, subprocess, sys, tempfile, threading, time, urllib.error, urllib.request

PORT, BROKER_PORT = 8792, 7092
BASE = f"http://127.0.0.1:{PORT}"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix="soc-obs-test-")
DB, LOGS, SERVER_LOG = f"{TMP}/test.db", f"{TMP}/logs", f"{TMP}/server.log"
ENV = {**os.environ, "SOC_DB_PATH": DB, "SOC_AUDIT_PATH": f"{TMP}/audit.jsonl", "SOC_LOG_DIR": LOGS, "MFA_REQUIRED": "0", "SOC_MFA_KEY_PATH": f"{TMP}/mfa.key", "BROKER_PORT": str(BROKER_PORT),
       "RUN_BURST": "100", "QUEUE_STALL_SECONDS": "1", "PYTHONUNBUFFERED": "1"}
for key in ("ANTHROPIC_API_KEY", "GEMINI_API_KEY", "LLM_PROVIDER"):
    ENV.pop(key, None)
os.environ.update({k: ENV[k] for k in ("SOC_DB_PATH", "SOC_AUDIT_PATH", "SOC_LOG_DIR", "BROKER_PORT")})
failures = 0


def check(label, ok, detail=""):
    global failures
    failures += not ok
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{f'  ({detail})' if detail != '' else ''}")


jar = http.cookiejar.CookieJar()
http_ = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def call(method, path, body=None, opener=None):
    req = urllib.request.Request(BASE + path, json.dumps(body).encode() if body is not None else None, {"content-type": "application/json"}, method=method)
    try:
        with (opener or http_).open(req, timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def sql(q, *p):
    c = sqlite3.connect(DB, timeout=10)
    with c:
        rows = c.execute(q, p).fetchall()
    c.close()
    return rows


def wait_for(fn, timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(0.1)
    raise TimeoutError(fn)


def summary():
    return json.loads(call("GET", "/api/obs/summary")[1])


def run_alert(alert):
    return json.loads(call("POST", "/api/runs", {"alert_id": alert, "mode": "demo"})[1])["run_id"]


def finish(run_id):
    def step():
        for (tid,) in sql("SELECT tool_use_id FROM approvals WHERE run_id=? AND status='pending'", run_id):
            call("POST", f"/api/runs/{run_id}/approve", {"tool_use_id": tid, "approved": True})
        return sql("SELECT 1 FROM runs WHERE id=? AND status IN ('completed','failed')", run_id)
    wait_for(step)


def main():
    python = sys.executable
    procs = [subprocess.Popen([python, "-m", "app.broker"], cwd=ROOT, env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)]
    time.sleep(0.5)
    log = open(SERVER_LOG, "w")
    procs.append(subprocess.Popen([python, "-m", "uvicorn", "app.server:app", "--port", str(PORT)], cwd=ROOT, env=ENV, stdout=log, stderr=log))
    try:
        wait_for(lambda: "Uvicorn running" in open(SERVER_LOG).read())
        passwords = dict(re.findall(r"^\s+(viewer|tier1|tier2|admin)\s+(\S+)$", open(SERVER_LOG).read(), re.M))
        check("tier2 logs in", call("POST", "/api/auth/login", {"username": "tier2", "password": passwords["tier2"]})[0] == 200)

        print("Access")
        anon = urllib.request.build_opener()
        for path in ["/api/obs/summary", "/metrics", "/api/runs/x/trace"]:
            check(f"{path} needs a login", call("GET", path, opener=anon)[0] == 401)

        check("the hidden attribute can't be overridden by layout CSS", "[hidden] { display: none !important; }" in call("GET", "/", opener=anon)[1])

        print("Alert: no workers running")
        stuck = run_alert("ALERT-1003")
        time.sleep(1.5)
        titles = [a["title"] for a in summary()["alerts"]]
        check("a job nobody picks up raises a critical alert", "Jobs are waiting and not being picked up" in titles, titles)

        procs.append(subprocess.Popen([python, "-m", "app.worker", "--id", "obs-test-worker", "--concurrency", "2"], cwd=ROOT, env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        finish(stuck)
        titles = [a["title"] for a in wait_for(lambda: (lambda s: s if not s["alerts"] else None)(summary()))["alerts"]]
        check("the alert clears when a worker takes the job", titles == [])

        print("Trace of a run with approvals")
        run_id = run_alert("ALERT-1002")
        time.sleep(1.5)
        finish(run_id)
        spans = json.loads(call("GET", f"/api/runs/{run_id}/trace")[1])
        names = [s["name"] for s in spans]
        by = {s["name"]: s for s in spans}
        check("spans cover server, queue, worker, tools and approval",
              {"api.enqueue", "queue.wait", "agent.attempt", "tool.get_alert", "tool.lookup_ip_reputation", "approval.wait"} <= set(names), sorted(set(names)))
        check("all spans belong to one trace", {s["run_id"] for s in spans} == {run_id})
        check("tool spans are children of the attempt", by["tool.get_alert"]["parent_id"] == by["agent.attempt"]["span_id"])
        check("approval wait is measured, and separately from tool time", by["approval.wait"]["attrs"]["outcome"] == "approved" and by["approval.wait"]["end_ts"] > by["approval.wait"]["start_ts"])
        check("cache result is on the tool span", by["tool.lookup_ip_reputation"]["attrs"]["cache"] in ("miss", "l1", "l2"))
        check("a run id that doesn't exist -> 404", call("GET", "/api/runs/nope/trace")[0] == 404)

        print("Dashboard summary and metrics")
        call("POST", "/api/auth/login", {"username": "tier2", "password": "wrong"})
        call("GET", "/api/runs/nope/events")
        s = summary()
        check("run counts and success rate", s["runs"]["by_status"].get("completed") == 2 and s["runs"]["success_rate"] == 1.0, s["runs"])
        check("latency percentiles exist", s["latency"]["agent.attempt"]["count"] == 2 and s["latency"]["queue.wait"]["p95"] is not None and s["latency"]["approval.wait"]["count"] >= 2)
        check("tool table has calls and timing", any(t["tool"] == "get_alert" and t["calls"] == 2 and t["p95"] for t in s["tools"]))
        check("injection flags and policy denials are counted", s["safety"]["injection_flags"] >= 1 and s["safety"]["policy"].get("deny", 0) >= 1, s["safety"]["policy"])
        check("approvals are counted by outcome", any(c["labels"]["outcome"] == "approved" for c in s["safety"]["approvals"]))
        check("failed login is counted", any(c["labels"]["kind"] == "login_failed" for c in s["safety"]["auth"]))
        demo = next(r for r in s["recent_runs"] if r["id"] == run_id)
        check("a demo run shows its loops, one attempt and no model", (demo["loops"], demo["attempts"], demo["models"]) == (4, 1, []), demo)
        check("demo runs don't appear as a model", s["models"] == [])
        created = subprocess.run([python, "-m", "app.auth", "create-token", "obs-test"], cwd=ROOT, env=ENV, capture_output=True, text=True)
        token = created.stdout.strip().splitlines()[-1]
        with urllib.request.urlopen(urllib.request.Request(BASE + "/metrics", headers={"authorization": f"Bearer {token}"}), timeout=10) as r:
            status, text = r.status, r.read().decode()
        check("/metrics is Prometheus text", status == 200 and "# TYPE soc_runs_finished_total counter" in text and 'soc_runs_finished_total{status="completed"} 2' in text and "soc_queue_depth 0" in text)
        check("routes are labeled by template, not raw path", 'route="/api/runs/{run_id}/events"' in text and "/api/runs/nope" not in text)

        print("Logs")
        lines = [json.loads(l) for f in os.listdir(LOGS) for l in open(os.path.join(LOGS, f))]
        worker_lines = [l for l in lines if l["component"] == "obs-test-worker"]
        check("JSON log files exist for server and worker", {"server", "obs-test-worker"} <= {l["component"] for l in lines})
        check("worker log lines carry the run id", any(l["run_id"] == run_id for l in worker_lines))

        print("No sensitive content in telemetry")
        blob = open(os.path.join(LOGS, "server.jsonl")).read() + open(os.path.join(LOGS, "obs-test-worker.jsonl")).read()
        blob += json.dumps(sql("SELECT * FROM spans")) + json.dumps(sql("SELECT * FROM metrics"))
        for needle, label in [("ignore all previous", "email contents"), ("svc-backup", "tool arguments"), ("j.doe", "log contents"), ("m.patel", "user names"), (passwords["tier2"], "passwords")]:
            check(f"no {label}", needle not in blob)
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            p.wait(timeout=15)

    in_process_tests()
    print(f"\n{'ALL PASSED' if not failures else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)


class StandIn(http.server.BaseHTTPRequestHandler):
    """Local stand-in for a model API: answers with the queued statuses."""
    statuses = []

    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", 0)))
        status = StandIn.statuses.pop(0)
        body = {"candidates": [{"content": {"role": "model", "parts": [{"text": "done"}]}, "finishReason": "STOP"}],
                "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 2}} if status == 200 else {"error": {"code": status, "message": "stand-in", "status": "X"}}
        data = json.dumps(body).encode()
        self.send_response(status); self.send_header("content-type", "application/json"); self.send_header("content-length", str(len(data))); self.end_headers(); self.wfile.write(data)

    def log_message(self, *a):
        pass


def in_process_tests():
    sys.path.insert(0, ROOT)
    srv = http.server.HTTPServer(("127.0.0.1", 0), StandIn)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_port}"
    os.environ.update(GEMINI_API_KEY="fake", LLM_PROVIDER="gemini", GOOGLE_GEMINI_BASE_URL=url, ANTHROPIC_BASE_URL=url, ANTHROPIC_API_KEY="fake")
    from app import agent, db, llm, obs

    print("Real SDKs: every HTTP attempt is counted, including retries")
    def http_count(provider, status):
        return (sql("SELECT SUM(value) FROM metrics WHERE name='llm_http' AND labels=?", json.dumps({"provider": provider, "status": status}, sort_keys=True))[0][0]) or 0
    StandIn.statuses[:] = [503, 503, 200]
    obs.set_run("in-process")
    llm.GeminiProvider("s", [], "hi").next_turn()
    check("Gemini: two 503s and a 200 are all visible", (http_count("gemini", "503"), http_count("gemini", "200")) == (2, 1))
    StandIn.statuses[:] = [401]
    try:
        llm.ClaudeProvider("s", [], "hi").next_turn()
    except llm.CredentialsError:
        pass
    check("Claude: responses are counted too", http_count("anthropic", "401") == 1)

    print("Model errors reach metrics and alerts")
    class Failing:
        def next_turn(self):
            raise llm.QuotaError("quota")
    try:
        agent._model_turn(Failing())
    except llm.QuotaError:
        pass
    check("quota error raises an alert", "Model quota exhausted" in [a["title"] for a in obs.summary(20)["alerts"]])
    check("failed model call is an error span", any(s["name"] == "llm.call" and s["status"] == "error" and s["attrs"]["error"] == "QuotaError" for s in obs.trace("in-process")))

    print("Models and loops")
    now = time.time()
    def usage(seq, model, run):
        db.add_event(run, {"seq": seq, "ts": now, "kind": "usage", "model": model, "input": 100, "output": 10, "cost_usd": 0.01})
    for run, attempts, loops, model in (("m1", 2, 3, "model-a"), ("m2", 1, 1, "model-a"), ("m3", 1, 2, "model-b")):
        db.create_run(run, "ALERT-1001", "live")
        seq = 0
        for _ in range(attempts):
            db.add_event(run, {"seq": seq, "ts": now, "kind": "start"}); seq += 1
        for _ in range(loops):
            db.add_event(run, {"seq": seq, "ts": now, "kind": "step"}); seq += 1
            usage(seq, model, run); seq += 1
    s = obs.summary(20)
    models = {m["model"]: m for m in s["models"]}
    a = models.get("model-a", {})
    check("calls, runs and tokens are grouped by model", (a.get("runs"), a.get("calls"), a.get("input_tokens")) == (2, 4, 400), a)
    check("average and largest loops per run", (a.get("avg_loops"), a.get("max_loops")) == (2.0, 3))
    check("each model has its own row", models.get("model-b", {}).get("calls") == 2)
    m1 = next(r for r in s["recent_runs"] if r["id"] == "m1")
    check("a retried run reports its loops, attempts and model", (m1["loops"], m1["attempts"], m1["models"]) == (3, 2, ["model-a"]), m1)
    check("the step limit is reported", s["max_steps"] == 15)

    print("Redaction")
    key = "AIza" + "x" * 35
    check("API keys are removed from log text", key not in obs.redact(f"url?key={key}") and "sk-ant-abc" not in obs.redact("sk-ant-abc-123"))
    check("service tokens are too", "soc_svc_abc" not in obs.redact("soc_svc_abc-123"))

    print("Telemetry can't break the agent")
    real = db.execute
    def broken(*a, **k):
        raise RuntimeError("telemetry store down")
    obs.db = type("Broken", (), {"execute": staticmethod(broken), "query": db.query, "executescript": db.executescript})
    try:
        obs.inc("x")
        obs.record_span("x", 0, 1, run_id="r")
        ran = False
        with obs.span("y"):
            ran = True
        check("metrics and spans fail silently, and work continues", ran)
    finally:
        obs.db = db
    assert db.execute is real


if __name__ == "__main__":
    main()
