"""Dynamic alerts: scenarios, rules, deduplication, secrecy of ground truth, demo runs and the API.

    .venv/bin/python tests/test_dynamic_alerts.py
"""
import json, os, random, re, subprocess, sys, tempfile, time, uuid
TMP = tempfile.mkdtemp(prefix="soc-alerts-test-")
os.environ.update(SOC_DB_PATH=f"{TMP}/t.db", SOC_AUDIT_PATH=f"{TMP}/a.jsonl", SOC_LOG_DIR=f"{TMP}/logs", SOC_MFA_KEY_PATH=f"{TMP}/k", BROKER_PORT="1", MFA_REQUIRED="0", MAX_OPEN_ALERTS="500")
for k in ("ANTHROPIC_API_KEY", "GEMINI_API_KEY", "LLM_PROVIDER"):
    os.environ.pop(k, None)
sys.path.insert(0, ".")
from app import actions, agent, alerts, auth, cache, circuit, db, multi, obs, queue, ratelimit, tools
db.init(); queue.init(); cache.init(); ratelimit.init(); obs.init(); actions.init(); circuit.init()
failures = 0


def check(label, ok, detail=""):
    global failures
    failures += not ok
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{f'  ({detail})' if detail != '' else ''}")


print("Each scenario raises an alert from its own evidence")
made = {}
for scenario in alerts.SCENARIOS:
    alert, is_new = alerts.generate(scenario, random.Random(hash(scenario) & 0xffff))
    made[scenario] = alert
    check(f"{scenario} -> {alert['id']}: {alert['title']}", is_new and alert["id"].startswith("ALERT-2"))
ids = [a["id"] for a in made.values()]
check("IDs are unique", len(set(ids)) == 4)
check("critical and high map to queue priorities", all(a["severity_hint"] in tools.PRIORITY for a in made.values()))
a = made["brute_force"]["entities"]
check("the evidence is searchable", tools.search_logs("user", a["user"])["count"] >= 3 and tools.lookup_ip_reputation(a["ip"])["reputation"] == "malicious")
b = made["benign_lockout"]["entities"]
check("a benign incident has benign evidence", tools.lookup_ip_reputation(b["ip"])["reputation"] == "clean" and any(l.get("type") == "helpdesk" for l in tools.search_logs("user", b["user"])["hits"]))
m = made["malware"]["entities"]
check("hosts are known to asset lookup", tools.get_host_info(m["host"])["owner"] == m["user"])
s = made["phishing"]["entities"]
domain = s["sender"].split("@")[1]
check("phishing domains resolve through search and reputation", tools.lookup_domain_reputation(domain)["reputation"] == "malicious" and tools.search_logs("domain", domain)["count"] >= 2)
check("original alerts still work", tools.get_alert("ALERT-1001")["id"] == "ALERT-1001" and alerts.get("ALERT-1003")["id"] == "ALERT-1003" and {"ALERT-1001", ids[0]} <= {x["id"] for x in alerts.list_all()})

print("Detection rules")
def auth_events(fails, success=True):
    e = [{"type": "auth", "user": "x", "ip": "203.0.113.9", "result": "fail", "count": fails}]
    return e + ([{"type": "auth", "user": "x", "ip": "203.0.113.9", "result": "success"}] if success else [])
check("below the threshold raises nothing", alerts._detect(auth_events(9)) == [])
check("failures without a success raise nothing", alerts._detect(auth_events(50, False)) == [])
check("at the threshold it fires", len(alerts._detect(auth_events(10))) == 1)
check("failures add up across events", len(alerts._detect([{"type": "auth", "user": "x", "ip": "i", "result": "fail", "count": 6}, {"type": "auth", "user": "x", "ip": "i", "result": "fail", "count": 6}, {"type": "auth", "user": "x", "ip": "i", "result": "success"}])) == 1)
check("different IPs don't combine", alerts._detect([{"type": "auth", "user": "x", "ip": "a", "result": "fail", "count": 20}, {"type": "auth", "user": "x", "ip": "b", "result": "success"}]) == [])
check("ordinary PowerShell raises nothing", alerts._detect([{"type": "process", "host": "h", "parent": "explorer.exe", "process": "powershell.exe", "cmdline": "powershell -enc x"}, {"type": "process", "host": "h", "parent": "WINWORD.EXE", "process": "powershell.exe", "cmdline": "powershell Get-Date"}]) == [])

print("Repeats of one incident")
before = len(db.query("SELECT 1 FROM generated_alerts"))
first, new1 = alerts.raise_from_events(auth_events(40), "brute_force", {"verdict": "true_positive"})
second, new2 = alerts.raise_from_events(auth_events(40), "brute_force", {"verdict": "true_positive"})
check("the repeat merges into the same alert", new1 and not new2 and first["id"] == second["id"] and second["occurrences"] == 2 and len(db.query("SELECT 1 FROM generated_alerts")) == before + 1)
check("an event batch with no detection makes no alert", alerts.raise_from_events(auth_events(2)) == (None, False))
db.execute("UPDATE generated_alerts SET created_at=0 WHERE id=?", (first["id"],))
third, new3 = alerts.raise_from_events(auth_events(40), "brute_force", {"verdict": "true_positive"})
check("after the window it's a new alert", new3 and third["id"] != first["id"])

print("Synthetic data can't point at anything real")
blob, rng = [], random.Random(7)
for i in range(200):
    events, intel, facts = alerts._simulate(rng.choice(alerts.SCENARIOS), rng)
    blob.append(json.dumps([events, intel, facts]))
text = " ".join(blob)
ips = set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text))
check("every IP is in a reserved documentation range", ips and all(i.startswith(("203.0.113.", "198.51.100.")) for i in ips), len(ips))
domains = set(re.findall(r"@([a-z0-9.-]+)", text)) | {d.replace("[.]", ".") for d in re.findall(r"hxxps://([a-z0-9\[\].-]+)/", text)}
check("every domain uses .example", domains and all(d.endswith(".example") for d in domains), len(domains))
check("links are defanged", "https://" not in text and "hxxps://" in text)
check("all kinds of incident occur, including injections and second victims", '"injection": true' in text and '"victim": "' in text and '"verdict": "false_positive"' in text)

print("Ground truth stays hidden from the agent")
for scenario, alert in made.items():
    seen = json.dumps(tools.get_alert(alert["id"]))
    check(f"{scenario}: get_alert has no verdict or scenario", not {"facts", "scenario", "verdict", "fingerprint"} & set(tools.get_alert(alert["id"])) and "_positive" not in seen)
check("nor do any listed alerts", not any({"facts", "scenario"} & set(x) for x in alerts.list_all()))
check("nor search results", "true_positive" not in json.dumps(tools.search_logs("user", made["brute_force"]["entities"]["user"])))

print("Demo runs, both architectures, every scenario")
agent.Run.wait_for_approval = lambda self, *a, **k: True
for arch in ("single", "multi"):
    for scenario in alerts.SCENARIOS:
        alert, _ = alerts.generate(scenario)
        rid = uuid.uuid4().hex[:8]
        db.create_run(rid, alert["id"], "demo", architecture=arch)
        run = agent.execute_job(rid, alert["id"], "demo", 1)
        events = db.get_events(rid)
        bad = [e["reason"] for e in events if e["kind"] == "policy" and e["decision"] == "deny"]
        expected = "false_positive" if scenario == "benign_lockout" else "true_positive"
        check(f"{arch}/{scenario}: report, no refused calls", run.report and run.report["verdict"] == expected and bad == [], bad)
        if scenario == "benign_lockout":
            check(f"{arch}: no containment on a false positive", run.actions == [])
    plan_valid = all(tools.validate_args(c[0], c[1]) is None for sc in alerts.SCENARIOS for st in alerts.demo_plan(alerts.generate(sc)[0]["id"])["steps"] for c in st[1])
    check(f"{arch}: every planned call passes validation", plan_valid)

print("Accuracy counts live runs only")
alert, _ = alerts.generate("benign_lockout")
for mode, verdict, n in (("demo", "false_positive", 2), ("live", "true_positive", 1), ("live", "false_positive", 1)):
    for _ in range(n):
        rid = uuid.uuid4().hex[:8]; db.create_run(rid, alert["id"], mode); db.finish_run(rid, "completed", {"verdict": verdict, "severity": "low"})
acc = alerts.accuracy(0)
check("a wrong call on a benign alert counts against it", (acc["runs"], acc["correct"]) == (2, 1), acc)

print("The API")
from fastapi.testclient import TestClient
from app import server
alerts.MAX_OPEN = 500
with TestClient(server.app) as web:
    for user, role in (("kashish", "tier1"), ("look", "viewer"), ("ana", "researcher")):
        auth.set_user(user, role, "a-long-password-1")
    def login(u):
        c = TestClient(server.app); c.post("/api/auth/login", json={"username": u, "password": "a-long-password-1"}); return c
    k, look, ana = login("kashish"), login("look"), login("ana")
    check("anonymous can't generate", TestClient(server.app).post("/api/alerts/generate", json={}).status_code == 401)
    check("viewers can't generate", look.post("/api/alerts/generate", json={}).status_code == 403)
    check("a bad scenario is refused", k.post("/api/alerts/generate", json={"scenario": "ransomware"}).status_code == 400)
    res = k.post("/api/alerts/generate", json={"scenario": "phishing"})
    new = res.json()["alert"]
    check("tier1 can generate", res.status_code == 201 and new["id"].startswith("ALERT-"))
    check("researchers can generate", ana.post("/api/alerts/generate", json={}).status_code == 201)
    listed = look.get("/api/alerts").json()
    row = next(x for x in listed if x["id"] == new["id"])
    check("viewers see it, newest first, marked new, without ground truth", listed[0]["id"] != "ALERT-1001" and row["triage"] == "new" and "facts" not in row and "scenario" not in row)
    run = k.post("/api/runs", json={"alert_id": new["id"], "mode": "demo"})
    check("a run can start on a generated alert", run.status_code == 202 and db.get_run(run.json()["run_id"])["alert_id"] == new["id"])
    check("its status updates", next(x for x in k.get("/api/alerts").json() if x["id"] == new["id"])["triage"] == "queued")
    check("an unknown alert is refused", k.post("/api/runs", json={"alert_id": "ALERT-9999", "mode": "demo"}).status_code == 404)
    prio = db.query("SELECT priority FROM jobs WHERE run_id=?", (run.json()["run_id"],))[0]["priority"]
    check("queue priority follows the alert's severity", prio == tools.PRIORITY[new["severity_hint"]])
    codes = [k.post("/api/alerts/generate", json={}).status_code for _ in range(12)]
    check("generating too fast is limited", 429 in codes, codes.count(429))
    alerts.MAX_OPEN = 1
    ana_full = ana.post("/api/alerts/generate", json={})
    check("a full backlog refuses more", ana_full.status_code == 409 and "waiting" in ana_full.json()["error"])
    alerts.MAX_OPEN = 500
    s = k.get("/api/obs/summary").json()
    check("the dashboard reports alerts and keeps its attention list", s["alert_queue"]["generated"] >= 1 and "accuracy" in s["alert_queue"] and isinstance(s["alerts"], list))
    db.execute("UPDATE generated_alerts SET created_at=1 WHERE severity_hint='critical'")
    db.execute("INSERT INTO generated_alerts (id, title, source, severity_hint, entities, description, fingerprint, facts, created_at) VALUES ('ALERT-X','t','s','critical','{}','d','fp','{}',1)")
    check("an untriaged critical alert raises a dashboard alert", "A critical alert isn't being triaged" in [a["title"] for a in k.get("/api/obs/summary").json()["alerts"]])

print("The stream")
env = {**os.environ, "SOC_DB_PATH": f"{TMP}/stream.db", "SOC_LOG_DIR": f"{TMP}/stream-logs", "MAX_OPEN_ALERTS": "2"}
p = subprocess.Popen([sys.executable, "-m", "app.alertgen", "--every", "0.1", "--max", "50"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(4)
p.terminate(); p.wait(timeout=10)
import sqlite3
count = sqlite3.connect(f"{TMP}/stream.db").execute("SELECT COUNT(*) FROM generated_alerts").fetchone()[0]
check("it makes alerts, pauses at the backlog limit, and stops cleanly", count == 2 and p.returncode == 0, count)

print(f"\n{'ALL PASSED' if not failures else f'{failures} FAILED'}")
sys.exit(1 if failures else 0)
