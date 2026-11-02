"""End-to-end auth test against a real server, worker and broker.

    .venv/bin/python tests/test_auth.py

Everything runs on its own ports with a temporary database and audit log, and only the
processes started here are stopped, so it is safe to run while the real app is up.
"""
import http.cookiejar
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

PORT, BROKER_PORT = 8791, 7091
BASE = f"http://127.0.0.1:{PORT}"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix="soc-auth-test-")
DB, AUDIT, SERVER_LOG = f"{TMP}/test.db", f"{TMP}/audit.jsonl", f"{TMP}/server.log"
ENV = {**os.environ, "SOC_DB_PATH": DB, "SOC_AUDIT_PATH": AUDIT, "SOC_LOG_DIR": f"{TMP}/logs", "MFA_REQUIRED": "0", "SOC_MFA_KEY_PATH": f"{TMP}/mfa.key", "BROKER_PORT": str(BROKER_PORT),
       "RUN_BURST": "100", "LOGINS_PER_MINUTE": "5", "PYTHONUNBUFFERED": "1"}
ENV.pop("ANTHROPIC_API_KEY", None)
failures = 0


def check(label, ok, detail=""):
    global failures
    failures += not ok
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{f'  ({detail})' if detail else ''}")


class Client:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.http = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(BASE + path, data, {"content-type": "application/json"}, method=method)
        try:
            with self.http.open(req, timeout=10) as r:
                return r.status, r.read().decode(), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(), dict(e.headers)

    def get(self, path):
        return self.call("GET", path)[0]

    def post(self, path, body=None):
        return self.call("POST", path, body if body is not None else {})[0]

    def login(self, username, password):
        return self.post("/api/auth/login", {"username": username, "password": password})


def sql(query, *params):
    conn = sqlite3.connect(DB, timeout=10)
    with conn:
        rows = conn.execute(query, params).fetchall()
    conn.close()
    return rows


def wait_for(fn, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        value = fn()
        if value:
            return value
        time.sleep(0.1)
    raise TimeoutError(fn)


def main():
    python = sys.executable
    procs = [subprocess.Popen([python, "-m", "app.broker"], cwd=ROOT, env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)]
    time.sleep(0.5)
    log = open(SERVER_LOG, "w")
    procs.append(subprocess.Popen([python, "-m", "uvicorn", "app.server:app", "--port", str(PORT)], cwd=ROOT, env=ENV, stdout=log, stderr=log))
    try:
        wait_for(lambda: "Uvicorn running" in open(SERVER_LOG).read())
        procs.append(subprocess.Popen([python, "-m", "app.worker", "--id", "auth-test-worker", "--concurrency", "2"],
                                      cwd=ROOT, env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        run_tests(dict(re.findall(r"^\s+(viewer|tier1|tier2|admin)\s+(\S+)$", open(SERVER_LOG).read(), re.M)))
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            p.wait(timeout=15)
    print(f"\n{'ALL PASSED' if not failures else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)


def run_tests(passwords):
    print("Seeding and password storage")
    check("first start creates one user per role", set(passwords) == {"viewer", "tier1", "tier2", "admin"}, sorted(passwords))
    stored = dict(sql("SELECT username, password_hash FROM users"))
    check("database holds salted hashes, not passwords",
          all(s.startswith("scrypt$") and passwords[u] not in s for u, s in stored.items()))
    check("same scheme still gives each user a unique salt", len({s.split("$")[1] for s in stored.values()}) == len(stored))

    print("Not logged in")
    anon = Client()
    for path in ["/api/alerts", "/api/runs", "/api/queue", "/api/cache", "/api/me", "/api/runs/x/events"]:
        check(f"GET {path} -> 401", anon.get(path) == 401)
    check("POST /api/runs -> 401", anon.post("/api/runs", {"alert_id": "ALERT-1001"}) == 401)
    check("POST approve -> 401", anon.post("/api/runs/x/approve", {"tool_use_id": "t", "approved": True}) == 401)
    check("POST cache flush -> 401", anon.post("/api/cache/invalidate") == 401)
    status, page, _ = anon.call("GET", "/")
    check("page shell loads but contains no alert data", status == 200 and "185.220.101.45" not in page and "j.doe" not in page)

    print("Login")
    wrong = Client().call("POST", "/api/auth/login", {"username": "tier1", "password": "wrong"})
    unknown = Client().call("POST", "/api/auth/login", {"username": "nobody", "password": "wrong"})
    check("wrong password -> 401", wrong[0] == 401)
    check("unknown user gets the identical response", unknown[:2] == wrong[:2])

    clients = {}
    for role in passwords:
        clients[role] = Client()
        status = clients[role].login(role, passwords[role])
        check(f"{role} logs in", status == 200)
    tier1, tier2, viewer, admin = clients["tier1"], clients["tier2"], clients["viewer"], clients["admin"]

    probe = Client()
    _, _, headers = probe.call("POST", "/api/auth/login", {"username": "viewer", "password": passwords["viewer"]})
    cookie = headers.get("set-cookie", "").lower()
    check("cookie is HttpOnly and SameSite=Strict", "httponly" in cookie and "samesite=strict" in cookie, cookie.split(";", 1)[1].strip())
    token = next(c.value for c in probe.jar if c.name == "soc_session")
    check("database stores only a hash of the session token", not sql("SELECT 1 FROM sessions WHERE token_hash=?", token))

    print("Permissions")
    alert = {"alert_id": "ALERT-1002", "mode": "demo"}
    check("viewer can read", viewer.get("/api/runs") == 200)
    check("viewer can't start a run -> 403", viewer.post("/api/runs", alert) == 403)
    check("admin can't start a run -> 403", admin.post("/api/runs", alert) == 403)
    check("tier1 can't flush the cache -> 403", tier1.post("/api/cache/invalidate") == 403)
    check("tier2 can flush the cache", tier2.post("/api/cache/invalidate") == 200)

    print("Approvals on a real run")
    status, body, _ = tier1.call("POST", "/api/runs", alert)
    run_id = json.loads(body)["run_id"]
    check("tier1 starts a run, recorded under their name",
          status == 202 and sql("SELECT started_by FROM runs WHERE id=?", run_id)[0][0] == "tier1")

    def pending(tool):
        rows = sql("SELECT tool_use_id FROM approvals WHERE run_id=? AND tool=? AND status='pending'", run_id, tool)
        return rows[0][0] if rows else None

    path = f"/api/runs/{run_id}/approve"
    isolate = wait_for(lambda: pending("isolate_host"))
    decision = {"tool_use_id": isolate, "approved": True}
    check("viewer can't approve -> 403", viewer.post(path, decision) == 403)
    check("admin can't approve (separation of duties) -> 403", admin.post(path, decision) == 403)
    check("anonymous can't approve -> 401", anon.post(path, decision) == 401)
    check("after all those attempts it is still pending", pending("isolate_host") == isolate)
    check("tier2 approves, and sending a fake name is ignored", tier2.post(path, {**decision, "decided_by": "ceo"}) == 200)
    check("recorded decider is the logged-in user",
          sql("SELECT decided_by FROM approvals WHERE tool_use_id=? AND run_id=?", isolate, run_id)[0][0] == "tier2")
    check("a decided approval can't be decided again -> 404", tier2.post(path, decision) == 404)

    block = wait_for(lambda: pending("block_ip"))
    check("tier1 can approve block_ip", tier1.post(path, {"tool_use_id": block, "approved": True}) == 200)
    wait_for(lambda: sql("SELECT 1 FROM runs WHERE id=? AND status='completed'", run_id))
    events = [json.loads(r[0]) for r in sql("SELECT data FROM events WHERE run_id=? AND kind='approval_result' ORDER BY seq", run_id)]
    check("trace names each decider", [(e["tool"], e["decided_by"], e["approved"]) for e in events]
          == [("isolate_host", "tier2", True), ("block_ip", "tier1", True)])
    audit = [json.loads(line) for line in open(AUDIT)]
    refused = {e["user"] for e in audit if e["kind"] == "approval_forbidden"}
    check("audit log records the refused approvals", refused == {"viewer", "admin"}, sorted(refused))
    status, body, _ = tier1.call("POST", "/api/runs", alert)
    tier1_run = json.loads(body)["run_id"]

    def tier1_pending(tool):
        rows = sql("SELECT tool_use_id FROM approvals WHERE run_id=? AND tool=? AND status='pending'", tier1_run, tool)
        return rows[0][0] if rows else None

    tid = wait_for(lambda: tier1_pending("isolate_host"))
    check("tier1 can approve isolate_host", tier1.post(f"/api/runs/{tier1_run}/approve", {"tool_use_id": tid, "approved": True}) == 200
          and sql("SELECT decided_by FROM approvals WHERE run_id=? AND tool_use_id=?", tier1_run, tid)[0][0] == "tier1")
    tid = wait_for(lambda: tier1_pending("block_ip"))
    tier1.post(f"/api/runs/{tier1_run}/approve", {"tool_use_id": tid, "approved": True})
    wait_for(lambda: sql("SELECT 1 FROM runs WHERE id=? AND status='completed'", tier1_run))
    check("tier1 still can't manage users or flush the cache", tier1.get("/api/users") == 403 and tier1.post("/api/cache/invalidate") == 403)
    check("audit log records failed logins", any(e["kind"] == "login_failed" and e["user"] == "nobody" for e in audit))
    check("passwords never reach the audit log", not any(p in open(AUDIT).read() for p in passwords.values()))

    print("Dashboard is its own permission")
    for role, expected in (("viewer", 403), ("tier1", 200), ("admin", 200)):
        check(f"{role} dashboard summary -> {expected}", clients[role].get("/api/obs/summary") == expected)
        check(f"{role} run trace -> {expected}", clients[role].get(f"/api/runs/{run_id}/trace") == expected)
    check("tier2 can open the dashboard", tier2.get("/api/obs/summary") == 200)
    check("anonymous dashboard -> 401", anon.get("/api/obs/summary") == 401)
    check("viewer can still use basic read endpoints", viewer.get("/api/queue") == 200 and viewer.get("/api/runs") == 200)
    check("the page only offers it to allowed roles", json.loads(viewer.call("GET", "/api/me")[1])["permissions"].count("dashboard:view") == 0
          and "dashboard:view" in json.loads(tier1.call("GET", "/api/me")[1])["permissions"])
    check("the dashboard doesn't give tier1 more power", tier1.post("/api/cache/invalidate") == 403 and tier1.get("/api/users") == 403)

    print("Metrics needs a service token, not a login")
    def token_cli(*args):
        return subprocess.run([sys.executable, "-m", "app.auth", *args], cwd=ROOT, env=ENV, capture_output=True, text=True)

    def scrape(token=None, cookie=None, path="/metrics", method="GET"):
        headers = {}
        if token is not None:
            headers["authorization"] = f"Bearer {token}"
        if cookie:
            headers["cookie"] = f"soc_session={cookie}"
        req = urllib.request.Request(BASE + path, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read().decode(), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(), dict(e.headers)

    check("no credentials -> 401, naming the scheme", (lambda r: r[0] == 401 and r[2].get("www-authenticate") == "Bearer")(scrape()))
    for role in passwords:
        cookie = next(c.value for c in clients[role].jar if c.name == "soc_session")
        check(f"{role} login session can't read metrics", scrape(cookie=cookie)[0] == 401)
    created = token_cli("create-token", "prometheus")
    metrics_token = created.stdout.strip().splitlines()[-1]
    check("CLI creates a token and shows it once", created.returncode == 0 and metrics_token.startswith("soc_svc_"))
    check("only its hash is stored", not sql("SELECT 1 FROM service_tokens WHERE token_hash=?", metrics_token) and "soc_svc_" not in str(sql("SELECT * FROM service_tokens")))
    check("a duplicate name is refused", token_cli("create-token", "prometheus").returncode != 0)
    status, text, _ = scrape(metrics_token)
    check("a valid token reads metrics", status == 200 and "soc_queue_depth" in text)
    check("last use is recorded", sql("SELECT last_used_at FROM service_tokens WHERE name='prometheus'")[0][0] is not None)
    check("list-tokens never prints a token", "soc_svc_" not in token_cli("list-tokens").stdout and "prometheus" in token_cli("list-tokens").stdout)
    for path, method in [("/api/me", "GET"), ("/api/obs/summary", "GET"), ("/api/runs", "GET"), ("/api/cache/invalidate", "POST"), (f"/api/runs/{run_id}/approve", "POST")]:
        check(f"the token can't reach {method} {path}", scrape(metrics_token, path=path, method=method)[0] == 401)
    check("a token in the URL doesn't work", scrape(path=f"/metrics?token={metrics_token}")[0] == 401)
    check("a token isn't accepted as a session cookie", scrape(cookie=metrics_token)[0] == 401)
    second = token_cli("create-token", "prometheus-2").stdout.strip().splitlines()[-1]
    check("rotation: a second token works alongside the first", scrape(second)[0] == 200 and scrape(metrics_token)[0] == 200)
    check("revoking works", token_cli("revoke-token", "prometheus").returncode == 0 and scrape(metrics_token)[0] == 401)
    check("revoking one leaves the other working", scrape(second)[0] == 200)
    check("revoking an unknown token reports failure", token_cli("revoke-token", "nope").returncode != 0)
    check("a token isn't written to the audit log", metrics_token not in open(AUDIT).read() and second not in open(AUDIT).read())
    codes = [scrape("wrong-token")[0] for _ in range(11)]
    check("repeated bad tokens get throttled -> 429", codes[-1] == 429 and codes[0] == 401, codes)
    check("rejected tokens are audited", any(json.loads(l)["kind"] == "token_rejected" for l in open(AUDIT)))

    print("Named users, researchers and account management")
    python = sys.executable

    def set_user_cli(username, role, first, second=None):
        # Stands in for typing at the password prompts; the rest is the real command.
        code = ("import getpass, sys; answers = iter([%r, %r]); getpass.getpass = lambda prompt='': next(answers); "
                "sys.argv = ['auth', 'set-user', %r, %r]; from app import auth; auth.main()") % (first, second if second is not None else first, username, role)
        return subprocess.run([python, "-c", code], cwd=ROOT, env=ENV, capture_output=True, text=True)

    def admin_cli(*args):
        return subprocess.run([python, "-m", "app.auth", *args], cwd=ROOT, env=ENV, capture_output=True, text=True)

    check("a short password is refused", set_user_cli("kashish", "tier2", "short").returncode != 0)
    check("mismatched passwords are refused", set_user_cli("kashish", "tier2", "a-long-password-1", "a-long-password-2").returncode != 0)
    check("a bad username is refused", set_user_cli("Kashish Kothari!", "tier2", "a-long-password-1").returncode != 0)
    check("an unknown role is refused", set_user_cli("kashish", "superuser", "a-long-password-1").returncode != 0)
    check("none of those created an account", not sql("SELECT 1 FROM users WHERE username='kashish'"))
    check("kashish can be created", set_user_cli("kashish", "tier2", "kashish-password-1").returncode == 0)
    check("a researcher can be created", set_user_cli("researcher.ana", "researcher", "researcher-password-1").returncode == 0)
    check("the password isn't printed or stored", "researcher-password-1" not in str(sql("SELECT * FROM users")) and "researcher-password-1" not in admin_cli("list-users").stdout)
    kashish, ana = Client(), Client()
    check("kashish logs in with their own name", kashish.login("kashish", "kashish-password-1") == 200 and json.loads(kashish.call("GET", "/api/me")[1])["username"] == "kashish")
    check("the researcher logs in", ana.login("researcher.ana", "researcher-password-1") == 200)
    check("researchers can read and use the dashboard", ana.get("/api/runs") == 200 and ana.get("/api/obs/summary") == 200)
    check("researchers can't flush the cache", ana.post("/api/cache/invalidate") == 403)
    check("researchers can't read /metrics with a login", scrape(cookie=next(c.value for c in ana.jar if c.name == "soc_session"))[0] in (401, 429))  # 429: the check above used up the failure limit
    status, body, _ = ana.call("POST", "/api/runs", alert)
    named_run = json.loads(body)["run_id"]
    check("researchers can start a run, recorded under their name", status == 202 and sql("SELECT started_by FROM runs WHERE id=?", named_run)[0][0] == "researcher.ana")

    def pending_on(tool):
        rows = sql("SELECT tool_use_id FROM approvals WHERE run_id=? AND tool=? AND status='pending'", named_run, tool)
        return rows[0][0] if rows else None

    named_path = f"/api/runs/{named_run}/approve"
    tid = wait_for(lambda: pending_on("isolate_host"))
    check("researchers can't approve containment", ana.post(named_path, {"tool_use_id": tid, "approved": True}) == 403)
    check("kashish can, and the record names them", kashish.post(named_path, {"tool_use_id": tid, "approved": True}) == 200
          and sql("SELECT decided_by FROM approvals WHERE run_id=? AND tool_use_id=?", named_run, tid)[0][0] == "kashish")
    tid = wait_for(lambda: pending_on("block_ip"))
    kashish.post(named_path, {"tool_use_id": tid, "approved": True})
    wait_for(lambda: sql("SELECT 1 FROM runs WHERE id=? AND status='completed'", named_run))
    listing = admin_cli("list-users").stdout
    check("list-users shows names and roles, not hashes", "kashish" in listing and "researcher" in listing and "scrypt" not in listing)
    check("the last admin can't be removed or demoted", admin_cli("remove-user", "admin").returncode != 0 and set_user_cli("admin", "viewer", "a-long-password-1").returncode != 0)
    check("admin still works after that", admin.get("/api/obs/summary") == 200)
    check("removing a user works", admin_cli("remove-user", "researcher.ana").returncode == 0)
    check("it ends their session at once", ana.get("/api/me") == 401)
    check("and they can't log in", Client().login("researcher.ana", "researcher-password-1") == 401)
    check("their name stays on past runs", sql("SELECT started_by FROM runs WHERE id=?", named_run)[0][0] == "researcher.ana")
    check("removing an unknown user reports failure", admin_cli("remove-user", "nobody").returncode != 0)
    check("account changes are audited", {"user_saved", "user_removed"} <= {json.loads(l)["kind"] for l in open(AUDIT)})
    check("passwords never reach the audit log (named users)", "kashish-password-1" not in open(AUDIT).read())

    print("Session lifetime")
    check("a made-up token is rejected", forged_status("not-a-real-token") == 401)
    sql("UPDATE users SET role='viewer' WHERE username='tier2'")
    check("role change applies to a live session at once", tier2.post("/api/runs", alert) == 403)
    sql("UPDATE users SET role='tier2' WHERE username='tier2'")
    check("logout: tier2 still logged in before", tier2.get("/api/me") == 200)
    stolen = next(c.value for c in tier2.jar if c.name == "soc_session")
    tier2.post("/api/auth/logout")
    check("logout revokes on the server: an old copy of the token stops working", forged_status(stolen) == 401)
    sql("UPDATE sessions SET expires_at=0 WHERE username='tier1'")
    check("expired session -> 401", tier1.get("/api/me") == 401)

    print("Password guessing")
    guesser, codes = Client(), []
    for _ in range(7):
        codes.append(guesser.login("admin", "guess"))
    check("repeated guesses get throttled -> 429", codes[-1] == 429, codes)


def forged_status(token):
    req = urllib.request.Request(BASE + "/api/me", headers={"cookie": f"soc_session={token}"})
    try:
        return urllib.request.urlopen(req, timeout=5).status
    except urllib.error.HTTPError as e:
        return e.code


if __name__ == "__main__":
    main()
