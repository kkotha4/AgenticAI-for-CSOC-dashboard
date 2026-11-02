"""Production settings, startup safety, browser protections, health checks, backups and deployment files.

    .venv/bin/python tests/test_production.py [path-to-python]

An optional Python path tests a separately built environment. Runs on temporary data and its own ports.
"""
import json, os, re, sqlite3, stat, subprocess, sys, tempfile, time, urllib.error, urllib.request
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.argv[1] if len(sys.argv) > 1 else sys.executable
APP_DIR = sys.argv[2] if len(sys.argv) > 2 else ROOT
TMP = tempfile.mkdtemp(prefix="soc-prod-test-")
DATA, SECRETS = f"{TMP}/data", f"{TMP}/secrets"
os.makedirs(DATA); os.makedirs(SECRETS)
KEY = f"{SECRETS}/mfa.key"
open(KEY, "wb").write(os.urandom(32)); os.chmod(KEY, 0o400)
PORT, BROKER = 8870, 7170
BASE = f"http://127.0.0.1:{PORT}"
ENV = {**{k: v for k, v in os.environ.items() if k not in ("ANTHROPIC_API_KEY", "GEMINI_API_KEY", "LLM_PROVIDER", "CLAUDE_CODE_OWNER", "MFA_REQUIRED", "COOKIE_SECURE")},
       "APP_ENV": "production", "COOKIE_SECURE": "1", "SOC_DB_PATH": f"{DATA}/soc.db", "SOC_AUDIT_PATH": f"{DATA}/audit.jsonl", "SOC_LOG_DIR": f"{DATA}/logs",
       "SOC_MFA_KEY_PATH": KEY, "BROKER_PORT": str(BROKER), "PYTHONUNBUFFERED": "1", "LOGINS_PER_MINUTE": "5"}
UVICORN = [PY, "-m", "uvicorn", "app.server:app", "--host", "127.0.0.1", "--port", str(PORT), "--proxy-headers", "--forwarded-allow-ips", "*"]
failures = 0


def check(label, ok, detail=""):
    global failures
    failures += not ok
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{f'  ({detail})' if detail != '' else ''}")


def http(method, path, body=None, headers=None):
    req = urllib.request.Request(BASE + path, json.dumps(body).encode() if body is not None else None, {"content-type": "application/json", **(headers or {})}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers


def refused(extra, role="web"):
    env = {**ENV, **extra}
    env = {k: v for k, v in env.items() if v is not None}
    command = UVICORN if role == "web" else [PY, "-m", "app.worker", "--id", "x"]
    try:
        done = subprocess.run(command, cwd=APP_DIR, env=env, capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        return False, "started anyway"
    return done.returncode != 0 and "Refusing to start" in done.stdout + done.stderr, done.returncode


print("Unsafe settings stop the app")
misplaced = f"{DATA}/mfa.key"
open(misplaced, "wb").write(os.urandom(32))
short = f"{SECRETS}/short.key"
open(short, "wb").write(b"short")
for label, extra in (("MFA switched off", {"MFA_REQUIRED": "0"}), ("cookies allowed over plain HTTP", {"COOKIE_SECURE": None}), ("no MFA key configured", {"SOC_MFA_KEY_PATH": None}),
                     ("a missing MFA key", {"SOC_MFA_KEY_PATH": f"{SECRETS}/nope"}), ("a key stored with the data", {"SOC_MFA_KEY_PATH": misplaced}), ("a key of the wrong size", {"SOC_MFA_KEY_PATH": short}),
                     ("someone's personal Claude Code login", {"LLM_PROVIDER": "claude_code"})):
    ok, detail = refused(extra)
    check(f"web refuses {label}", ok, detail)
os.remove(misplaced)
check("worker refuses a provider with no API key", refused({"LLM_PROVIDER": "gemini"}, "worker")[0])
check("worker refuses a personal Claude Code login", refused({"LLM_PROVIDER": "claude_code"}, "worker")[0])

print("A correct configuration starts")
log = open(f"{TMP}/s.log", "w")
procs = [subprocess.Popen(UVICORN, cwd=APP_DIR, env=ENV, stdout=log, stderr=log)]
try:
    end = time.time() + 30
    while "Uvicorn running" not in open(f"{TMP}/s.log").read() and time.time() < end:
        time.sleep(0.1)
    check("the server starts", procs[0].poll() is None)
    text = open(f"{TMP}/s.log").read()
    check("no demo accounts or passwords are created", "demo users" not in text and sqlite3.connect(f"{DATA}/soc.db").execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0)

    print("Health checks")
    status, body, _ = http("GET", "/healthz")
    check("/healthz works without a login and says nothing else", status == 200 and json.loads(body) == {"status": "ok"})
    status, body, _ = http("GET", "/readyz")
    check("/readyz checks the database, and reveals nothing", status == 200 and json.loads(body) == {"status": "ok"})

    print("Browser protections")
    for path in ("/", "/healthz", "/api/me", "/static/js/core.js"):
        _, _, headers = http("GET", path)
        csp = headers.get("content-security-policy", "")
        check(f"{path} has security headers", "script-src 'self'" in csp and "frame-ancestors 'none'" in csp and headers.get("x-content-type-options") == "nosniff"
              and headers.get("referrer-policy") == "no-referrer" and "max-age" in headers.get("strict-transport-security", ""))
    check("scripts can't be injected from elsewhere: no inline scripts in the page", "<script>" not in http("GET", "/")[1])
    for path in ("/docs", "/redoc", "/openapi.json"):
        check(f"{path} isn't published", http("GET", path)[0] == 404)
    for path in ("/static/../soc.db", "/static/%2e%2e/%2e%2e/soc.db", "/.env", "/soc.db", "/static/../app/server.py"):
        check(f"{path} can't be fetched", http("GET", path)[0] == 404)

    print("Accounts in production")
    code = ("import getpass, sys; getpass.getpass = lambda prompt='': 'first-admin-password'; sys.argv = ['auth', 'set-user', 'admin', 'admin']; from app import auth; auth.main()")
    check("the first admin is created on purpose, from the command line", subprocess.run([PY, "-c", code], cwd=APP_DIR, env=ENV, capture_output=True, text=True).returncode == 0)
    status, body, headers = http("POST", "/api/auth/login", {"username": "admin", "password": "first-admin-password"}, {"x-forwarded-for": "198.51.100.1"})
    cookie = headers.get("set-cookie", "").lower()
    check("login still needs MFA", status == 200 and json.loads(body)["next"] == "enroll")
    check("its cookie only travels over HTTPS", "secure" in cookie and "httponly" in cookie and "samesite=strict" in cookie, cookie.split(";", 1)[1].strip()[:70])
    status, body, headers = http("POST", "/api/auth/login", {"username": "admin", "password": "first-admin-password"}, {"x-forwarded-for": "198.51.100.2"})
    token = re.search(r"soc_mfa_pending=([^;]+)", headers.get("set-cookie", "")).group(1)
    status, body, _ = http("POST", "/api/auth/mfa/enroll", {}, {"cookie": f"soc_mfa_pending={token}"})
    check("MFA setup works with the key from the secrets folder", status == 200 and "secret" in json.loads(body))
    stored = sqlite3.connect(f"{DATA}/soc.db").execute("SELECT mfa_secret FROM users").fetchone()[0]
    check("the data folder holds only encrypted secrets, and not the key", json.loads(body)["secret"] not in stored and not os.path.exists(f"{DATA}/mfa.key"))

    print("Rate limits see real client addresses behind the proxy")
    codes = [http("POST", "/api/auth/login", {"username": "admin", "password": "wrong"}, {"x-forwarded-for": "203.0.113.50"})[0] for _ in range(7)]
    check("repeated failures from one client are throttled", codes[-1] == 429, codes)
    check("someone at another address isn't locked out", http("POST", "/api/auth/login", {"username": "admin", "password": "wrong"}, {"x-forwarded-for": "203.0.113.51"})[0] == 401)
    audit = open(f"{DATA}/audit.jsonl").read()
    check("the audit log records the client's address, not the proxy's", '"ip": "203.0.113.50"' in audit)

    print("Backups, while running")
    env = {**ENV, "SOC_BACKUP_DIR": f"{DATA}/backups"}
    made = [subprocess.run([PY, "-m", "app.backup", "--keep", "2"], cwd=APP_DIR, env=env, capture_output=True, text=True) for _ in range(1)]
    check("a backup completes", made[0].returncode == 0, made[0].stderr[-120:])
    files = sorted(os.listdir(f"{DATA}/backups"))
    db_file = next(f for f in files if f.endswith(".db"))
    restored = sqlite3.connect(f"{DATA}/backups/{db_file}")
    check("it restores, with the data", restored.execute("PRAGMA integrity_check").fetchone()[0] == "ok" and restored.execute("SELECT username FROM users").fetchone()[0] == "admin")
    check("it's readable only by its owner", all(stat.S_IMODE(os.stat(f"{DATA}/backups/{f}").st_mode) == 0o600 for f in files))
    check("it includes the audit log, not the MFA key", any(f.startswith("audit-") for f in files) and not any("key" in f for f in files))
    for _ in range(3):
        time.sleep(1.1)
        subprocess.run([PY, "-m", "app.backup", "--keep", "2"], cwd=APP_DIR, env=env, capture_output=True)
    check("old backups are removed", len([f for f in os.listdir(f"{DATA}/backups") if f.endswith(".db")]) == 2)

    print("Broker and worker in production")
    broker_env = {**ENV, "BROKER_BIND": "127.0.0.1"}
    procs.append(subprocess.Popen([PY, "-m", "app.broker"], cwd=APP_DIR, env=broker_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    time.sleep(0.6)
    procs.append(subprocess.Popen([PY, "-m", "app.worker", "--concurrency", "1"], cwd=APP_DIR, env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    time.sleep(2)
    check("workers and broker start with production settings", procs[-1].poll() is None and procs[-2].poll() is None)
finally:
    for p in procs:
        p.terminate()
    for p in procs:
        try:
            p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            p.kill(); p.wait()

print("Deployment files")
compose = yaml.safe_load(open(os.path.join(ROOT, "docker-compose.yml")))
services = compose["services"]
check("only Caddy publishes ports", [n for n, s in services.items() if s.get("ports")] == ["caddy"])
check("broker and worker aren't on the public network", "edge" not in services["broker"]["networks"] and "edge" not in services["worker"]["networks"])
check("the internal network has no internet route", compose["networks"]["internal"]["internal"] is True)
check("only workers get model API keys", not [k for k in services["web"]["environment"] if "API_KEY" in k] and "GEMINI_API_KEY" in services["worker"]["environment"])
check("only the web server gets the MFA key", services["web"]["secrets"] == ["mfa_key"] and not any(s.get("secrets") for n, s in services.items() if n != "web"))
check("no secret values are written in the file", not re.search(r"(sk-ant-|AIza)[A-Za-z0-9_-]{8,}", open(os.path.join(ROOT, "docker-compose.yml")).read()))
check("the broker has no access to the data", "volumes" not in services["broker"])
check("cookies are HTTPS-only", services["web"]["environment"]["COOKIE_SECURE"] == "1")
df = open(os.path.join(ROOT, "Dockerfile")).read()
check("the container doesn't run as root", re.search(r"^USER soc$", df, re.M) is not None)
check("the image copies only what it needs", "COPY . " not in df and "COPY app ./app" in df)
check("production mode is built in", "APP_ENV=production" in df)
check("the image ships nothing inside /data, which caused a startup race on new volumes", not re.search(r"(mkdir|COPY)[^\n]*/data/", df))
ignore = open(os.path.join(ROOT, ".dockerignore")).read().split("\n")
check("the build sees nothing unless listed", ignore[1] == "*" and {"!app/", "!static/", "!requirements.lock"} <= set(ignore))
git = open(os.path.join(ROOT, ".gitignore")).read().split("\n")
check("secrets are ignored by git", {".env", "secrets/", ".mfa.key", "soc.db*", "audit.jsonl", "logs/", "backups/"} <= set(git))
lock = [l for l in open(os.path.join(ROOT, "requirements.lock")).read().splitlines() if l.strip()]
check("every dependency is pinned", all("==" in l for l in lock), len(lock))
check("live events aren't buffered by the proxy", "flush_interval -1" in open(os.path.join(ROOT, "Caddyfile")).read())
example = open(os.path.join(ROOT, ".env.example")).read()
check(".env.example holds no real values", not re.search(r"(KEY|TOKEN|PASSWORD)=\S", example))

print(f"\n{'ALL PASSED' if not failures else f'{failures} FAILED'}")
sys.exit(1 if failures else 0)
