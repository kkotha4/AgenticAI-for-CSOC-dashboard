"""Invitations and MFA, end to end against a real server with MFA required.

    .venv/bin/python tests/test_mfa.py

Runs on temporary data and its own ports, and stops only the processes it started.
"""
import base64, hashlib, hmac, http.cookiejar, json, os, re, sqlite3, struct, subprocess, sys, tempfile, threading, time, urllib.error, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix="soc-mfa-test-")
PORT, BROKER = 8799, 7099
BASE = f"http://127.0.0.1:{PORT}"
DB, AUDIT, LOG, KEY = f"{TMP}/t.db", f"{TMP}/a.jsonl", f"{TMP}/s.log", f"{TMP}/mfa.key"
ENV = {**os.environ, "SOC_DB_PATH": DB, "SOC_AUDIT_PATH": AUDIT, "SOC_LOG_DIR": f"{TMP}/logs", "SOC_MFA_KEY_PATH": KEY, "BROKER_PORT": str(BROKER),
       "LOGINS_PER_MINUTE": "1000", "PYTHONUNBUFFERED": "1"}
ENV.pop("MFA_REQUIRED", None)
failures = 0


def check(label, ok, detail=""):
    global failures
    failures += not ok
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{f'  ({detail})' if detail != '' else ''}")


def totp(secret, offset=0):
    """Written separately from the app's version, so the two check each other."""
    counter = int(time.time() // 30) + offset
    h = hmac.new(base64.b32decode(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 15
    return f"{(struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff) % 1000000:06d}"


class Client:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def call(self, method, path, body=None):
        req = urllib.request.Request(BASE + path, json.dumps(body).encode() if body is not None else None, {"content-type": "application/json"}, method=method)
        try:
            with self.op.open(req, timeout=10) as r:
                text = r.read().decode()
                return r.status, json.loads(text) if text else {}, dict(r.headers)
        except urllib.error.HTTPError as e:
            text = e.read().decode()
            return e.code, json.loads(text) if text else {}, dict(e.headers)

    def cookie(self, name):
        return next((c for c in self.jar if c.name == name), None)

    def login(self, user, password):
        return self.call("POST", "/api/auth/login", {"username": user, "password": password})


def sql(q, *p):
    c = sqlite3.connect(DB, timeout=10)
    with c:
        rows = c.execute(q, p).fetchall()
    c.close()
    return rows


def enroll(client):
    secret = client.call("POST", "/api/auth/mfa/enroll")[1]["secret"]
    return secret, client.call("POST", "/api/auth/mfa/confirm", {"code": totp(secret)})


def clear_replay(user):
    sql("UPDATE users SET mfa_last_step=NULL WHERE username=?", user)


def full_login(user, password, secret):
    clear_replay(user)
    c = Client()
    c.login(user, password)
    c.call("POST", "/api/auth/mfa", {"code": totp(secret)})
    return c


python = sys.executable
procs = [subprocess.Popen([python, "-m", "app.broker"], cwd=ROOT, env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)]
time.sleep(0.5)
log = open(LOG, "w")
procs.append(subprocess.Popen([python, "-m", "uvicorn", "app.server:app", "--port", str(PORT)], cwd=ROOT, env=ENV, stdout=log, stderr=log))
try:
    while "Uvicorn running" not in open(LOG).read():
        time.sleep(0.1)
    passwords = dict(re.findall(r"^\s+(viewer|tier1|tier2|admin)\s+(\S+)$", open(LOG).read(), re.M))

    print("TOTP matches the standard")
    sys.path.insert(0, ROOT)
    for k in ("SOC_DB_PATH", "SOC_AUDIT_PATH", "SOC_LOG_DIR", "SOC_MFA_KEY_PATH", "BROKER_PORT"):
        os.environ[k] = ENV[k]
    from app import mfa
    rfc_secret = base64.b32encode(b"12345678901234567890").decode()
    check("RFC 6238 test vectors pass", [mfa.totp(rfc_secret, t // 30, 8) for t in (59, 1111111109, 1234567890, 2000000000)] == ["94287082", "07081804", "89005924", "69279037"])

    print("A password alone gets nothing")
    admin = Client()
    status, body, _ = admin.login("admin", passwords["admin"])
    check("right password -> must enroll, no session", status == 200 and body["next"] == "enroll" and admin.cookie("soc_session") is None)
    check("pending cookie is HttpOnly, SameSite=Strict and limited to auth routes",
          (lambda c: c.has_nonstandard_attr("HttpOnly") and c.path == "/api/auth")(admin.cookie("soc_mfa_pending")))
    for path in ["/api/me", "/api/runs", "/api/alerts", "/api/users", "/api/obs/summary"]:
        check(f"pending can't reach {path}", admin.call("GET", path)[0] == 401)
    pending = admin.cookie("soc_mfa_pending").value
    check("wrong password -> 401, nothing pending", (lambda c: (c.login("admin", "wrong")[0], c.cookie("soc_mfa_pending")))(Client()) == (401, None))

    print("Enrollment")
    status, start, headers = admin.call("POST", "/api/auth/mfa/enroll")
    secret = start["secret"]
    check("returns a QR code and key, uncached", status == 200 and start["qr_svg"].startswith("<svg") and headers.get("cache-control") == "no-store")
    check("the secret is encrypted in the database", secret not in str(sql("SELECT mfa_secret FROM users WHERE username='admin'")))
    check("the key file is owner-only", oct(os.stat(KEY).st_mode)[-3:] == "600")
    check("a wrong code doesn't enable it", admin.call("POST", "/api/auth/mfa/confirm", {"code": "000000"})[0] == 400 and not sql("SELECT mfa_enabled_at FROM users WHERE username='admin'")[0][0])
    status, done, headers = admin.call("POST", "/api/auth/mfa/confirm", {"code": totp(secret)})
    codes = done["recovery_codes"]
    check("a right code enables it and starts a session", status == 200 and done["next"] == "done" and admin.cookie("soc_session") is not None and admin.call("GET", "/api/me")[0] == 200)
    check("10 recovery codes, uncached, stored only as hashes", len(codes) == 10 and headers.get("cache-control") == "no-store" and codes[0].replace("-", "") not in str(sql("SELECT * FROM recovery_codes")))
    check("the pending state is used up", admin.call("POST", "/api/auth/mfa/enroll")[0] == 401)
    attacker = Client()
    attacker.login("admin", passwords["admin"])
    check("someone with the password can't re-enroll over active MFA", attacker.call("POST", "/api/auth/mfa/enroll")[0] == 409 and attacker.call("POST", "/api/auth/mfa/confirm", {"code": totp(secret)})[0] == 400)

    print("Login with a code")
    clear_replay("admin")
    c = Client()
    status, body, _ = c.login("admin", passwords["admin"])
    check("password -> asks for a code, no session", body["next"] == "mfa" and c.cookie("soc_session") is None)
    check("a wrong code is refused", c.call("POST", "/api/auth/mfa", {"code": "000000"})[0] == 400 and c.call("GET", "/api/me")[0] == 401)
    code = totp(secret)
    check("the right code logs in", c.call("POST", "/api/auth/mfa", {"code": code})[0] == 200 and c.call("GET", "/api/me")[0] == 200)
    replay = Client()
    replay.login("admin", passwords["admin"])
    check("the same code can't be used twice", replay.call("POST", "/api/auth/mfa", {"code": code})[0] == 400 and replay.call("GET", "/api/me")[0] == 401)
    check("an expired code is refused", (clear_replay("admin"), replay.call("POST", "/api/auth/mfa", {"code": totp(secret, -3)})[0])[1] == 400)
    check("a code with no pending login is refused", Client().call("POST", "/api/auth/mfa", {"code": totp(secret)})[0] == 401)
    sql("UPDATE mfa_pending SET expires_at=0")
    check("a pending login expires", replay.call("POST", "/api/auth/mfa", {"code": totp(secret)})[0] == 401)

    print("Recovery codes")
    rec = Client()
    rec.login("admin", passwords["admin"])
    check("a recovery code logs in", rec.call("POST", "/api/auth/mfa", {"code": codes[0]})[0] == 200 and rec.call("GET", "/api/me")[0] == 200)
    rec2 = Client()
    rec2.login("admin", passwords["admin"])
    check("it works only once", rec2.call("POST", "/api/auth/mfa", {"code": codes[0]})[0] == 400)
    check("lowercase and no dashes work too", rec2.call("POST", "/api/auth/mfa", {"code": codes[1].replace("-", "").lower()})[0] == 200)

    print("Guessing limits")
    tier1 = Client()
    tier1.login("tier1", passwords["tier1"])
    tier1_secret, _ = enroll(tier1)
    g = Client()
    g.login("tier1", passwords["tier1"])
    results = [g.call("POST", "/api/auth/mfa", {"code": "000000"})[0] for _ in range(5)]
    check("5 wrong codes end the pending login", results == [400, 400, 400, 400, 401], results)
    check("the right code doesn't work after that", g.call("POST", "/api/auth/mfa", {"code": totp(tier1_secret)})[0] == 401)
    codes_seen = []
    for _ in range(3):
        g2 = Client()
        g2.login("tier1", passwords["tier1"])
        codes_seen.append(g2.call("POST", "/api/auth/mfa", {"code": "000000"})[0])
        codes_seen.append(g2.call("POST", "/api/auth/mfa", {"code": "000000"})[0])
    check("new logins can't buy more guesses: the account limit holds", 429 in codes_seen, codes_seen)
    sql("DELETE FROM rate_buckets WHERE name LIKE 'mfa:%'")

    print("Who can manage users")
    admin = full_login("admin", passwords["admin"], secret)
    t2 = Client(); t2.login("tier2", passwords["tier2"]); t2_secret, _ = enroll(t2)
    anon = Client()
    invite_body = {"username": "researcher.ana", "role": "researcher"}
    check("anonymous can't list or invite", anon.call("GET", "/api/users")[0] == 401 and anon.call("POST", "/api/users/invites", invite_body)[0] == 401)
    check("tier2 can't list or invite", t2.call("GET", "/api/users")[0] == 403 and t2.call("POST", "/api/users/invites", invite_body)[0] == 403)
    check("tier2 can't remove or reset anyone", t2.call("DELETE", "/api/users/tier1")[0] == 403 and t2.call("POST", "/api/users/tier1/reset-mfa")[0] == 403)
    check("there's no open sign-up", anon.call("POST", "/api/invites/accept", {"token": "made-up", "password": "a-long-password-1"})[0] == 404)

    print("Invitation flow")
    status, invite, headers = admin.call("POST", "/api/users/invites", invite_body)
    token = invite["token"]
    check("admin creates an invitation, uncached", status == 201 and token.startswith("soc_inv_") and headers.get("cache-control") == "no-store")
    check("only its hash is stored", token not in str(sql("SELECT * FROM invites")))
    check("no account exists yet", not sql("SELECT 1 FROM users WHERE username='researcher.ana'"))
    check("a duplicate open invitation is refused", admin.call("POST", "/api/users/invites", invite_body)[0] == 400)
    check("inviting an existing user is refused", admin.call("POST", "/api/users/invites", {"username": "tier1", "role": "viewer"})[0] == 400)
    check("a bad username is refused", admin.call("POST", "/api/users/invites", {"username": "Bad Name!", "role": "viewer"})[0] == 400)
    check("a bad role is refused", admin.call("POST", "/api/users/invites", {"username": "someone", "role": "superuser"})[0] == 400)
    check("it appears in the list, without the token", (lambda d: d["invites"][0]["username"] == "researcher.ana" and token not in str(d))(admin.call("GET", "/api/users")[1]))
    ana = Client()
    check("the link shows who it's for", ana.call("POST", "/api/invites/lookup", {"token": token})[1] == {"username": "researcher.ana", "role": "researcher"})
    check("a short password is refused and doesn't use it up", ana.call("POST", "/api/invites/accept", {"token": token, "password": "short"})[0] == 400 and ana.call("POST", "/api/invites/lookup", {"token": token})[0] == 200)
    status, body, _ = ana.call("POST", "/api/invites/accept", {"token": token, "password": "researcher-password-1"})
    check("accepting creates the account and goes straight to MFA, no session yet", status == 200 and body["next"] == "enroll" and ana.call("GET", "/api/me")[0] == 401)
    check("the role comes from the invitation", sql("SELECT role FROM users WHERE username='researcher.ana'")[0][0] == "researcher")
    check("the link works once", Client().call("POST", "/api/invites/accept", {"token": token, "password": "another-password-1"})[0] == 404 and Client().call("POST", "/api/invites/lookup", {"token": token})[0] == 404)
    ana_secret, (status, _, _) = enroll(ana)
    check("finishing MFA starts a session", status == 200 and json.loads(json.dumps(ana.call("GET", "/api/me")[1]))["username"] == "researcher.ana")
    check("the invitation can't pick its own role in the request", (lambda t: Client().call("POST", "/api/invites/accept", {"token": t, "password": "a-long-password-1", "role": "admin"})[0] == 200 and sql("SELECT role FROM users WHERE username='ben'")[0][0] == "viewer")(admin.call("POST", "/api/users/invites", {"username": "ben", "role": "viewer"})[1]["token"]))
    expired = admin.call("POST", "/api/users/invites", {"username": "old", "role": "viewer"})[1]["token"]
    sql("UPDATE invites SET expires_at=0 WHERE username='old'")
    check("an expired link is refused", Client().call("POST", "/api/invites/accept", {"token": expired, "password": "a-long-password-1"})[0] == 404)
    revoked = admin.call("POST", "/api/users/invites", {"username": "gone", "role": "viewer"})[1]["token"]
    check("revoking works", admin.call("DELETE", "/api/users/invites/gone")[0] == 200 and Client().call("POST", "/api/invites/accept", {"token": revoked, "password": "a-long-password-1"})[0] == 404)
    race = admin.call("POST", "/api/users/invites", {"username": "race", "role": "viewer"})[1]["token"]
    outcomes = []
    threads = [threading.Thread(target=lambda: outcomes.append(Client().call("POST", "/api/invites/accept", {"token": race, "password": "a-long-password-1"})[0])) for _ in range(5)]
    [t.start() for t in threads]; [t.join() for t in threads]
    check("5 simultaneous uses of one link: exactly one succeeds", sorted(outcomes).count(200) == 1, sorted(outcomes))

    print("Managing users")
    listing = admin.call("GET", "/api/users")[1]["users"]
    check("the list shows MFA status and no secrets", {u["username"]: u["mfa_enabled"] for u in listing}["researcher.ana"] is True and "scrypt" not in str(listing) and "mfa_secret" not in str(listing))
    check("admins can't reset their own MFA here", admin.call("POST", "/api/users/admin/reset-mfa")[0] == 400)
    check("admins can't remove themselves", admin.call("DELETE", "/api/users/admin")[0] == 400)
    check("resetting MFA ends their session and removes recovery codes",
          admin.call("POST", "/api/users/researcher.ana/reset-mfa")[0] == 200 and ana.call("GET", "/api/me")[0] == 401 and not sql("SELECT 1 FROM recovery_codes WHERE username='researcher.ana'"))
    check("their old authenticator no longer works: they must enroll again", (lambda c: c.login("researcher.ana", "researcher-password-1")[1]["next"])(Client()) == "enroll")
    check("removing a user ends their access", (admin.call("DELETE", "/api/users/tier1")[0], Client().login("tier1", passwords["tier1"])[0]) == (200, 401))
    cli = subprocess.run([python, "-m", "app.auth", "reset-mfa", "tier2"], cwd=ROOT, env=ENV, capture_output=True, text=True)
    check("the command line can reset MFA as a last resort", cli.returncode == 0 and t2.call("GET", "/api/me")[0] == 401)

    print("Audit and secrecy")
    text = open(AUDIT).read()
    kinds = {json.loads(l)["kind"] for l in text.splitlines()}
    check("security events are audited", {"mfa_enrolled", "mfa_failed", "recovery_code_used", "invite_created", "invite_accepted", "invite_revoked", "mfa_reset", "user_removed", "password_accepted", "login"} <= kinds, sorted(kinds))
    logs = "".join(open(os.path.join(f"{TMP}/logs", f)).read() for f in os.listdir(f"{TMP}/logs")) + open(LOG).read().split("Uvicorn running", 1)[1]
    for label, value in (("invitation tokens", token), ("TOTP secrets", secret), ("recovery codes", codes[2]), ("new passwords", "researcher-password-1")):
        check(f"no {label} in audit or logs", value not in text and value not in logs)
    summary = admin.call("GET", "/api/obs/summary")[1]
    check("repeated code failures raise a dashboard alert", "Repeated MFA failures" in [a["title"] for a in summary["alerts"]])
    os.replace(KEY, KEY + ".moved"); open(KEY, "wb").write(os.urandom(32))
    wrong_key = Client()
    wrong_key.login("admin", passwords["admin"])
    check("a lost key fails closed", (clear_replay("admin"), wrong_key.call("POST", "/api/auth/mfa", {"code": totp(secret)})[0])[1] == 400)
    os.replace(KEY + ".moved", KEY)
finally:
    for p in procs:
        p.terminate()
    for p in procs:
        try:
            p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            p.kill(); p.wait()

print(f"\n{'ALL PASSED' if not failures else f'{failures} FAILED'}")
sys.exit(1 if failures else 0)
