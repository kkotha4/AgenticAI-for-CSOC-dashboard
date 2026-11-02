"""The whole journey in a real browser, with real clicks, MFA on, and the live event stream.

    .venv/bin/python tests/test_ui_browser.py [screenshot-folder]

Admin login -> MFA setup -> invite -> accept and set up MFA -> investigate -> approve -> report -> dashboard.
Uses demo mode only, temporary data and its own ports. Needs Google Chrome; it stops only what it started.
"""
import base64, hashlib, hmac, json, os, re, shutil, struct, subprocess, sys, tempfile, time, urllib.request
from websockets.sync.client import connect

CHROME = os.environ.get("CHROME_BIN") or next((c for c in ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", shutil.which("google-chrome"), shutil.which("chromium")) if c and os.path.exists(c)), None)
if not CHROME:
    sys.exit("Google Chrome wasn't found. Set CHROME_BIN.")  # fails rather than skips, so CI can't pass by not testing
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix="soc-ui-test-")
SHOTS = sys.argv[1] if len(sys.argv) > 1 else None
PORT, BROKER, DEBUG = 8850, 7150, 9350
BASE = f"http://127.0.0.1:{PORT}"
ENV = {**os.environ, "SOC_DB_PATH": f"{TMP}/t.db", "SOC_AUDIT_PATH": f"{TMP}/a.jsonl", "SOC_LOG_DIR": f"{TMP}/logs", "SOC_MFA_KEY_PATH": f"{TMP}/k", "BROKER_PORT": str(BROKER), "PYTHONUNBUFFERED": "1"}
for key in ("ANTHROPIC_API_KEY", "GEMINI_API_KEY", "LLM_PROVIDER", "CLAUDE_CODE_OWNER", "MFA_REQUIRED"):
    ENV.pop(key, None)
failures = 0


def check(label, ok, detail=""):
    global failures
    failures += not ok
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{f'  ({detail})' if detail != '' else ''}")


def totp(secret, offset=0):
    counter = int(time.time() // 30) + offset
    h = hmac.new(base64.b32decode(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 15
    return f"{(struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff) % 1000000:06d}"


class Browser:
    def __init__(self):
        tab = json.load(urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{DEBUG}/json/new?about:blank", method="PUT")))
        self.ws = connect(tab["webSocketDebuggerUrl"], max_size=None, legacy=True)
        self.next_id, self.errors = 0, []
        for domain in ("Page", "Runtime", "Log"):
            self.send(f"{domain}.enable")

    def send(self, method, **params):
        self.next_id += 1
        self.ws.send(json.dumps({"id": self.next_id, "method": method, "params": params}))
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get("method") == "Runtime.exceptionThrown":
                self.errors.append(msg["params"]["exceptionDetails"].get("exception", {}).get("description", "script error")[:200])
            if msg.get("id") == self.next_id:
                return msg.get("result", {})

    def js(self, code):
        res = self.send("Runtime.evaluate", expression=code, returnByValue=True, awaitPromise=True)
        if "exceptionDetails" in res:
            raise RuntimeError(f"{code[:80]}: {res['exceptionDetails'].get('text')}")
        return res["result"].get("value")

    def go(self, url):
        self.send("Page.navigate", url=url)
        time.sleep(1.2)  # long enough for a reload triggered by a #fragment change
        self.wait("document.readyState === 'complete'")

    def wait(self, condition, timeout=30):
        end = time.time() + timeout
        while time.time() < end:
            if self.js(f"Boolean({condition})"):
                return True
            time.sleep(0.15)
        raise TimeoutError(condition)

    def visible(self, selector):
        return self.js(f"(() => {{ const e = document.querySelector({json.dumps(selector)}); return !!e && e.offsetParent !== null; }})()")

    def fill(self, selector, value):
        self.js(f"document.querySelector({json.dumps(selector)}).value = {json.dumps(value)}")

    def click(self, selector):
        """A real mouse click at the element's position, so anything covering it would make this fail."""
        self.wait(f"document.querySelector({json.dumps(selector)})")
        box = self.js(f"(() => {{ const e = document.querySelector({json.dumps(selector)}); e.scrollIntoView({{block:'center'}}); const r = e.getBoundingClientRect(); return [r.left + r.width / 2, r.top + r.height / 2]; }})()")
        time.sleep(0.05)
        for kind, extra in (("mouseMoved", {}), ("mousePressed", {"button": "left", "clickCount": 1}), ("mouseReleased", {"button": "left", "clickCount": 1})):
            self.send("Input.dispatchMouseEvent", type=kind, x=box[0], y=box[1], **extra)

    def text(self, selector):
        return self.js(f"document.querySelector({json.dumps(selector)})?.textContent ?? ''")

    def shot(self, name, width=1440, height=900, dark=False):
        if not SHOTS:
            return
        self.send("Emulation.setDeviceMetricsOverride", width=width, height=height, deviceScaleFactor=1, mobile=False)
        self.send("Emulation.setEmulatedMedia", features=[{"name": "prefers-color-scheme", "value": "dark" if dark else "light"}])
        time.sleep(0.3)
        data = self.send("Page.captureScreenshot", format="png")["data"]
        open(os.path.join(SHOTS, f"{name}.png"), "wb").write(base64.b64decode(data))
        self.send("Emulation.clearDeviceMetricsOverride")
        self.send("Emulation.setEmulatedMedia", features=[])

    def no_side_scroll(self, width):
        self.send("Emulation.setDeviceMetricsOverride", width=width, height=900, deviceScaleFactor=1, mobile=False)
        time.sleep(0.3)
        overflow = self.js("document.documentElement.scrollWidth - document.documentElement.clientWidth")
        self.send("Emulation.clearDeviceMetricsOverride")
        return overflow <= 0, overflow


python = sys.executable
quiet = dict(cwd=ROOT, env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
procs = [subprocess.Popen([python, "-m", "app.broker"], **quiet)]
time.sleep(0.5)
log = open(f"{TMP}/s.log", "w")
procs.append(subprocess.Popen([python, "-m", "uvicorn", "app.server:app", "--port", str(PORT)], cwd=ROOT, env=ENV, stdout=log, stderr=log))
procs.append(subprocess.Popen([python, "-m", "app.worker", "--id", "ui-test-worker", "--concurrency", "2"], **quiet))
procs.append(subprocess.Popen([CHROME, "--headless=new", "--disable-gpu", "--no-first-run", f"--user-data-dir={TMP}/chrome", f"--remote-debugging-port={DEBUG}", "--remote-allow-origins=*", *os.environ.get("CHROME_FLAGS", "").split(), "about:blank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
try:
    while "Uvicorn running" not in open(f"{TMP}/s.log").read():
        time.sleep(0.1)
    admin_password = re.search(r"^\s+admin\s+(\S+)$", open(f"{TMP}/s.log").read(), re.M).group(1)
    for _ in range(60):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{DEBUG}/json/version")
            break
        except OSError:
            time.sleep(0.25)
    b = Browser()

    print("Login and MFA setup")
    b.go(BASE + "/")
    b.wait("document.querySelector('#login-form') && document.querySelector('#login-form').offsetParent")
    check("logged out shows only the login form", b.visible("#login-form") and not b.visible("#shell") and not b.visible("#app"))
    b.shot("login")
    b.fill("#user", "admin"); b.fill("#pass", "wrong")
    b.click("#login-form button")
    b.wait("document.querySelector('#login-err').textContent")
    check("a wrong password shows an error", "Wrong username" in b.text("#login-err"))
    b.fill("#user", "admin"); b.fill("#pass", admin_password)
    b.click("#login-form button")
    b.wait("document.querySelector('#enroll-secret').textContent")
    check("a first login goes to MFA setup, with a QR code", b.visible("#enroll-form") and b.js("!!document.querySelector('#enroll-qr svg')"))
    b.shot("enroll")
    secret = b.text("#enroll-secret")
    b.fill("#enroll-code", "000000")
    b.click("#enroll-form button")
    b.wait("document.querySelector('#enroll-err').textContent")
    check("a wrong code shows an error and stays here", b.visible("#enroll-form"))
    b.fill("#enroll-code", totp(secret))
    b.click("#enroll-form button")
    b.wait("document.querySelector('#recovery-codes').children.length === 10")
    check("the right code shows recovery codes, and Continue waits for confirmation", b.js("document.querySelector('#recovery-done').disabled"))
    b.shot("recovery")
    b.click("#recovery-saved")
    b.wait("!document.querySelector('#recovery-done').disabled")
    b.click("#recovery-done")
    b.wait("document.querySelector('#shell') && document.querySelector('#shell').offsetParent")
    check("then the app opens", b.visible("#nav-users") and b.text("#me-name") == "admin")
    check("admin can't start runs", not b.js("!!document.querySelector('#run-controls') && document.querySelector('#run-controls').offsetParent"))

    print("Inviting someone")
    b.click("#nav-users")
    b.wait("document.querySelector('#users-table table')")
    check("the Users page opens", b.visible("#new-invite") and not b.visible("#app"))
    check("the role defaults to least privilege", b.js("document.querySelector('#new-role').value") == "viewer")
    b.fill("#new-user", "kashish")
    b.js("document.querySelector('#new-role').value = 'tier2'")
    b.click("#new-invite button")
    b.wait("document.querySelector('#invite-link').textContent")
    link = b.text("#invite-link")
    check("an invitation link appears", "#invite/soc_inv_" in link)
    b.wait("document.querySelector('#invites-table').textContent.includes('kashish')")
    b.shot("users")
    b.click("#logout")
    b.wait("document.querySelector('#login-form') && document.querySelector('#login-form').offsetParent")

    print("Accepting it")
    b.go(link)
    b.wait("document.querySelector('#invite-user').textContent")
    check("the link names the person and role", b.text("#invite-user") == "kashish" and b.text("#invite-role") == "tier2")
    b.fill("#invite-pass", "kashish-password-1"); b.fill("#invite-pass2", "kashish-password-1")
    b.click("#invite-form button")
    b.wait("document.querySelector('#enroll-secret').textContent")
    check("the token leaves the address bar", "soc_inv_" not in b.js("location.href"))
    kashish_secret = b.text("#enroll-secret")
    b.fill("#enroll-code", totp(kashish_secret))
    b.click("#enroll-form button")
    b.wait("document.querySelector('#recovery-codes').children.length === 10")
    b.click("#recovery-saved")
    b.wait("!document.querySelector('#recovery-done').disabled")
    b.click("#recovery-done")
    b.wait("document.querySelector('#alerts .alert')")
    check("they land in the app, with no Users page", b.text("#me-name") == "kashish" and not b.visible("#nav-users"))
    check("Investigate is the starting page", b.visible("#case-empty") and b.visible("#nav-dashboard"))
    b.shot("queue")

    print("Investigating")
    b.js("document.querySelector('#scenario').value = 'malware'")
    b.click("#generate")
    b.wait("document.querySelector('#generate-msg').textContent.startsWith('Created')")
    b.wait("document.querySelector('#case-name').textContent.includes('PowerShell')")
    check("a simulated alert opens straight away", b.visible("#case") and "not investigated" in b.text("#timeline").lower())
    check("Demo is the default, so a stray click can't use a model", b.js("document.querySelector('input[name=mode]:checked').value") == "demo")
    b.click("#go")
    b.wait("document.querySelector('.callout.ask')", 40)
    check("an approval request appears, live, from the event stream", "isolate" in b.text(".callout.ask").lower() and b.visible(".callout.ask .yes"))
    b.shot("approval")
    b.click(".callout.ask .yes")
    b.wait("[...document.querySelectorAll('.ev-head')].some((h) => h.textContent.includes('Approved by kashish'))", 20)
    check("the decision is recorded under their name", True)
    b.wait("document.querySelectorAll('.callout.ask').length === 2", 20)
    b.click("#timeline .ev:last-of-type .callout.ask .yes")
    b.wait("document.querySelector('.report')", 40)
    report = b.text(".report")
    check("the report appears, naming the actions taken", "critical" in report.lower() and "isolate host" in report.lower() and "block ip" in report.lower())
    check("the stats finish", "Report ready" in b.text("#stats"))
    b.shot("report")
    b.shot("report-dark", dark=True)
    b.wait("document.querySelector('#alerts .alert.sel .state') && !document.querySelector('#alerts .alert.sel .state').classList.contains('fresh')", 15)
    check("the queue shows it's triaged", "true positive" in b.text("#alerts .alert.sel .state"))
    check("the page has no sideways scroll at 1280", *b.no_side_scroll(1280))
    check("nor at 420", *b.no_side_scroll(420))
    b.shot("narrow", width=420, height=1000)
    check("the rerun button is back", not b.js("document.querySelector('#go').disabled"))

    print("Specialists")
    b.js("document.querySelector('#scenario').value = 'phishing'")
    b.click("#generate")
    b.wait("document.querySelector('#generate-msg').textContent.includes('ALERT') && document.querySelector('#case-name').textContent.includes('phishing')")
    b.click("input[name=architecture][value=multi] + span")
    b.click("#go")
    b.wait("document.querySelector('.report')", 40)
    check("specialists are labeled, the coordinator isn't", b.js("[...document.querySelectorAll('.tag.agent')].map((t) => t.textContent).includes('email_web')") and not b.js("[...document.querySelectorAll('.tag.agent')].map((t) => t.textContent).includes('coordinator')"))

    print("Dashboard")
    b.js("document.querySelector('#scenario').value = 'brute_force'")
    b.click("#generate")
    b.wait("document.querySelector('#generate-msg').textContent.includes('Created') && document.querySelector('#case-name').textContent.includes('login')")
    target = b.text("#case-id")
    b.click("#nav-dashboard")
    b.wait("document.querySelector('[data-open-alert]')", 15)
    check("it opens, and the agent page hides", b.visible("#obs") and not b.visible("#app"))
    check("demo results are labeled as scripted", "scripted" in b.text("#obs").lower())
    b.shot("dashboard", height=1500)
    b.shot("dashboard-dark", height=1500, dark=True)
    check("no sideways scroll at 1280", *b.no_side_scroll(1280))
    check("nor at 420", *b.no_side_scroll(420))
    b.shot("dashboard-narrow", width=420, height=1200)
    b.click(f"[data-open-alert='{target}']")
    b.wait(f"document.querySelector('#case-id').textContent === {json.dumps(target)} && document.querySelector('#app').offsetParent")
    check("clicking Next to triage opens that alert", b.visible("#case"))
    b.click("#nav-triage")
    check("no script errors anywhere in the journey", not b.errors, b.errors[:3])

    print("Logging back in")
    b.click("#logout")
    b.wait("document.querySelector('#login-form') && document.querySelector('#login-form').offsetParent")
    b.fill("#user", "kashish"); b.fill("#pass", "kashish-password-1")
    b.click("#login-form button")
    b.wait("document.querySelector('#mfa-form').offsetParent")
    check("a returning user is asked for a code", True)
    b.fill("#mfa-code", totp(kashish_secret, 1))
    b.click("#mfa-form button")
    b.wait("document.querySelector('#shell') && document.querySelector('#shell').offsetParent")
    check("the code logs them in", b.text("#me-name") == "kashish")
    check("still no script errors", not b.errors, b.errors[:3])
    check("no server errors in the whole journey", " 500 " not in open(f"{TMP}/s.log").read())
finally:
    for p in procs:
        p.terminate()
    for p in procs:
        try:
            p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            p.kill(); p.wait()
    shutil.rmtree(f"{TMP}/chrome", ignore_errors=True)

print(f"\n{'ALL PASSED' if not failures else f'{failures} FAILED'}")
sys.exit(1 if failures else 0)
