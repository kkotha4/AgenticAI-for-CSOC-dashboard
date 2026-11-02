"""Record the product demo: real clicks in real Chrome, on a temporary server with simulated data.

    .venv/bin/python scripts/record_demo.py <output-folder> <frames-folder>

Demo mode only, so no model usage. A made-up account on a temporary database: nothing real can appear on screen.
Frames and narration go to <frames-folder>; scripts/encode_demo.py turns them into a video and GIF.
Narration uses macOS text-to-speech, and the walkthrough waits for each line, so voice and picture stay together.
"""
import base64, hashlib, hmac, json, os, re, shutil, struct, subprocess, sys, tempfile, threading, time, urllib.request
from websockets.sync.client import connect

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT, FRAMES = sys.argv[1], sys.argv[2]
TMP = tempfile.mkdtemp(prefix="soc-demo-")
PORT, BROKER, DEBUG = 8860, 7160, 9360
BASE = f"http://127.0.0.1:{PORT}"
USER, PASSWORD = "analyst", "demo-only-password"
VOICE = os.environ.get("DEMO_VOICE", "Samantha")
# How the captions should sound where the written form would be misread.
SPOKEN = [("SOC Triage Agent", "Sock Triage Agent"), ("an AI analyst", "an A I analyst"), ("AI tools", "A I tools"), ("MFA", "M F A"), ("Demo mode", "demo mode")]
ENV = {**os.environ, "SOC_DB_PATH": f"{TMP}/t.db", "SOC_AUDIT_PATH": f"{TMP}/a.jsonl", "SOC_LOG_DIR": f"{TMP}/logs", "SOC_MFA_KEY_PATH": f"{TMP}/k", "BROKER_PORT": str(BROKER), "PYTHONUNBUFFERED": "1"}
for key in ("ANTHROPIC_API_KEY", "GEMINI_API_KEY", "LLM_PROVIDER", "CLAUDE_CODE_OWNER", "MFA_REQUIRED"):
    ENV.pop(key, None)

# Injected on every page load, for the recording only: a visible pointer and a caption bar.
OVERLAY = """
window.__demo = {
  ready() {
    if (document.getElementById('demo-cursor') || !document.body) return;
    const style = document.createElement('style');
    style.textContent = `#demo-cursor{position:fixed;left:640px;top:400px;width:22px;height:22px;margin:-11px 0 0 -11px;border-radius:50%;background:rgba(79,70,229,.32);border:2px solid #4f46e5;z-index:99999;pointer-events:none;transition:left .45s ease,top .45s ease,transform .12s}
      #demo-cursor.down{transform:scale(.65);background:rgba(79,70,229,.7)}
      #demo-caption{position:fixed;left:50%;bottom:22px;transform:translateX(-50%);max-width:820px;background:rgba(15,18,28,.93);color:#fff;font:500 16px/1.4 system-ui,sans-serif;padding:11px 20px;border-radius:12px;z-index:99998;text-align:center;pointer-events:none;box-shadow:0 6px 24px rgba(0,0,0,.3)}
      #demo-caption:empty{display:none}`;
    document.head.appendChild(style);
    const c = document.createElement('div'); c.id = 'demo-cursor'; document.body.appendChild(c);
    const t = document.createElement('div'); t.id = 'demo-caption'; document.body.appendChild(t);
    t.textContent = sessionStorage.getItem('demo-caption') || '';
  },
  caption(text) { this.ready(); sessionStorage.setItem('demo-caption', text); document.getElementById('demo-caption').textContent = text; },
  move(x, y) { this.ready(); const c = document.getElementById('demo-cursor'); c.style.left = x + 'px'; c.style.top = y + 'px'; },
  press(on) { document.getElementById('demo-cursor').classList.toggle('down', on); },
};
document.addEventListener('DOMContentLoaded', () => window.__demo.ready());
"""


def totp(secret):
    counter = int(time.time() // 30)
    h = hmac.new(base64.b32decode(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 15
    return f"{(struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff) % 1000000:06d}"


class Session:
    def __init__(self, url):
        self.ws = connect(url, max_size=None, legacy=True)
        self.next_id = 0

    def send(self, method, **params):
        self.next_id += 1
        self.ws.send(json.dumps({"id": self.next_id, "method": method, "params": params}))
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == self.next_id:
                return msg.get("result", {})

    def js(self, code):
        res = self.send("Runtime.evaluate", expression=code, returnByValue=True, awaitPromise=True)
        if "exceptionDetails" in res:
            raise RuntimeError(f"{code[:90]}: {res['exceptionDetails'].get('text')}")
        return res["result"].get("value")


python = os.path.join(ROOT, ".venv/bin/python")
quiet = dict(cwd=ROOT, env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
seed = """
from app import auth, db, mfa
db.init(); auth.init()
auth.set_user(%r, 'tier2', %r)
secret = mfa.start_enrollment(%r)['secret']
step = int(__import__('time').time() // 30) - 1
mfa.confirm_enrollment(%r, mfa.totp(secret, step))
print(secret)
""" % (USER, PASSWORD, USER, USER)
secret = subprocess.run([python, "-c", seed], cwd=ROOT, env=ENV, capture_output=True, text=True, check=True).stdout.strip().splitlines()[-1]
procs = [subprocess.Popen([python, "-m", "app.broker"], **quiet)]
time.sleep(0.5)
log = open(f"{TMP}/s.log", "w")
procs.append(subprocess.Popen([python, "-m", "uvicorn", "app.server:app", "--port", str(PORT)], cwd=ROOT, env=ENV, stdout=log, stderr=log))
procs.append(subprocess.Popen([python, "-m", "app.worker", "--id", "worker-1", "--concurrency", "2"], **quiet))
procs.append(subprocess.Popen([CHROME, "--headless=new", "--disable-gpu", "--no-first-run", "--hide-scrollbars", "--window-size=1280,800", f"--user-data-dir={TMP}/chrome", f"--remote-debugging-port={DEBUG}", "--remote-allow-origins=*", "about:blank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
recording = threading.Event()
frames = []


def capture(url):
    s = Session(url)
    while recording.is_set():
        started = time.time()
        try:
            data = s.send("Page.captureScreenshot", format="jpeg", quality=82)["data"]
        except Exception:  # a page reload can drop this connection; the next frame just comes slightly later
            time.sleep(0.2)
            try:
                s = Session(url)
            except Exception:
                pass
            continue
        path = os.path.join(FRAMES, f"f{len(frames):05d}.jpg")
        open(path, "wb").write(base64.b64decode(data))
        frames.append((path, started))
        time.sleep(max(0, 0.08 - (time.time() - started)))


try:
    while "Uvicorn running" not in open(f"{TMP}/s.log").read():
        time.sleep(0.1)
    for _ in range(60):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{DEBUG}/json/version")
            break
        except OSError:
            time.sleep(0.25)
    tab = json.load(urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{DEBUG}/json/new?about:blank", method="PUT")))
    b = Session(tab["webSocketDebuggerUrl"])
    for domain in ("Page", "Runtime"):
        b.send(f"{domain}.enable")
    b.send("Page.addScriptToEvaluateOnNewDocument", source=OVERLAY)
    b.send("Emulation.setEmulatedMedia", features=[{"name": "prefers-color-scheme", "value": "light"}])

    def wait(condition, timeout=45):
        end = time.time() + timeout
        while time.time() < end:
            if b.js(f"Boolean({condition})"):
                return
            time.sleep(0.1)
        raise TimeoutError(condition)

    spoken_until = [0.0]
    narration = []

    def cap(text, hold=0.0):
        # Never talk over the previous line, and stay on this one until it has been said.
        time.sleep(max(0, spoken_until[0] - time.time()))
        b.js(f"window.__demo.caption({json.dumps(text)})")
        words = text
        for written, said in SPOKEN:
            words = words.replace(written, said)
        audio = os.path.join(FRAMES, f"line{len(narration):02d}.aiff")
        subprocess.run(["say", "-v", VOICE, "-r", "178", "-o", audio, words], check=True)
        info = subprocess.run(["afinfo", audio], capture_output=True, text=True, check=True).stdout
        length = float(re.search(r"estimated duration: ([\d.]+)", info).group(1))
        now = time.time()
        narration.append({"audio": audio, "start": now, "duration": length, "text": text})
        spoken_until[0] = now + length + 0.35
        time.sleep(hold)

    def click(selector, hold=0.35):
        wait(f"document.querySelector({json.dumps(selector)})")
        x, y = b.js(f"(() => {{ const e = document.querySelector({json.dumps(selector)}); e.scrollIntoView({{block:'nearest'}}); const r = e.getBoundingClientRect(); return [r.left + r.width / 2, r.top + r.height / 2]; }})()")
        b.js(f"window.__demo.move({x}, {y})")
        time.sleep(0.5)
        b.js("window.__demo.press(true)")
        for kind, extra in (("mouseMoved", {}), ("mousePressed", {"button": "left", "clickCount": 1}), ("mouseReleased", {"button": "left", "clickCount": 1})):
            b.send("Input.dispatchMouseEvent", type=kind, x=x, y=y, **extra)
        b.js("window.__demo.press(false)")
        time.sleep(hold)

    def type_into(selector, text):
        click(selector, 0.1)
        for i in range(1, len(text) + 1):
            b.js(f"document.querySelector({json.dumps(selector)}).value = {json.dumps(text[:i])}")
            time.sleep(0.035)

    def scroll_to(pane, selector, block="start"):
        b.js(f"document.querySelector({json.dumps(selector)})?.scrollIntoView({{behavior:'smooth', block:{json.dumps(block)}}})")
        time.sleep(1.1)

    def still(name):
        """A clean screenshot for the README: no pointer or caption."""
        b.js("document.getElementById('demo-cursor').hidden = true; document.getElementById('demo-caption').style.visibility = 'hidden'")
        data = b.send("Page.captureScreenshot", format="png")["data"]
        open(os.path.join(OUT, f"{name}.png"), "wb").write(base64.b64decode(data))
        b.js("document.getElementById('demo-cursor').hidden = false; document.getElementById('demo-caption').style.visibility = ''")

    b.send("Page.navigate", url=BASE + "/")
    wait("document.querySelector('#login-form') && document.querySelector('#login-form').offsetParent")
    recording.set()
    thread = threading.Thread(target=capture, args=(tab["webSocketDebuggerUrl"],), daemon=True)
    thread.start()

    cap("SOC Triage Agent: an AI analyst that investigates alerts, with people in control", 2.8)
    still("login")
    cap("Every login needs a password and an authenticator code", 0.6)
    type_into("#user", USER)
    type_into("#pass", PASSWORD)
    click("#login-form button")
    wait("document.querySelector('#mfa-form').offsetParent")
    type_into("#mfa-code", totp(secret))
    click("#mfa-form button")
    time.sleep(1)
    wait("document.querySelector('#alerts .alert')")
    b.js("window.__demo.ready()")
    cap("Simulated log events pass through detection rules, and the rules raise alerts", 1.2)
    for scenario in ("benign_lockout", "malware"):
        b.js(f"document.querySelector('#scenario').value = {json.dumps(scenario)}")
        click("#generate", 1.1)
    target_malware = b.js("document.querySelector('#case-id').textContent")
    click("#filters .chip[data-filter=all]", 0.3)
    b.js("document.querySelector('#alerts').scrollTop = 0")
    cap("The queue puts what most needs a person first", 2.4)
    still("alert-queue")

    cap("This email reports a phishing attempt. Its body hides instructions aimed at AI tools.", 0.5)
    click(".alert[data-id='ALERT-1003']", 1.4)
    click("input[name=architecture][value=multi] + span", 0.5)
    cap("A coordinator delegates to read-only specialists. This walkthrough uses scripted Demo mode.", 1.6)
    click("#go", 0.2)
    # The scripted run finishes faster than anyone can talk about it, so narrate it afterwards, moment by moment.
    wait("document.querySelector('.report')")
    time.sleep(max(0, spoken_until[0] - time.time()) + 0.3)
    b.js("document.querySelector('.ev.guardrail').scrollIntoView({behavior:'smooth', block:'center'})")
    time.sleep(1.0)
    cap("The hidden instructions are flagged, and treated as data rather than as commands", 2.0)
    time.sleep(max(0, spoken_until[0] - time.time()))
    b.js("document.querySelector('.ev.denied').scrollIntoView({behavior:'smooth', block:'center'})")
    time.sleep(1.0)
    cap("A specialist tries a containment action. It's outside its scope, so code refuses it.", 2.0)
    still("policy-block")
    time.sleep(max(0, spoken_until[0] - time.time()))
    scroll_to(".work-pane", ".report")
    cap("The report separates confirmed facts from inference, and lists what it couldn't check", 3.0)
    still("report")

    time.sleep(max(0, spoken_until[0] - time.time()))
    cap("Actions that change something need an analyst's approval", 0.4)
    click(f".alert[data-id='{target_malware}']", 1.0)
    click("input[name=architecture][value=single] + span", 0.5)
    click("#go", 0.2)
    wait("document.querySelector('.callout.ask')")
    time.sleep(0.5)
    cap("The run pauses here. Nothing changes until a person decides.", 2.6)
    still("approval")
    click(".callout.ask .yes", 0.3)
    wait("document.querySelectorAll('.callout.ask').length === 2")
    time.sleep(1.2)
    click("#timeline .ev:last-of-type .callout.ask .yes", 0.3)
    wait("document.querySelector('.report')")
    time.sleep(0.5)
    scroll_to(".work-pane", ".report")
    cap("Each decision is recorded under the analyst's name, and each action runs only once", 2.8)

    click("#nav-dashboard", 0.4)
    wait("document.querySelector('[data-open-alert], #obs .db-card')")
    time.sleep(1.2)
    cap("The dashboard shows what needs attention, and labels scripted demo runs as not being results", 3.4)
    still("dashboard")
    b.js("document.querySelector('.content').scrollTo({top: 780, behavior: 'smooth'})")
    time.sleep(1.6)
    cap("Every investigation is searchable, with its verdict, model, loops and cost", 2.8)
    runs = json.loads(b.js("fetch('/api/runs').then((r) => r.text())"))
    multi = next(r for r in runs if r["architecture"] == "multi")
    b.js(f"loadTrace({json.dumps(multi['id'])}, {json.dumps(multi['alert_id'])})")
    time.sleep(1.4)
    cap("A trace shows where the time went, with specialists running side by side", 3.2)
    still("trace")
    b.js("document.querySelector('.content').scrollTo({top: 0, behavior: 'smooth'})")
    cap("Policy checks, human approval, MFA, retries and an audit trail, all outside the model", 2.0)
    time.sleep(max(0, spoken_until[0] - time.time()) + 0.5)
    recording.clear()
    thread.join(timeout=5)
    b.send("Emulation.setEmulatedMedia", features=[{"name": "prefers-color-scheme", "value": "dark"}])
    time.sleep(0.4)
    b.js("sessionStorage.removeItem('demo-caption'); window.__demo.caption('')")
    still("dashboard-dark")
    json.dump([[p, t] for p, t in frames], open(os.path.join(FRAMES, "frames.json"), "w"))
    json.dump(narration, open(os.path.join(FRAMES, "narration.json"), "w"))
    print(f"{len(frames)} frames over {frames[-1][1] - frames[0][1]:.0f}s; server errors: {open(f'{TMP}/s.log').read().count(' 500 ')}")
finally:
    recording.clear()
    for p in procs:
        p.terminate()
    for p in procs:
        try:
            p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            p.kill(); p.wait()
    shutil.rmtree(TMP, ignore_errors=True)
