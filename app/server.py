"""HTTP API + live event stream (Server-Sent Events) for the UI.

The server is a producer only: it records the run, enqueues a job and returns.
Workers (app/worker.py) do the agent work. The server never blocks on an agent,
so it stays responsive however many investigations are in flight.
"""
import json
import logging
import math
import os
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import actions, alerts, auth, cache, circuit, config, db, llm, mfa, obs, queue, ratelimit, tools
from .agent import DAILY_BUDGET_USD
from .audit import audit
from .bus import bus


@asynccontextmanager
async def lifespan(_app):
    config.enforce("web")
    db.init()
    queue.init()
    cache.init()
    ratelimit.init()
    obs.init(prune=True)
    actions.init()
    circuit.init()
    obs.configure_logging("server", console=False)
    auth.init()
    if not config.is_production():  # production accounts are created deliberately: see DEPLOY.md
        auth.seed_demo_users()
    if not mfa.required():
        logging.getLogger("uvicorn.error").warning("MFA_REQUIRED=0: logging in needs only a password. Don't use this outside tests.")
    yield


# In production, don't publish an interactive map of the API.
_docs = {"docs_url": None, "redoc_url": None, "openapi_url": None} if config.is_production() else {}
app = FastAPI(title="SOC Triage Agent", lifespan=lifespan, **_docs)


class SecurityHeaders:
    """Browser protections on every response. Scripts may only come from this site, which limits what XSS can do."""
    HEADERS = [
        (b"content-security-policy", b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                                     b"connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"),
        (b"x-content-type-options", b"nosniff"),
        (b"referrer-policy", b"no-referrer"),
        (b"x-frame-options", b"DENY"),
    ]
    if config.is_production():
        HEADERS.append((b"strict-transport-security", b"max-age=31536000"))

    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.inner(scope, receive, send)

        async def with_headers(message):
            if message["type"] == "http.response.start":
                message.setdefault("headers", []).extend(self.HEADERS)
            await send(message)

        await self.inner(scope, receive, with_headers)


class ResponseMetrics:
    """Counts failed requests and all writes, by route template (not raw path, so labels stay bounded).
    A plain ASGI wrapper, because buffering middleware would interfere with the live event stream."""

    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.inner(scope, receive, send)

        async def counting_send(message):
            if message["type"] == "http.response.start":
                status = message["status"]
                if status >= 400 or scope["method"] != "GET":
                    route = getattr(scope.get("route"), "path", "unmatched")
                    obs.inc("http_responses", route=route, method=scope["method"], status=str(status))
            await send(message)

        await self.inner(scope, receive, counting_send)


app.add_middleware(ResponseMetrics)
app.add_middleware(SecurityHeaders)
STATIC = Path(__file__).resolve().parent.parent / "static"
# Only page shell, styles and scripts: every piece of data still sits behind an authenticated API.
app.mount("/static", StaticFiles(directory=STATIC), name="static")

# Admission control. Env vars so tests and deployments can tune them.
RUNS_PER_MINUTE = float(os.environ.get("RUNS_PER_MINUTE", 12))  # per client, sustained
RUN_BURST = float(os.environ.get("RUN_BURST", 5))               # per client, short burst
QUEUE_SOFT_LIMIT = int(os.environ.get("QUEUE_SOFT_LIMIT", 10))  # above this, shed medium/low alerts
QUEUE_HARD_LIMIT = int(os.environ.get("QUEUE_HARD_LIMIT", 20))  # above this, shed everything
LOGINS_PER_MINUTE = float(os.environ.get("LOGINS_PER_MINUTE", 5))  # per username + address, slows password guessing
COOKIE_NAME = "soc_session"
PENDING_COOKIE = "soc_mfa_pending"
NO_STORE = {"Cache-Control": "no-store"}  # for responses containing secrets
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"       # set to 1 when serving over HTTPS


def reject(status, message, retry_after):
    return JSONResponse({"error": message, "retry_after": retry_after}, status_code=status,
                        headers={"Retry-After": str(math.ceil(retry_after))})


def audit_auth(kind, **data):
    audit("auth", {"ts": time.time(), "kind": kind, **data})
    obs.inc("auth_events", kind=kind)  # the audit log has the names; the metric only has counts


def current_user(request: Request):
    """Authentication: every protected endpoint depends on this, so a missing check fails closed."""
    user = auth.user_for_token(request.cookies.get(COOKIE_NAME))
    if user is None:
        raise HTTPException(401, "Not logged in")
    return user


def require(permission):
    """Authorization: the caller must hold this permission."""
    def check(request: Request, user: dict = Depends(current_user)):
        if permission not in user["permissions"]:
            audit_auth("forbidden", user=user["username"], role=user["role"], needed=permission, path=request.url.path)
            raise HTTPException(403, f"Your role ({user['role']}) can't do this.")
        return user
    return check


def require_token(scope):
    """Authentication for machines: a service token in the Authorization header. Sessions don't count here."""
    def check(request: Request):
        header = request.headers.get("authorization", "")
        token = header[7:].strip() if header.lower().startswith("bearer ") else None
        name = auth.verify_token(token, scope)
        if name:
            return name
        ip = request.client.host
        wait = ratelimit.try_acquire(f"token-failure:{ip}", 10 / 60, 10)  # only failures spend from this bucket
        audit_auth("token_rejected" if not wait else "token_throttled", ip=ip, path=request.url.path)
        if wait:
            raise HTTPException(429, "Too many failed token attempts.", headers={"Retry-After": str(math.ceil(wait))})
        raise HTTPException(401, "A valid service token is required.", headers={"WWW-Authenticate": "Bearer"})
    return check


class LoginRequest(BaseModel):
    username: str
    password: str


class StartRequest(BaseModel):
    alert_id: str
    mode: str = "auto"  # auto | live | demo
    architecture: str = "single"  # single | multi


class InvalidateRequest(BaseModel):
    indicator: str | None = None  # None = flush everything


class ApprovalRequest(BaseModel):
    tool_use_id: str
    approved: bool


@app.get("/healthz")
def healthz():
    """Is the process up? Says nothing else, so it's safe to leave open."""
    return {"status": "ok"}


@app.get("/readyz")
def readyz():
    """Can it serve requests? Checks the database. Reveals no details if it can't."""
    try:
        db.query("SELECT 1 FROM runs LIMIT 1")
    except Exception:
        logging.getLogger("uvicorn.error").exception("Readiness check failed")
        return JSONResponse({"status": "unavailable"}, status_code=503)
    return {"status": "ok"}


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.post("/api/auth/login")
def login(req: LoginRequest, request: Request, response: Response):
    ip = request.client.host
    username = req.username[:64]
    # Limit by address first, so random usernames can't create unlimited limiter entries.
    wait = (ratelimit.try_acquire(f"login-ip:{ip}", 20 / 60, 20)
            or ratelimit.try_acquire(f"login:{ip}:{username}", LOGINS_PER_MINUTE / 60, LOGINS_PER_MINUTE))
    if wait:
        audit_auth("login_throttled", user=username, ip=ip)
        return reject(429, "Too many login attempts.", wait)
    if auth.authenticate(username, req.password) is None:
        audit_auth("login_failed", user=username, ip=ip)
        raise HTTPException(401, "Wrong username or password.")  # same message either way
    if not mfa.required():
        return _complete_login(response, username, ip)
    # The password was right, but that only earns the chance to give a second factor. No session yet.
    audit_auth("password_accepted", user=username, ip=ip)
    _set_pending(response, username)
    return {"ok": True, "next": "mfa" if mfa.is_enabled(username) else "enroll"}


def _complete_login(response, username, ip):
    audit_auth("login", user=username, ip=ip)
    response.set_cookie(COOKIE_NAME, auth.create_session(username), max_age=auth.SESSION_SECONDS,
                        httponly=True,        # page scripts can't read it, so XSS can't steal it
                        samesite="strict",    # other sites can't make the browser send it (CSRF)
                        secure=COOKIE_SECURE)
    response.delete_cookie(PENDING_COOKIE, path="/api/auth")
    return {"ok": True, "next": "done"}


def _set_pending(response, username):
    response.set_cookie(PENDING_COOKIE, mfa.create_pending(username), max_age=mfa.PENDING_SECONDS, path="/api/auth",
                        httponly=True, samesite="strict", secure=COOKIE_SECURE)


def _pending(request):
    token = request.cookies.get(PENDING_COOKIE)
    username = mfa.pending_user(token)
    if not username:
        raise HTTPException(401, "That login has expired. Enter your password again.")
    return token, username


def _mfa_limit(username, ip):
    # Per account, so starting new logins can't buy extra guesses at the 6 digits.
    wait = ratelimit.try_acquire(f"mfa:{username}", 10 / 300, 10)
    if wait:
        audit_auth("mfa_throttled", user=username, ip=ip)
        raise HTTPException(429, "Too many code attempts. Try again later.", headers={"Retry-After": str(math.ceil(wait))})


class CodeRequest(BaseModel):
    code: str


@app.post("/api/auth/mfa")
def mfa_verify(req: CodeRequest, request: Request, response: Response):
    token, username = _pending(request)
    ip = request.client.host
    _mfa_limit(username, ip)
    method = mfa.verify(username, req.code)
    if method is None:
        audit_auth("mfa_failed", user=username, ip=ip)
        if mfa.record_failure(token):
            raise HTTPException(401, "Too many wrong codes. Enter your password again.")
        raise HTTPException(400, "That code isn't right, or has already been used.")
    if method == "recovery":
        audit_auth("recovery_code_used", user=username, ip=ip, left=mfa.recovery_codes_left(username))
    mfa.end_pending(token)
    return _complete_login(response, username, ip)


@app.post("/api/auth/mfa/enroll")
def mfa_enroll(request: Request, response: Response):
    _, username = _pending(request)
    if mfa.is_enabled(username):
        raise HTTPException(409, "MFA is already set up. An admin can reset it if you've lost your device.")
    response.headers.update(NO_STORE)
    return {"username": username, **mfa.start_enrollment(username)}


@app.post("/api/auth/mfa/confirm")
def mfa_confirm(req: CodeRequest, request: Request, response: Response):
    token, username = _pending(request)
    ip = request.client.host
    _mfa_limit(username, ip)
    codes = mfa.confirm_enrollment(username, req.code)
    if codes is None:
        audit_auth("mfa_enroll_failed", user=username, ip=ip)
        if mfa.record_failure(token):
            raise HTTPException(401, "Too many wrong codes. Enter your password again.")
        raise HTTPException(400, "That code isn't right. Check the time on your phone and try the next code.")
    audit_auth("mfa_enrolled", user=username, ip=ip)
    mfa.end_pending(token)
    response.headers.update(NO_STORE)
    return {**_complete_login(response, username, ip), "recovery_codes": codes}


class InviteLookup(BaseModel):
    token: str


class InviteAccept(BaseModel):
    token: str
    password: str


def _invite_limit(ip):
    wait = ratelimit.try_acquire(f"invite:{ip}", 20 / 60, 20)
    if wait:
        raise HTTPException(429, "Too many attempts. Try again later.", headers={"Retry-After": str(math.ceil(wait))})


# The token travels in the page's #fragment and the request body, so it stays out of server logs.
@app.post("/api/invites/lookup")
def invite_lookup(req: InviteLookup, request: Request):
    _invite_limit(request.client.host)
    details = auth.invite_details(req.token)
    if not details:
        raise HTTPException(404, "This invitation isn't valid. It may have expired or already been used.")
    return {"username": details["username"], "role": details["role"]}


@app.post("/api/invites/accept")
def invite_accept(req: InviteAccept, request: Request, response: Response):
    ip = request.client.host
    _invite_limit(ip)
    try:
        username = auth.accept_invite(req.token, req.password)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if not username:
        raise HTTPException(404, "This invitation isn't valid. It may have expired or already been used.")
    audit_auth("invite_accepted", user=username, ip=ip)
    if not mfa.required():
        return _complete_login(response, username, ip)
    _set_pending(response, username)
    return {"ok": True, "next": "enroll"}


class InviteCreate(BaseModel):
    username: str
    role: str


@app.get("/api/users")
def users_list(admin: dict = Depends(require("users:manage"))):
    return {"users": [{**u, "mfa_enabled": bool(u["mfa_enabled"]), "you": u["username"] == admin["username"]} for u in auth.list_users()],
            "invites": auth.list_invites(), "roles": sorted(auth.PERMISSIONS)}


@app.post("/api/users/invites", status_code=201)
def users_invite(req: InviteCreate, response: Response, admin: dict = Depends(require("users:manage"))):
    username = req.username.strip()
    try:
        token = auth.create_invite(username, req.role, admin["username"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit_auth("invite_created", user=username, role=req.role, by=admin["username"])
    response.headers.update(NO_STORE)
    return {"token": token, "username": username, "expires_hours": auth.INVITE_SECONDS // 3600}


@app.delete("/api/users/invites/{username}")
def users_invite_revoke(username: str, admin: dict = Depends(require("users:manage"))):
    if not auth.revoke_invite(username):
        raise HTTPException(404, "No open invitation for that user.")
    audit_auth("invite_revoked", user=username, by=admin["username"])
    return {"ok": True}


@app.post("/api/users/{username}/reset-mfa")
def users_reset_mfa(username: str, admin: dict = Depends(require("users:manage"))):
    if username == admin["username"]:
        raise HTTPException(400, "You can't reset your own MFA here. Another admin must do it, so one stolen session can't remove the second factor.")
    if not mfa.reset(username):
        raise HTTPException(404, "No such user.")
    audit_auth("mfa_reset", user=username, by=admin["username"])
    return {"ok": True}


@app.delete("/api/users/{username}")
def users_remove(username: str, admin: dict = Depends(require("users:manage"))):
    if username == admin["username"]:
        raise HTTPException(400, "You can't remove your own account.")
    try:
        if not auth.remove_user(username):
            raise HTTPException(404, "No such user.")
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit_auth("user_removed", user=username, by=admin["username"])
    return {"ok": True}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(COOKIE_NAME)
    if token:
        auth.end_session(token)
    response.delete_cookie(COOKIE_NAME)
    mfa.end_pending(request.cookies.get(PENDING_COOKIE))
    response.delete_cookie(PENDING_COOKIE, path="/api/auth")
    return {"ok": True}


@app.get("/api/me")
def me(user: dict = Depends(current_user)):
    # Lets the page hide buttons. The server still checks every action; hiding is only a courtesy.
    return {"username": user["username"], "role": user["role"], "permissions": sorted(user["permissions"]),
            "approvable_tools": [t for t in auth.APPROVAL_PERMISSION if auth.can_decide(user, t)]}


@app.get("/api/alerts", dependencies=[Depends(require("view"))])
def list_alerts():
    return alerts.list_all()


class GenerateRequest(BaseModel):
    scenario: str | None = None  # None = a random one


@app.post("/api/alerts/generate", status_code=201)
def generate_alert(req: GenerateRequest, user: dict = Depends(require("alerts:generate"))):
    if req.scenario is not None and req.scenario not in alerts.SCENARIOS:
        raise HTTPException(400, f"scenario must be one of {', '.join(alerts.SCENARIOS)}")
    wait = ratelimit.try_acquire(f"generate:{user['username']}", 30 / 60, 10)
    if wait:
        return reject(429, "Generating alerts too quickly.", wait)
    try:
        alert, is_new = alerts.generate(req.scenario)
    except alerts.BacklogFull as e:
        return reject(409, f"{e} Triage some before generating more.", 30)
    if alert and is_new:
        bus.publish("alerts")
    return {"alert": alert, "new": is_new}


@app.post("/api/runs", status_code=202)  # 202 Accepted: queued, not done
def start_run(req: StartRequest, user: dict = Depends(require("run"))):
    alert = alerts.get(req.alert_id)
    if not alert:
        raise HTTPException(404, "Unknown alert")
    if req.mode not in ("auto", "live", "demo"):
        raise HTTPException(400, "mode must be auto, live or demo")
    if req.architecture not in ("single", "multi"):
        raise HTTPException(400, "architecture must be single or multi")

    refused = llm.live_refused_for(user["username"], req.mode)
    if refused:
        raise HTTPException(403, refused)

    # 1. Rate limit per user: protects against one noisy caller (429 = "you are sending too fast").
    wait = ratelimit.try_acquire(f"user:{user['username']}", RUNS_PER_MINUTE / 60, RUN_BURST)
    if wait:
        obs.inc("runs_rejected", reason="rate_limited")
        return reject(429, f"Too many runs from this user: limit is {RUNS_PER_MINUTE:g}/min.", wait)

    # 2. Backpressure on queue depth: protects the system as a whole (503 = "we are overloaded").
    #    Shed the least important work first, so a flood of low alerts can't delay a critical one.
    priority = tools.PRIORITY[alert["severity_hint"]]
    depth = queue.depth()
    if depth >= QUEUE_HARD_LIMIT or (depth >= QUEUE_SOFT_LIMIT and priority >= tools.PRIORITY["medium"]):
        obs.inc("runs_rejected", reason="queue_full")
        return reject(503, f"Queue is full ({depth} waiting). Shedding {'all' if depth >= QUEUE_HARD_LIMIT else 'medium/low'} alerts.", 30)

    run_id = uuid.uuid4().hex[:8]
    began = time.time()
    db.create_run(run_id, req.alert_id, req.mode, started_by=user["username"], architecture=req.architecture)
    queue.enqueue(run_id, req.alert_id, req.mode, priority)
    obs.record_span("api.enqueue", began, time.time(), run_id=run_id, alert=req.alert_id, mode=req.mode, architecture=req.architecture)
    obs.inc("runs_submitted", alert=req.alert_id, mode=req.mode, architecture=req.architecture)
    bus.publish("jobs")  # wake an idle worker now instead of on its next poll
    return {"run_id": run_id, "status": "queued"}


@app.get("/api/runs", dependencies=[Depends(require("view"))])
def list_runs():
    return db.list_runs()


@app.get("/api/obs/summary", dependencies=[Depends(require("dashboard:view"))])
def obs_summary():
    return obs.summary(DAILY_BUDGET_USD)


@app.get("/api/runs/{run_id}/trace", dependencies=[Depends(require("dashboard:view"))])
def run_trace(run_id: str):
    if not db.get_run(run_id):
        raise HTTPException(404, "Unknown run")
    return obs.trace(run_id)


@app.get("/metrics", dependencies=[Depends(require_token(auth.METRICS_SCOPE))])
def metrics():
    return PlainTextResponse(obs.prometheus(), media_type="text/plain; version=0.0.4")


@app.get("/api/queue", dependencies=[Depends(require("view"))])
def queue_stats():
    return queue.stats()


@app.get("/api/cache", dependencies=[Depends(require("view"))])
def cache_stats():
    return cache.stats()


@app.post("/api/cache/invalidate", dependencies=[Depends(require("cache:flush"))])
def cache_invalidate(req: InvalidateRequest):
    # e.g. an analyst marks an IP as a false positive: stale "malicious" verdicts must go everywhere.
    return {"deleted": cache.invalidate(req.indicator)}


@app.get("/api/runs/{run_id}/events", dependencies=[Depends(require("view"))])
def stream_events(run_id: str):
    if not db.get_run(run_id):
        raise HTTPException(404, "Unknown run")

    def generate():
        # Tail the events table, sleeping until a worker publishes on run.<id>.
        # Works the same for live runs and finished ones (replay).
        last_seq, last_send = -1, time.time()
        yield f"data: {json.dumps({'kind': 'queued'})}\n\n"
        with bus.subscribe(f"run.{run_id}") as sub:
            while True:
                sub.clear()
                events = db.get_events(run_id, after=last_seq)
                for event in events:
                    yield f"data: {json.dumps(event, default=str)}\n\n"
                    last_seq = event["seq"]
                    if event["kind"] == "end":
                        return
                if events:
                    last_send = time.time()
                elif time.time() - last_send > 15:
                    yield ": keep-alive\n\n"
                    last_send = time.time()
                if not events:
                    sub.wait()

    return StreamingResponse(generate(), media_type="text/event-stream")


@app.post("/api/runs/{run_id}/approve")
def approve(run_id: str, req: ApprovalRequest, user: dict = Depends(current_user)):
    # What's being approved comes from the database, never from the request,
    # so a caller can't relabel "isolate_host" as something they're allowed to approve.
    approval = db.get_approval(run_id, req.tool_use_id)
    if approval is None or approval["status"] != "pending":
        raise HTTPException(404, "No pending approval")
    if not auth.can_decide(user, approval["tool"]):
        audit_auth("approval_forbidden", user=user["username"], role=user["role"], run=run_id, tool=approval["tool"])
        raise HTTPException(403, f"Your role ({user['role']}) can't decide {approval['tool']}.")
    # The decider's name comes from the session, so it can't be forged.
    if not db.decide_approval(run_id, req.tool_use_id, "approved" if req.approved else "denied", user["username"]):
        raise HTTPException(404, "No pending approval")
    bus.publish(f"approval.{run_id}")  # wake the worker waiting on this run
    return {"ok": True}
