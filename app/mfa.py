"""Multi-factor authentication with authenticator apps (TOTP, RFC 6238), and one-time recovery codes.

A password only opens a short-lived pending state: no session exists until the second factor passes.

TOTP secrets have to be readable to check codes, so unlike passwords they can't be hashed. They're
encrypted with a key kept outside the database (SOC_MFA_KEY_PATH), so a stolen database alone can't
generate codes. In production that key belongs in a secrets manager or KMS.
"""
import base64
import hashlib
import hmac
import io
import os
import secrets
import struct
import time
from pathlib import Path
from urllib.parse import quote, urlencode

import segno
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import db

ISSUER = "SOC Triage Agent"
STEP_SECONDS = 30
WINDOW = 1                # accept one step either side, to allow for clock drift
PENDING_SECONDS = 300     # how long a password check stays valid while waiting for the second factor
PENDING_ATTEMPTS = 5      # wrong codes allowed per pending login
RECOVERY_CODES = 10
KEY_PATH = Path(os.environ.get("SOC_MFA_KEY_PATH", Path(__file__).resolve().parent.parent / ".mfa.key"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS mfa_pending (
    token_hash TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS recovery_codes (
    code_hash TEXT PRIMARY KEY,
    username  TEXT NOT NULL
);
"""


def init():
    db.executescript(SCHEMA)
    first_upgrade = "mfa_secret" not in {r["name"] for r in db.query("PRAGMA table_info(users)")}
    db.add_column_if_missing("users", "mfa_secret", "TEXT")       # encrypted
    db.add_column_if_missing("users", "mfa_enabled_at", "REAL")   # NULL until a code has been confirmed
    db.add_column_if_missing("users", "mfa_last_step", "INTEGER")  # stops a code being used twice
    if first_upgrade:
        db.execute("DELETE FROM sessions")  # sessions from before MFA existed never passed a second factor


def required():
    return os.environ.get("MFA_REQUIRED", "1") != "0"


# --- encryption at rest ----------------------------------------------------

def _key():
    if not KEY_PATH.exists() and os.environ.get("APP_ENV", "").lower() == "production":
        raise RuntimeError("The MFA key is missing. A new one would lock everyone out, so it's never created automatically in production.")
    if not KEY_PATH.exists():
        KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        try:  # exclusive and owner-only, so two processes can't race and others can't read it
            fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(AESGCM.generate_key(256))
        except FileExistsError:
            pass
    return KEY_PATH.read_bytes()


def _encrypt(secret, username):
    nonce = secrets.token_bytes(12)
    # The username is bound in, so a secret can't be copied onto another account row.
    return base64.b64encode(nonce + AESGCM(_key()).encrypt(nonce, secret.encode(), username.encode())).decode()


def _decrypt(stored, username):
    raw = base64.b64decode(stored)
    return AESGCM(_key()).decrypt(raw[:12], raw[12:], username.encode()).decode()


# --- TOTP ------------------------------------------------------------------

def totp(secret, step, digits=6):
    key = base64.b32decode(secret, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** digits).zfill(digits)


def _matching_step(secret, code, now=None):
    step = int((now or time.time()) // STEP_SECONDS)
    matched = None
    for candidate in range(step - WINDOW, step + WINDOW + 1):  # check all, so timing doesn't reveal which matched
        if hmac.compare_digest(totp(secret, candidate), code):
            matched = candidate
    return matched


def _consume_step(username, step):
    """Atomic, so a code seen by an attacker can't be replayed, even in the same 30 seconds."""
    return db.execute("UPDATE users SET mfa_last_step=? WHERE username=? AND (mfa_last_step IS NULL OR mfa_last_step < ?)",
                      (step, username, step)) == 1


# --- enrollment ------------------------------------------------------------

def is_enabled(username):
    rows = db.query("SELECT mfa_enabled_at FROM users WHERE username=?", (username,))
    return bool(rows and rows[0]["mfa_enabled_at"])


def start_enrollment(username):
    """A new secret, unconfirmed until a code proves the authenticator app has it. Never replaces an active one."""
    if is_enabled(username):
        raise ValueError("MFA is already set up for this account.")
    secret = base64.b32encode(secrets.token_bytes(20)).decode()
    db.execute("UPDATE users SET mfa_secret=? WHERE username=? AND mfa_enabled_at IS NULL", (_encrypt(secret, username), username))
    uri = (f"otpauth://totp/{quote(ISSUER)}:{quote(username)}?"
           + urlencode({"secret": secret, "issuer": ISSUER, "algorithm": "SHA1", "digits": 6, "period": STEP_SECONDS}))
    buffer = io.BytesIO()
    segno.make(uri, error="m").save(buffer, kind="svg", scale=5, border=2, xmldecl=False)
    return {"secret": secret, "qr_svg": buffer.getvalue().decode()}


def confirm_enrollment(username, code):
    """Returns recovery codes, shown once, or None if the code is wrong."""
    rows = db.query("SELECT mfa_secret, mfa_enabled_at FROM users WHERE username=?", (username,))
    if not rows or not rows[0]["mfa_secret"] or rows[0]["mfa_enabled_at"]:
        return None
    step = _matching_step(_decrypt(rows[0]["mfa_secret"], username), _clean(code))
    if step is None or not _consume_step(username, step):
        return None
    db.execute("UPDATE users SET mfa_enabled_at=? WHERE username=?", (time.time(), username))
    return _new_recovery_codes(username)


def _clean(code):
    return "".join(str(code).split()).replace("-", "").upper()[:32]


def _code_hash(code):
    return hashlib.sha256(code.encode()).hexdigest()


def _new_recovery_codes(username):
    db.execute("DELETE FROM recovery_codes WHERE username=?", (username,))
    codes = []
    for _ in range(RECOVERY_CODES):
        code = base64.b32encode(secrets.token_bytes(10)).decode()  # 80 random bits, so a fast hash is safe here
        db.execute("INSERT INTO recovery_codes (code_hash, username) VALUES (?, ?)", (_code_hash(code), username))
        codes.append("-".join(code[i:i + 4] for i in range(0, len(code), 4)))
    return codes


def recovery_codes_left(username):
    return db.query("SELECT COUNT(*) AS n FROM recovery_codes WHERE username=?", (username,))[0]["n"]


def verify(username, code):
    """Check a login code. Returns 'totp', 'recovery', or None."""
    rows = db.query("SELECT mfa_secret, mfa_enabled_at FROM users WHERE username=?", (username,))
    if not rows or not rows[0]["mfa_enabled_at"]:
        return None
    cleaned = _clean(code)
    if len(cleaned) == 6 and cleaned.isdigit():
        try:
            secret = _decrypt(rows[0]["mfa_secret"], username)
        except (InvalidTag, ValueError):  # the key file changed: an admin must reset this user's MFA
            return None
        step = _matching_step(secret, cleaned)
        return "totp" if step is not None and _consume_step(username, step) else None
    # Deleted as it's checked, so a recovery code works exactly once.
    if db.execute("DELETE FROM recovery_codes WHERE code_hash=? AND username=?", (_code_hash(cleaned), username)) == 1:
        return "recovery"
    return None


def reset(username):
    """For a lost device. They set up MFA again at next login, and existing sessions end."""
    changed = db.execute("UPDATE users SET mfa_secret=NULL, mfa_enabled_at=NULL, mfa_last_step=NULL WHERE username=?", (username,)) == 1
    db.execute("DELETE FROM recovery_codes WHERE username=?", (username,))
    db.execute("DELETE FROM mfa_pending WHERE username=?", (username,))
    db.execute("DELETE FROM sessions WHERE username=?", (username,))
    return changed


# --- the state between password and second factor --------------------------

def create_pending(username):
    token, now = secrets.token_urlsafe(32), time.time()
    db.execute("DELETE FROM mfa_pending WHERE expires_at < ? OR username=?", (now, username))
    db.execute("INSERT INTO mfa_pending (token_hash, username, expires_at) VALUES (?, ?, ?)",
               (_code_hash(token), username, now + PENDING_SECONDS))
    return token


def pending_user(token):
    if not token:
        return None
    rows = db.query("SELECT username FROM mfa_pending WHERE token_hash=? AND expires_at > ?", (_code_hash(token), time.time()))
    return rows[0]["username"] if rows else None


def record_failure(token):
    """Returns True once the pending login has used up its attempts, and removes it. The password must be entered again."""
    hashed = _code_hash(token)
    db.execute("UPDATE mfa_pending SET attempts = attempts + 1 WHERE token_hash=?", (hashed,))
    return db.execute("DELETE FROM mfa_pending WHERE token_hash=? AND attempts >= ?", (hashed, PENDING_ATTEMPTS)) == 1


def end_pending(token):
    if token:
        db.execute("DELETE FROM mfa_pending WHERE token_hash=?", (_code_hash(token),))
