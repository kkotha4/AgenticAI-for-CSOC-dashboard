"""Authentication (who are you?) and authorization (what may you do?).

Passwords are stored only as salted scrypt hashes. Sessions are random tokens held in an
HttpOnly cookie; the database stores only a hash of each token, so a leaked database cannot
be used to log in, and deleting a row revokes that session immediately.

Roles are looked up on every request, so changing someone's role takes effect at once.

    python -m app.auth set-user <username> <role>     # create a user, or change their role and password
    python -m app.auth list-users
    python -m app.auth remove-user <username>
    python -m app.auth reset-mfa <username>           # last resort if no admin can log in
    python -m app.auth create-token <name>            # create a metrics token, shown once
    python -m app.auth list-tokens
    python -m app.auth revoke-token <name>

People log in and get sessions. Machines get service tokens: each has one scope, reaches only the
endpoints for that scope, and can be rotated or revoked without touching anyone's login.
"""
import getpass
import hashlib
import hmac
import re
import secrets
import sys
import time

from . import db, mfa
from .audit import audit

SESSION_SECONDS = 8 * 3600  # one analyst shift

# Least privilege: each role gets only what the job needs. Admins run the system but do not
# approve containment - separation of duties means no one role can do everything.
PERMISSIONS = {
    "viewer": {"view"},
    "tier1": {"view", "run", "approve:containment", "approve:high_impact", "dashboard:view", "alerts:generate"},
    "tier2": {"view", "run", "approve:containment", "approve:high_impact", "cache:flush", "dashboard:view", "alerts:generate"},
    "admin": {"view", "cache:flush", "dashboard:view", "users:manage", "alerts:generate"},
    # Researchers can investigate and study results, but a person on the SOC team decides containment.
    "researcher": {"view", "run", "dashboard:view", "alerts:generate"},
}

MIN_PASSWORD_LENGTH = 12
INVITE_SECONDS = 48 * 3600
USERNAME = re.compile(r"[a-z0-9][a-z0-9._-]{1,31}")

# What it takes to decide each state-changing action.
# A block is easy to undo; isolating a host or disabling an account can stop someone's work.
APPROVAL_PERMISSION = {
    "block_ip": "approve:containment",
    "isolate_host": "approve:high_impact",
    "disable_user_account": "approve:high_impact",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL,
    created_at    REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS invites (
    token_hash TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    role       TEXT NOT NULL,
    invited_by TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    used_at    REAL,
    revoked_at REAL
);
CREATE TABLE IF NOT EXISTS service_tokens (
    name         TEXT PRIMARY KEY,
    token_hash   TEXT NOT NULL UNIQUE,
    scope        TEXT NOT NULL,
    created_at   REAL NOT NULL,
    last_used_at REAL,
    revoked_at   REAL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    username   TEXT NOT NULL REFERENCES users(username),
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
"""


def init():
    db.executescript(SCHEMA)
    mfa.init()


def seed_demo_users():
    """On an empty database, create one user per role with random passwords, shown only once."""
    if db.query("SELECT 1 FROM users LIMIT 1"):
        return
    print("\n=== First run: demo users created. Save these passwords; they are not shown again. ===", flush=True)
    for role in ("viewer", "tier1", "tier2", "admin"):
        password = secrets.token_urlsafe(12)
        set_user(role, role, password)
        print(f"    {role:<8} {password}", flush=True)
    print("=== To reset one: .venv/bin/python -m app.auth set-user <username> <role> ===\n", flush=True)


def _is_last_admin(username):
    admins = [r["username"] for r in db.query("SELECT username FROM users WHERE role='admin'")]
    return admins == [username]


def remove_user(username):
    """Ends their access. Their name stays on past runs and approvals, which remain an accurate record."""
    if _is_last_admin(username):
        raise ValueError("That's the last admin account. Create another admin first.")
    mfa.reset(username)
    removed = db.execute("DELETE FROM users WHERE username=?", (username,)) == 1
    if removed:
        audit("auth", {"ts": time.time(), "kind": "user_removed", "user": username})
    return removed


def list_users():
    return db.query("SELECT username, role, mfa_enabled_at IS NOT NULL AS mfa_enabled FROM users ORDER BY role, username")


# --- invitations -----------------------------------------------------------

def create_invite(username, role, invited_by):
    """Returns the one-time token. Only its hash is stored, so it can't be shown again."""
    if role not in PERMISSIONS:
        raise ValueError(f"Unknown role {role!r}.")
    if not USERNAME.fullmatch(username):
        raise ValueError("Usernames use 2-32 lowercase letters, numbers, dots, dashes or underscores, starting with a letter or number.")
    now = time.time()
    if db.query("SELECT 1 FROM users WHERE username=?", (username,)):
        raise ValueError(f"{username} already has an account.")
    if db.query("SELECT 1 FROM invites WHERE username=? AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?", (username, now)):
        raise ValueError(f"{username} already has an open invitation. Revoke it first.")
    token = f"soc_inv_{secrets.token_urlsafe(32)}"
    db.execute("INSERT INTO invites (token_hash, username, role, invited_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
               (_token_hash(token), username, role, invited_by, now, now + INVITE_SECONDS))
    return token


def invite_details(token):
    rows = db.query("SELECT username, role, expires_at FROM invites WHERE token_hash=? AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?",
                    (_token_hash(token or ""), time.time()))
    return rows[0] if rows else None


def accept_invite(token, password):
    """Creates the account. Returns the username, or None if the invitation isn't valid."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Use at least {MIN_PASSWORD_LENGTH} characters.")
    details = invite_details(token)
    if not details:
        return None
    # Claim it atomically first, so two simultaneous requests can't both use one invitation.
    claimed = db.execute("UPDATE invites SET used_at=? WHERE token_hash=? AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?",
                         (time.time(), _token_hash(token), time.time())) == 1
    if not claimed or db.query("SELECT 1 FROM users WHERE username=?", (details["username"],)):
        return None
    set_user(details["username"], details["role"], password)
    return details["username"]


def list_invites():
    return db.query("SELECT username, role, invited_by, expires_at FROM invites "
                    "WHERE used_at IS NULL AND revoked_at IS NULL AND expires_at > ? ORDER BY created_at DESC", (time.time(),))


def revoke_invite(username):
    return db.execute("UPDATE invites SET revoked_at=? WHERE username=? AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?",
                      (time.time(), username, time.time())) >= 1


def set_user(username, role, password):
    if role not in PERMISSIONS:
        raise ValueError(f"Unknown role {role!r}. Choose from: {', '.join(PERMISSIONS)}")
    if not USERNAME.fullmatch(username):
        raise ValueError("Usernames use 2-32 lowercase letters, numbers, dots, dashes or underscores, starting with a letter or number.")
    if role != "admin" and _is_last_admin(username):
        raise ValueError("That's the last admin account. Create another admin first.")
    db.execute("""INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)
                  ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash, role=excluded.role""",
               (username, hash_password(password), role, time.time()))
    db.execute("DELETE FROM sessions WHERE username=?", (username,))  # a password reset ends old sessions
    audit("auth", {"ts": time.time(), "kind": "user_saved", "user": username, "role": role})


# --- passwords -------------------------------------------------------------

def _scrypt(password, salt):
    # Deliberately slow and memory-hard, so stolen hashes are expensive to guess.
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)


def hash_password(password):
    salt = secrets.token_bytes(16)
    return f"scrypt${salt.hex()}${_scrypt(password, salt).hex()}"


def verify_password(password, stored):
    _, salt, expected = stored.split("$")
    return hmac.compare_digest(_scrypt(password, bytes.fromhex(salt)).hex(), expected)


_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def authenticate(username, password):
    """Returns the username, or None. Unknown users do the same work as wrong passwords,
    so response time doesn't reveal which usernames exist."""
    rows = db.query("SELECT username, password_hash FROM users WHERE username=?", (username,))
    stored = rows[0]["password_hash"] if rows else _DUMMY_HASH
    ok = verify_password(password, stored)
    return rows[0]["username"] if rows and ok else None


# --- sessions --------------------------------------------------------------

def _token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(username):
    token = secrets.token_urlsafe(32)
    now = time.time()
    db.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
    db.execute("INSERT INTO sessions (token_hash, username, created_at, expires_at) VALUES (?, ?, ?, ?)",
               (_token_hash(token), username, now, now + SESSION_SECONDS))
    return token


def end_session(token):
    db.execute("DELETE FROM sessions WHERE token_hash=?", (_token_hash(token),))


def user_for_token(token):
    """Returns {username, role, permissions}, or None if the token is missing, unknown or expired."""
    if not token:
        return None
    rows = db.query("""SELECT u.username, u.role FROM sessions s JOIN users u ON u.username = s.username
                       WHERE s.token_hash=? AND s.expires_at > ?""", (_token_hash(token), time.time()))
    if not rows:
        return None
    return {**rows[0], "permissions": PERMISSIONS.get(rows[0]["role"], set())}


# --- service tokens ---------------------------------------------------------

METRICS_SCOPE = "metrics:read"


def create_token(name, scope=METRICS_SCOPE):
    """Returns the token, which can't be recovered later: only its hash is stored.
    Rotate by creating a second token, switching the scraper to it, then revoking the first."""
    token = f"soc_svc_{secrets.token_urlsafe(32)}"
    if db.query("SELECT 1 FROM service_tokens WHERE name=?", (name,)):
        raise ValueError(f"A token named {name!r} already exists. Choose another name.")
    db.execute("INSERT INTO service_tokens (name, token_hash, scope, created_at) VALUES (?, ?, ?, ?)",
               (name, _token_hash(token), scope, time.time()))
    return token


def verify_token(token, scope):
    """Returns the token's name if it's valid and has this scope, else None."""
    if not token:
        return None
    rows = db.query("SELECT name FROM service_tokens WHERE token_hash=? AND scope=? AND revoked_at IS NULL",
                    (_token_hash(token), scope))
    if not rows:
        return None
    db.execute("UPDATE service_tokens SET last_used_at=? WHERE name=?", (time.time(), rows[0]["name"]))
    return rows[0]["name"]


def revoke_token(name):
    return db.execute("UPDATE service_tokens SET revoked_at=? WHERE name=? AND revoked_at IS NULL", (time.time(), name)) == 1


def list_tokens():
    return db.query("SELECT name, scope, created_at, last_used_at, revoked_at FROM service_tokens ORDER BY created_at")


def can_decide(user, tool):
    """Default deny: a tool with no entry in the table requires a permission nobody has."""
    return APPROVAL_PERMISSION.get(tool, "approve:unmapped") in user["permissions"]


def main():
    args = sys.argv[1:]
    db.init()
    init()
    if len(args) == 3 and args[0] == "set-user":
        password = getpass.getpass(f"New password for {args[1]} (at least {MIN_PASSWORD_LENGTH} characters): ")
        if len(password) < MIN_PASSWORD_LENGTH:
            sys.exit(f"Password too short: use at least {MIN_PASSWORD_LENGTH} characters.")
        if getpass.getpass("Type it again: ") != password:
            sys.exit("Passwords don't match. Nothing was changed.")
        try:
            set_user(args[1], args[2], password)
        except ValueError as e:
            sys.exit(str(e))
        print(f"Saved {args[1]} as {args[2]}. Any existing sessions were ended.")
    elif args == ["list-users"]:
        for user in list_users():
            print(f"{user['username']:<20} {user['role']:<12} MFA {'on' if user['mfa_enabled'] else 'not set up'}")
    elif len(args) == 2 and args[0] == "reset-mfa":
        if not mfa.reset(args[1]):
            sys.exit(f"No user named {args[1]!r}.")
        audit("auth", {"ts": time.time(), "kind": "mfa_reset", "user": args[1], "by": "command line"})
        print(f"MFA reset for {args[1]}. They'll set it up again at next login.")
    elif len(args) == 2 and args[0] == "remove-user":
        try:
            removed = remove_user(args[1])
        except ValueError as e:
            sys.exit(str(e))
        if not removed:
            sys.exit(f"No user named {args[1]!r}.")
        print(f"Removed {args[1]}. Their past runs and approvals keep their name.")
    elif len(args) == 2 and args[0] == "create-token":
        try:
            token = create_token(args[1])
        except ValueError as e:
            sys.exit(str(e))
        print(f"Created token {args[1]!r} with scope {METRICS_SCOPE}. Save it now; it can't be shown again:\n{token}")
    elif args == ["list-tokens"]:
        for t in list_tokens():
            used = time.strftime("%Y-%m-%d %H:%M", time.localtime(t["last_used_at"])) if t["last_used_at"] else "never"
            print(f"{t['name']}  {t['scope']}  last used: {used}{'  REVOKED' if t['revoked_at'] else ''}")
    elif len(args) == 2 and args[0] == "revoke-token":
        if not revoke_token(args[1]):
            sys.exit(f"No active token named {args[1]!r}.")
        print(f"Revoked {args[1]}.")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
