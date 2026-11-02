"""Production safety checks. With APP_ENV=production, unsafe settings stop the app instead of being a warning.

Local development is unaffected: nothing here applies unless APP_ENV=production.
"""
import os
import stat
from pathlib import Path


def is_production():
    return os.environ.get("APP_ENV", "").strip().lower() == "production"


def _problems_for_web():
    problems = []
    if os.environ.get("MFA_REQUIRED", "1") == "0":
        problems.append("MFA_REQUIRED=0 would let people log in with only a password.")
    if os.environ.get("COOKIE_SECURE") != "1":
        problems.append("COOKIE_SECURE must be 1, so login cookies are only ever sent over HTTPS.")
    key = os.environ.get("SOC_MFA_KEY_PATH")
    if not key:
        problems.append("SOC_MFA_KEY_PATH must point to the MFA encryption key.")
    elif not Path(key).is_file():
        problems.append(f"The MFA key file {key} doesn't exist. See DEPLOY.md.")
    else:
        path = Path(key)
        if path.stat().st_size != 32:
            problems.append("The MFA key must be exactly 32 random bytes.")
        if path.stat().st_mode & stat.S_IWOTH:
            problems.append("The MFA key file must not be writable by everyone.")
        database = os.environ.get("SOC_DB_PATH")
        if database and path.resolve().parent == Path(database).resolve().parent:
            problems.append("Keep the MFA key away from the database: a stolen data folder must not include the key.")
    return problems


def _problems_for_worker():
    problems = []
    provider = os.environ.get("LLM_PROVIDER", "").strip().lower()
    required = {"anthropic": "ANTHROPIC_API_KEY", "gemini": "GEMINI_API_KEY"}
    if provider in required and not os.environ.get(required[provider]):
        problems.append(f"LLM_PROVIDER={provider} needs {required[provider]}.")
    return problems


def problems(role):
    """Everything wrong with this configuration for a process of this role: web or worker."""
    if not is_production():
        return []
    found = _problems_for_web() if role == "web" else _problems_for_worker()
    if os.environ.get("LLM_PROVIDER", "").strip().lower() == "claude_code" or os.environ.get("CLAUDE_CODE_OWNER"):
        found.append("The claude_code provider is for one person's local testing. A shared deployment needs an API key provider.")
    return found


def enforce(role):
    found = problems(role)
    if found:
        raise SystemExit("Refusing to start in production:\n  - " + "\n  - ".join(found))
