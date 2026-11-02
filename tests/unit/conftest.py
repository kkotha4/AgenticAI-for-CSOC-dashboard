"""Unit tests: one function at a time, with no servers, browser or network. A temporary database only."""
import os
import sys
import tempfile

_tmp = tempfile.mkdtemp(prefix="soc-unit-")
os.environ.update(SOC_DB_PATH=f"{_tmp}/t.db", SOC_AUDIT_PATH=f"{_tmp}/a.jsonl", SOC_LOG_DIR=f"{_tmp}/logs", SOC_MFA_KEY_PATH=f"{_tmp}/mfa.key", BROKER_PORT="1")
for key in ("APP_ENV", "MFA_REQUIRED", "COOKIE_SECURE", "LLM_PROVIDER", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "CLAUDE_CODE_OWNER"):
    os.environ.pop(key, None)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app import actions, auth, cache, circuit, db, obs, queue, ratelimit  # noqa: E402

db.init(); queue.init(); cache.init(); ratelimit.init(); obs.init(); actions.init(); circuit.init(); auth.init()
