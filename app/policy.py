"""Guardrails. Deterministic code that sits between the model and the tools.

The model proposes; policy disposes. Nothing here depends on the model behaving well,
which is what makes it a real control rather than a prompt-level suggestion.
"""
import re

from . import tools

# Assets the agent may never act on, even with approval (break-glass only).
PROTECTED = {
    "isolate_host": {"DC-01"},
    "disable_user_account": {"svc-backup", "administrator", "krbtgt"},
    "block_ip": {"10.0.0.1", "8.8.8.8"},
}

MAX_STEPS = 15  # hard cap on loop iterations: stops runaway agents and runaway cost

# Phrases that indicate text is trying to instruct the agent (prompt injection).
INJECTION_PATTERNS = [
    r"ignore (all )?(previous|prior) instructions",
    r"\bAI assistant\b",
    r"you are now",
    r"system prompt",
    r"call (disable_user_account|block_ip|isolate_host)",
]


def decide(name, args):
    """Return (decision, reason). decision is 'allow', 'needs_approval' or 'deny'."""
    risk = tools.risk_of(name)
    if risk is None:
        return "deny", f"Unknown tool '{name}' is not on the allowlist."
    # Compare normalized values, so " DC-01" or "dc-01" can't slip past the list.
    protected = {p.lower() for p in PROTECTED.get(name, set())}
    for key, value in args.items():
        if key != "reason" and isinstance(value, str) and value.strip().lower() in protected:
            return "deny", f"'{value}' is a protected asset. {name} is blocked by policy."
    if risk == tools.WRITE:
        return "needs_approval", "State-changing action: a human analyst must approve."
    return "allow", "Read-only tool."


def scan_for_injection(text):
    return [p for p in INJECTION_PATTERNS if re.search(p, text, re.IGNORECASE)]


def wrap_untrusted(text):
    """Mark tool output as data so the model can tell it apart from instructions."""
    # Attacker text must not be able to close the wrapper and pose as instructions outside it.
    safe = re.sub(r"(?i)<(/?)\s*untrusted_tool_output", r"&lt;\1untrusted_tool_output", text)
    return f"<untrusted_tool_output>\n{safe}\n</untrusted_tool_output>"
