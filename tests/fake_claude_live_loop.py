"""Run the real live-mode loop against a fake Claude client (no API key needed).

    .venv/bin/python tests/fake_claude_live_loop.py
"""
import inspect, json, os, sys, tempfile, time, uuid
_tmp = tempfile.mkdtemp(prefix="soc-test-")  # never touch the real database or audit log
os.environ["SOC_DB_PATH"] = f"{_tmp}/test.db"
os.environ["SOC_AUDIT_PATH"] = f"{_tmp}/audit.jsonl"
os.environ["BROKER_PORT"] = "1"              # no broker needed
from types import SimpleNamespace as NS
sys.path.insert(0, ".")
os.environ["ANTHROPIC_API_KEY"] = "fake"
from app import agent, cache, db, llm, queue, ratelimit
from anthropic.resources.beta.messages import Messages
from anthropic.types.beta import BetaTextBlock, BetaThinkingBlock, BetaToolUseBlock
from app import actions, circuit
db.init(); queue.init(); cache.init(); ratelimit.init()
from app import obs
obs.init(); actions.init(); circuit.init()

SCRIPT = [  # what "Claude" does on each turn
    [("thinking", "Fetch the alert first."), ("tool_use", "get_alert", {"alert_id": "ALERT-1001"})],
    [("text", "Checking the IP and history."), ("tool_use", "lookup_ip_reputation", {"ip": "185.220.101.45"}),
     ("tool_use", "search_case_history", {"indicator": "185.220.101.45"})],
    [("tool_use", "submit_triage_report", {"verdict": "true_positive", "severity": "high", "mitre_techniques": ["T1110"],
                                           "summary": "Brute force from Tor exit.", "recommendations": ["Reset password"], "limitations": ["Test run"]})],
]
SIG = inspect.signature(Messages.create)
calls = []

class FakeMessages:
    def create(self, **kw):
        SIG.bind(None, **kw)                      # TypeError if we pass a parameter the real SDK doesn't accept
        calls.append(kw)
        turn = SCRIPT[len(calls) - 1]
        blocks = []
        for b in turn:
            if b[0] == "thinking": blocks.append(BetaThinkingBlock.model_validate({"type": "thinking", "thinking": b[1], "signature": "sig"}))
            elif b[0] == "text": blocks.append(BetaTextBlock.model_validate({"type": "text", "text": b[1]}))
            else: blocks.append(BetaToolUseBlock.model_validate({"type": "tool_use", "id": f"toolu_{uuid.uuid4().hex[:6]}", "name": b[1], "input": b[2]}))
        # 20k fresh input + 2k output per turn = $0.08 + $0.04 = $0.12
        usage = NS(input_tokens=20000, output_tokens=2000, cache_read_input_tokens=0, cache_creation_input_tokens=0)
        return NS(content=blocks, usage=usage, stop_reason="tool_use", stop_details=None, model="claude-opus-5-5")

llm.anthropic.Anthropic = lambda **kw: NS(beta=NS(messages=FakeMessages()), _kw=kw)

def live_run(label):
    calls.clear()
    rid = uuid.uuid4().hex[:8]; db.create_run(rid, "ALERT-1001", "live")
    run = agent.execute_job(rid, "ALERT-1001", "live", 1)
    ev = db.get_events(rid)
    errs = [e["message"] for e in ev if e["kind"] == "error"]
    cost = db.get_run(rid)["cost_usd"]
    print(f"{label}: {len(calls)} Claude calls, cost ${cost:.2f}, report={'yes' if run.report else 'no'}, "
          f"stopped: {errs[0] if errs else '-'}")
    return rid

agent.RUN_BUDGET_USD, agent.DAILY_BUDGET_USD = 1.00, 100
rid = live_run("A. normal run          ")
last = calls[-1]
assert_all = []
assert_all.append(("request settings", last["model"] == "claude-opus-5-5" and last["fallbacks"] == "default" and last["cache_control"] and last["system"][0]["cache_control"] and last["output_config"]["effort"] == "high"))
print("   request checks: model=%s fallbacks=%s top-level cache_control=%s system marker=%s effort=%s" % (
    last["model"], last["fallbacks"], last["cache_control"], last["system"][0]["cache_control"], last["output_config"]["effort"]))
roles = [m["role"] for m in last["messages"]]
ids_ok = all(r["tool_use_id"] in {b.id for b in last["messages"][i-1]["content"] if b.type == "tool_use"}
             for i, m in enumerate(last["messages"]) if m["role"] == "user" and isinstance(m["content"], list)
             for r in m["content"])
assert_all.append(("roles alternate", all(a != b for a, b in zip(roles, roles[1:])) and roles[0] == "user"))
assert_all.append(("tool results match calls", ids_ok))
print(f"   message roles alternate: {roles}  every tool_result matches a tool_use id: {ids_ok}")
wrapped = all(r["content"].startswith("<untrusted_tool_output>") for r in last["messages"][-3]["content"])
assert_all.append(("lookup results wrapped", wrapped))
print(f"   lookup results (step 2) wrapped as untrusted data: {wrapped}")

agent.RUN_BUDGET_USD = 0.20
live_run("B. run budget $0.20   ")
assert_all.append(("run budget stops the run", len(calls) == 2))
agent.RUN_BUDGET_USD, agent.DAILY_BUDGET_USD = 1.00, 0.50
live_run("C. daily budget $0.50 ")
assert_all.append(("daily budget refuses a run", len(calls) == 0))
failed = [name for name, ok in assert_all if not ok]
print("ALL PASSED" if not failed else f"FAILED: {failed}")
sys.exit(1 if failed else 0)
