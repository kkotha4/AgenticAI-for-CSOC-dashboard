"""Run the real live loop against a fake Gemini client, using Google's real SDK types (no key needed).

    .venv/bin/python tests/fake_gemini_live_loop.py
"""
import os, sys, tempfile, uuid
from types import SimpleNamespace as NS
_tmp = tempfile.mkdtemp(prefix="soc-test-")  # never touch the real database or audit log
os.environ.update(SOC_DB_PATH=f"{_tmp}/test.db", SOC_AUDIT_PATH=f"{_tmp}/audit.jsonl", BROKER_PORT="1",
                  LLM_PROVIDER="gemini", GEMINI_API_KEY="fake")
os.environ.pop("ANTHROPIC_API_KEY", None)
sys.path.insert(0, ".")
from google import genai
from google.genai import types
from app import actions, agent, cache, circuit, db, llm, obs, policy, queue, ratelimit, tools
db.init(); queue.init(); cache.init(); ratelimit.init(); obs.init(); actions.init(); circuit.init()
failures = 0


def check(label, ok, detail=""):
    global failures
    failures += not ok
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{f'  ({detail})' if detail else ''}")


def fc(name, args, call_id=None, sig=None):
    return types.Part(function_call=types.FunctionCall(id=call_id, name=name, args=args), thought_signature=sig)


def reply(parts, finish="STOP"):
    return types.GenerateContentResponse(
        candidates=[types.Candidate(content=types.Content(role="model", parts=parts), finish_reason=finish)],
        model_version="gemini-3.8-flash",
        usage_metadata=types.GenerateContentResponseUsageMetadata(
            prompt_token_count=20000, cached_content_token_count=5000, candidates_token_count=1000, thoughts_token_count=1000))


REPORT = {"verdict": "true_positive", "severity": "high", "mitre_techniques": ["T1110"],
          "summary": "Brute force.", "recommendations": ["Reset password"], "limitations": ["Test run"]}
script, seen = [], []


class FakeModels:
    def generate_content(self, model, contents, config):
        seen.append(NS(model=model, contents=list(contents), config=config))
        item = script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


genai.Client = lambda **kw: NS(models=FakeModels())


def live():
    seen.clear()
    rid = uuid.uuid4().hex[:8]
    db.create_run(rid, "ALERT-1001", "live")
    run = agent.Run(rid, "ALERT-1001", "live")
    try:
        agent.run_live(run)
    except llm.TransientError as e:
        return run, db.get_events(rid), e
    return run, db.get_events(rid), None


print("Normal run")
SIG = b"opaque-signature"
script[:] = [
    reply([types.Part(text="Fetch the alert.", thought=True), fc("get_alert", {"alert_id": "ALERT-1001"}, "c1", SIG)]),
    reply([fc("lookup_ip_reputation", {"ip": "185.220.101.45"}, "c2", SIG), fc("search_case_history", {"indicator": "185.220.101.45"}, "c3")]),
    reply([fc("submit_triage_report", REPORT, "c4", SIG)]),
]
run, events, _ = live()
last = seen[-1]
check("loop finishes and produces a report", run.report == REPORT)
check("default model and thought summaries are requested", last.model == "gemini-3.8-flash" and last.config.thinking_config.include_thoughts)
check("SDK can never auto-run tools (would bypass policy)", last.config.automatic_function_calling.disable is True)
check("all tools declared to the model", len(last.config.tools[0].function_declarations) == len(tools.tool_definitions()))
check("thought summary reaches the trace", any(e["kind"] == "reason" and e["source"] == "thinking" for e in events))
model_turns = [c for c in last.contents if c.role == "model"]
check("thought signatures go back unchanged", model_turns[0].parts[1].thought_signature == SIG and model_turns[1].parts[0].thought_signature == SIG)
parallel = last.contents[4].parts
check("parallel results share one message, in order, with matching ids",
      [p.function_response.id for p in parallel] == ["c2", "c3"] and [p.function_response.name for p in parallel] == ["lookup_ip_reputation", "search_case_history"])
check("lookup results are wrapped as untrusted data", parallel[0].function_response.response["output"].startswith("<untrusted_tool_output>"))
usage = next(e for e in events if e["kind"] == "usage")
check("usage and cost: thoughts billed as output, cached not double-counted",
      (usage["input"], usage["output"], usage["cache_read"]) == (15000, 2000, 5000) and abs(usage["cost_usd"] - 0.045) < 1e-9, usage["cost_usd"])

print("Bad model output")
script[:] = [
    reply([fc("isolate_host", {"hostname": 123, "reason": "x"}, "b1")]),
    reply([fc("isolate_host", {"hostname": "FIN-WKS-022"}, "b2")]),
    reply([fc("isolate_host", {"hostname": "FIN-WKS-022", "reason": "x", "force": "yes"}, "b3")]),
    reply([fc("isolate_host", {"hostname": " dc-01 ", "reason": "x"}, "b4")]),
    reply([fc("delete_everything", {}, "b5")]),
    reply([fc("submit_triage_report", {**REPORT, "limitations": [" "]}, "b6")]),
    reply([fc("get_alert", {}, None)]),
    reply([fc("submit_triage_report", REPORT, "b7")]),
]
run, events, _ = live()
denied = [e["reason"] for e in events if e["kind"] == "policy" and e["decision"] == "deny"]
check("wrong type, missing and extra arguments are refused", len([d for d in denied if "must be a string" in d or "Bad arguments" in d]) >= 3, len(denied))
check("lowercase, padded protected host is blocked", any("protected asset" in d for d in denied))
check("unknown tool is blocked", any("allowlist" in d for d in denied))
check("a report with empty limitations is refused", any("limitations can't be empty" in d for d in denied))
check("nothing reached an approval gate", not any(e["kind"] == "approval_request" for e in events))
check("no containment action ran", run.actions == [])
check("the model gets errors back and can continue", run.report == REPORT)
check("a call with no id still gets a unique one, sent back as none",
      seen[-1].contents[-1].parts[0].function_response.id is None
      and any(e["kind"] == "act" and e["tool"] == "get_alert" and e["tool_use_id"].startswith("gemini_") for e in events))

print("Stops and failures")
script[:] = [reply([types.Part(text="I can't help with that.")], "SAFETY")]
_, events, _ = live()
check("safety block is reported as declined", any(e["kind"] == "error" and "declined" in e["message"] for e in events))
script[:] = [types.GenerateContentResponse(prompt_feedback=types.GenerateContentResponsePromptFeedback(block_reason="PROHIBITED_CONTENT"))]
_, events, _ = live()
check("blocked prompt with no candidates doesn't crash", any(e["kind"] == "error" and "declined" in e["message"] for e in events))
script[:] = [reply([types.Part(text="All done, no report.")])]
_, events, _ = live()
check("stopping without a report is an error", any(e["kind"] == "error" and "without submitting" in e["message"] for e in events))
script[:] = [genai.errors.ClientError(429, {"error": {"message": "slow down", "status": "RESOURCE_EXHAUSTED"}})]
_, _, err = live()
check("429 is retryable", isinstance(err, llm.TransientError))
script[:] = [genai.errors.ClientError(429, {"error": {"message": "quota", "status": "RESOURCE_EXHAUSTED", "details": [{"violations": [{"quotaId": "GenerateRequestsPerDayPerProjectPerModel-FreeTier"}]}]}})]
try:
    live(); check("daily quota is permanent", False)
except llm.PermanentError as e:
    check("daily quota is permanent, with a clear message", "daily request quota" in str(e))
script[:] = [genai.errors.ClientError(404, {"error": {"message": "model not found", "status": "NOT_FOUND"}})]
try:
    live(); check("404 is permanent", False)
except llm.PermanentError as e:
    check("bad model id is permanent, not retried", "404" in str(e))
os.environ.pop("GEMINI_API_KEY")
check("mode auto falls back to demo without a key", llm.available() is False)
try:
    llm.create("s", [], "m"); check("missing key is a clear error", False)
except llm.CredentialsError as e:
    check("missing key is a clear error", "GEMINI_API_KEY" in str(e))
os.environ["GEMINI_API_KEY"] = "fake"

print("Budgets")
agent.RUN_BUDGET_USD = 0.05
script[:] = [reply([fc("get_alert", {"alert_id": "ALERT-1001"}, "x1")]) for _ in range(3)]
_, events, _ = live()
check("run budget stops the loop", len(seen) == 2 and any("run budget" in e.get("message", "") for e in events), f"{len(seen)} calls")

print(f"\n{'ALL PASSED' if not failures else f'{failures} FAILED'}")
sys.exit(1 if failures else 0)
