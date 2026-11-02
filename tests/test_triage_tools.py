"""Domain search, domain reputation, ATLAS lookup and report limitations (no API key needed).

    .venv/bin/python tests/test_triage_tools.py
"""
import os, sys, tempfile, uuid
_tmp = tempfile.mkdtemp(prefix="soc-test-")  # never touch the real database or audit log
os.environ.update(SOC_DB_PATH=f"{_tmp}/test.db", SOC_AUDIT_PATH=f"{_tmp}/audit.jsonl", BROKER_PORT="1")
sys.path.insert(0, ".")
from app import actions, agent, cache, circuit, db, obs, queue, ratelimit, tools
db.init(); queue.init(); cache.init(); ratelimit.init(); obs.init(); actions.init(); circuit.init()
failures = 0


def check(label, ok, detail=""):
    global failures
    failures += not ok
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{f'  ({detail})' if detail else ''}")


def users(value):
    return {h.get("user") for h in tools.search_logs("domain", value)["hits"]}


print("Domain search")
for form in ["micr0soft-help.com", "MICR0SOFT-HELP.COM", " micr0soft-help[.]com ", "hxxps://micr0soft-help[.]com/login", "x@micr0soft-help.com"]:
    check(f"finds both users from {form!r}", users(form) == {"a.kim", "r.singh"}, sorted(users(form)))
check("finds the allowed visit the old search couldn't", any(h.get("action") == "allowed" for h in tools.search_logs("domain", "micr0soft-help.com")["hits"]))
saved = list(tools.LOGS)
tools.LOGS.extend([{"url": "https://login.micr0soft-help.com/a", "user": "sub"}, {"url": "https://evil-micr0soft-help.com/a", "user": "lookalike"},
                   {"url": "https://micr0soft-help.com.evil.net/a", "user": "prefix"}])
check("includes subdomains", "sub" in users("micr0soft-help.com"))
check("excludes other domains that merely contain the name", not {"lookalike", "prefix"} & users("micr0soft-help.com"))
tools.LOGS[:] = saved
check("empty value finds nothing", users("  ") == set())
check("the user field still needs an exact match", tools.search_logs("user", "a.kim")["count"] == 2)

print("Reputation and ATLAS")
check("known bad domain, defanged input", tools.lookup_domain_reputation("hxxps://micr0soft-help[.]com/login")["reputation"] == "malicious")
check("unknown domain is cached briefly as a negative", tools.is_negative(tools.lookup_domain_reputation("example.org")))
check("ATLAS indirect injection resolves", "Indirect" in tools.lookup_mitre_technique("AML.T0051.001")["description"])

print("Report limitations")
good = {"verdict": "true_positive", "severity": "low", "mitre_techniques": [], "summary": "s", "recommendations": [], "limitations": ["x"]}
check("a report with limitations is valid", tools.validate_args("submit_triage_report", good) is None)
check("missing is refused", "missing" in (tools.validate_args("submit_triage_report", {k: v for k, v in good.items() if k != "limitations"}) or ""))
check("empty is refused", "can't be empty" in (tools.validate_args("submit_triage_report", {**good, "limitations": []}) or ""))
check("every demo tool call passes validation",
      not [c for s in agent.DEMO_SCRIPTS.values() for _, calls in s for c in calls if tools.validate_args(*c)])
for phrase in ["search logs by domain", "MITRE ATLAS", "Absence of evidence", "no compromise occurred", "limitations"]:
    check(f"system prompt covers: {phrase}", phrase in agent.SYSTEM_PROMPT)

print("Full ALERT-1003 demo run")
rid = uuid.uuid4().hex[:8]
db.create_run(rid, "ALERT-1003", "demo")
run = agent.execute_job(rid, "ALERT-1003", "demo", 1)
events = db.get_events(rid)
acted = [e["tool"] for e in events if e["kind"] == "act"]
denied = [e["reason"] for e in events if e["kind"] == "policy" and e["decision"] == "deny"]
check("uses the new tools", "lookup_domain_reputation" in acted and any(e["kind"] == "act" and e["input"].get("field") == "domain" for e in events))
check("injection still flagged and blocked", any(e["kind"] == "guardrail" for e in events) and any("svc-backup" in d for d in denied))
check("no containment ran", run.actions == [])
check("report names r.singh, ATLAS and limitations",
      "r.singh" in run.report["summary"] and "AML.T0051.001" in run.report["mitre_techniques"] and len(run.report["limitations"]) >= 1)
check("report doesn't overclaim", "no compromise occurred" not in run.report["summary"].lower() and "no user compromise" not in run.report["summary"].lower())

print(f"\n{'ALL PASSED' if not failures else f'{failures} FAILED'}")
sys.exit(1 if failures else 0)
