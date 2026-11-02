import pytest
from app import tools


@pytest.mark.parametrize("value", ["evil.example", "EVIL.EXAMPLE", " evil[.]example ", "hxxps://evil[.]example/login?x=1", "https://evil.example:8443/a", "user@evil.example"])
def test_domains_are_normalized_from_any_form(value):
    assert tools.normalize_domain(value) == "evil.example"


def test_domain_match_covers_subdomains_only():
    log = lambda url: {"url": url}
    assert tools._log_matches_domain(log("https://evil.example/a"), "evil.example")
    assert tools._log_matches_domain(log("https://login.evil.example/a"), "evil.example")
    assert not tools._log_matches_domain(log("https://notevil.example/a"), "evil.example")
    assert not tools._log_matches_domain(log("https://evil.example.bad.net/a"), "evil.example")
    assert not tools._log_matches_domain(log("https://evil.example/a"), "")


def test_valid_arguments_pass():
    assert tools.validate_args("block_ip", {"ip": "1.2.3.4", "reason": "x"}) is None


@pytest.mark.parametrize("args,expected", [
    ({"ip": "1.2.3.4"}, "missing"), ({"ip": "1.2.3.4", "reason": "x", "force": True}, "unexpected"), ({"ip": 5, "reason": "x"}, "must be a string"), ("not an object", "object"),
])
def test_bad_arguments_are_explained(args, expected):
    assert expected in tools.validate_args("block_ip", args)


def test_enums_are_enforced():
    assert "must be one of" in tools.validate_args("search_logs", {"field": "password", "value": "x"})


REPORT = {"verdict": "true_positive", "severity": "low", "mitre_techniques": [], "summary": "s", "recommendations": [], "limitations": ["checked logs only"]}


@pytest.mark.parametrize("limitations", [[], [" "], ["", "  "]])
def test_reports_must_state_limitations(limitations):
    assert "limitations" in tools.validate_args("submit_triage_report", {**REPORT, "limitations": limitations})


def test_a_complete_report_passes():
    assert tools.validate_args("submit_triage_report", REPORT) is None


def test_single_agent_tools_exclude_delegation():
    names = {t["name"] for t in tools.tool_definitions()}
    assert tools.CONSULT not in names and "submit_findings" not in names and "search_logs" in names


def test_every_cached_tool_is_read_only():
    assert all(tools.risk_of(name) == tools.READ for name in tools.CACHE_POLICY)


@pytest.mark.parametrize("result,negative", [({"reputation": "unknown"}, True), ({"reputation": "malicious"}, False), ({"error": "x"}, True), ({"matches": []}, True), ({"matches": [1]}, False)])
def test_not_found_answers_are_cached_for_less_time(result, negative):
    assert tools.is_negative(result) is negative
