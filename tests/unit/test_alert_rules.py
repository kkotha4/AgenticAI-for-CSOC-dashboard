import json
import random

from app import alerts


def auth(fails, ip="203.0.113.9", success=True):
    events = [{"type": "auth", "user": "x", "ip": ip, "result": "fail", "count": fails}]
    return events + ([{"type": "auth", "user": "x", "ip": ip, "result": "success"}] if success else [])


def test_login_rule_fires_at_the_threshold_only():
    assert alerts._detect(auth(alerts.BRUTE_FORCE_THRESHOLD - 1)) == []
    assert len(alerts._detect(auth(alerts.BRUTE_FORCE_THRESHOLD))) == 1


def test_login_rule_needs_a_success_from_the_same_ip():
    assert alerts._detect(auth(50, success=False)) == []
    assert alerts._detect(auth(50)[:1] + [{"type": "auth", "user": "x", "ip": "other", "result": "success"}]) == []


def test_powershell_rule_needs_office_and_encoding():
    event = {"type": "process", "host": "h", "parent": "WINWORD.EXE", "process": "powershell.exe", "cmdline": "powershell -enc x"}
    assert len(alerts._detect([event])) == 1
    assert alerts._detect([{**event, "parent": "explorer.exe"}]) == []
    assert alerts._detect([{**event, "cmdline": "powershell Get-Date"}]) == []


def test_generated_data_uses_only_reserved_addresses_and_domains():
    rng = random.Random(1)
    for _ in range(100):
        events, intel, facts = alerts._simulate(rng.choice(alerts.SCENARIOS), rng)
        text = json.dumps([events, intel, facts])
        assert "https://" not in text
        for kind, key, _data in intel:
            if kind == "ip":
                assert key.startswith(("203.0.113.", "198.51.100."))
            if kind == "domain":
                assert key.endswith(".example")


def test_benign_incidents_expect_a_false_positive():
    _, _, facts = alerts._simulate("benign_lockout", random.Random(2))
    assert facts["verdict"] == "false_positive"
