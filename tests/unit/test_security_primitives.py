import base64
import json
import os
import time
import uuid

import pytest
from app import actions, auth, circuit, config, db, llm, mfa, obs, queue, ratelimit


def unique(prefix="t"):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@pytest.mark.parametrize("t,code", [(59, "94287082"), (1111111109, "07081804"), (1234567890, "89005924"), (2000000000, "69279037")])
def test_totp_matches_the_rfc_6238_vectors(t, code):
    assert mfa.totp(base64.b32encode(b"12345678901234567890").decode(), t // 30, 8) == code


def test_totp_accepts_only_nearby_steps():
    secret = base64.b32encode(os.urandom(20)).decode()
    now = 1_800_000_000
    step = now // 30
    assert mfa._matching_step(secret, mfa.totp(secret, step), now) == step
    assert mfa._matching_step(secret, mfa.totp(secret, step + 1), now) == step + 1
    assert mfa._matching_step(secret, mfa.totp(secret, step - 5), now) is None


def test_mfa_secrets_are_bound_to_their_account():
    sealed = mfa._encrypt("SECRET", "alice")
    assert mfa._decrypt(sealed, "alice") == "SECRET" and "SECRET" not in sealed
    with pytest.raises(Exception):
        mfa._decrypt(sealed, "mallory")


def test_passwords_are_salted_and_verified():
    a, b = auth.hash_password("same-password"), auth.hash_password("same-password")
    assert a != b and "same-password" not in a
    assert auth.verify_password("same-password", a) and not auth.verify_password("wrong", a)


@pytest.mark.parametrize("name", ["a", "Bad", "has space", "-start", "x" * 33, "a/b", "a;b"])
def test_bad_usernames_are_refused(name):
    with pytest.raises(ValueError):
        auth.set_user(name, "viewer", "a-long-password-1")


def test_tool_without_a_mapping_can_be_approved_by_nobody():
    for role in auth.PERMISSIONS:
        assert not auth.can_decide({"permissions": auth.PERMISSIONS[role]}, "brand_new_tool")


def test_researchers_and_admins_cannot_approve_containment():
    for role in ("researcher", "admin", "viewer"):
        assert not any(auth.can_decide({"permissions": auth.PERMISSIONS[role]}, t) for t in auth.APPROVAL_PERMISSION)


def test_only_admins_manage_users():
    assert [r for r, p in auth.PERMISSIONS.items() if "users:manage" in p] == ["admin"]


def test_token_bucket_allows_a_burst_then_refills():
    name = unique("bucket")
    assert [ratelimit.try_acquire(name, 10, 2) for _ in range(2)] == [0.0, 0.0]
    wait = ratelimit.try_acquire(name, 10, 2)
    assert 0 < wait <= 0.1
    time.sleep(wait + 0.02)
    assert ratelimit.try_acquire(name, 10, 2) == 0.0


def test_circuit_breaker_lifecycle():
    name = unique("circuit")
    for _ in range(circuit.THRESHOLD):
        circuit.before_call(name)
        circuit.on_failure(name)
    with pytest.raises(circuit.CircuitOpen):
        circuit.before_call(name)
    db.execute("UPDATE circuits SET opened_until=0 WHERE name=?", (name,))
    circuit.before_call(name)  # the one trial call
    with pytest.raises(circuit.CircuitOpen):
        circuit.before_call(name)  # everyone else waits for it
    circuit.on_success(name)
    circuit.before_call(name)


def test_action_keys_ignore_the_reason_and_formatting():
    a = actions.make_key("r", "block_ip", {"ip": "1.2.3.4", "reason": "one"})
    assert a == actions.make_key("r", "block_ip", {"ip": " 1.2.3.4 ", "reason": "two"})
    assert a != actions.make_key("r", "block_ip", {"ip": "1.2.3.5", "reason": "one"})
    assert a != actions.make_key("other", "block_ip", {"ip": "1.2.3.4", "reason": "one"})


def test_queue_takes_most_urgent_first_and_fences_stale_workers():
    low, high = unique(), unique()
    for run, priority in ((low, 3), (high, 0)):
        db.create_run(run, "ALERT-1", "demo")
        queue.enqueue(run, "ALERT-1", "demo", priority)
    first = queue.claim("w")
    assert first["run_id"] == high
    db.execute("UPDATE jobs SET lease_expires_at=0 WHERE id=?", (first["id"],))
    again = queue.claim("w")
    assert again["run_id"] == high and again["attempts"] == 2
    assert not queue.owns(first["id"], "w", first["attempts"]) and queue.owns(again["id"], "w", again["attempts"])
    assert queue.complete(first, "w") is False and queue.complete(again, "w") is True
    assert queue.claim("w")["run_id"] == low


@pytest.mark.parametrize("secret", ["AIza" + "x" * 30, "sk-ant-abc123", "soc_svc_abcdef", "soc_inv_abcdef", "url?key=abcdefghijkl"])
def test_secrets_are_removed_from_logs(secret):
    assert secret not in obs.redact(f"before {secret} after")


def test_metric_labels_cannot_collide_with_parameters():
    obs.inc("unit_test_metric", 1, name="a", value_label="b")


def test_claude_code_login_is_only_for_its_owner(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "claude_code")
    monkeypatch.setenv("CLAUDE_CODE_OWNER", "owner")
    assert llm.live_refused_for("owner", "live") is None
    assert llm.live_refused_for("someone", "live") and llm.live_refused_for("someone", "auto")
    assert llm.live_refused_for("someone", "demo") is None


def test_production_checks_apply_only_in_production(monkeypatch):
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.setenv("MFA_REQUIRED", "0")
    assert config.problems("web") == []
    monkeypatch.setenv("APP_ENV", "production")
    assert any("MFA_REQUIRED" in p for p in config.problems("web"))
