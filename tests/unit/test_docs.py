"""The README teaches how the agents work, so it must match the code."""
import re
from pathlib import Path

import pytest
from app import auth, multi, policy, tools

ROOT = Path(__file__).resolve().parents[2]
README = (ROOT / "README.md").read_text()
COLUMNS = {"Coordinator": set(multi.COORDINATOR_TOOLS), **{name: set(spec["tools"]) for name, spec in multi.SPECIALISTS.items()}, "Single agent": tools.single_agent_tools()}


def tool_rows():
    section = README[README.index("## The tools"):README.index("## How a decision gets made")]
    lines = [l for l in section.splitlines() if l.startswith("|")]
    header = [c.strip() for c in lines[0].strip("|").split("|")]
    return header, {re.search(r"`(\w+)`", l).group(1): [c.strip() for c in l.strip("|").split("|")] for l in lines[2:]}


def test_every_tool_is_documented():
    assert set(tool_rows()[1]) == set(tools.REGISTRY)


@pytest.mark.parametrize("agent", list(COLUMNS))
def test_the_scope_table_matches_the_code(agent):
    header, rows = tool_rows()
    documented = {name for name, cells in rows.items() if cells[header.index(agent)] == "✅"}
    assert documented == COLUMNS[agent]


def test_risk_labels_match_the_code():
    header, rows = tool_rows()
    labels = {tools.READ: "Read", tools.WRITE: "⚠️ Change", tools.DELEGATE: "Delegate", tools.FINAL: "Final"}
    for name, cells in rows.items():
        assert cells[header.index("Risk")] == labels[tools.risk_of(name)]


def test_stated_limits_match_the_code():
    assert f"up to {multi.MAX_PARALLEL} specialists at once" in README
    assert f"{multi.MAX_CONSULTS} consultations per run" in README
    assert f"{multi.SPECIALIST_MAX_STEPS} loops per consultation" in README


def test_the_role_table_matches_the_code():
    text = (ROOT / "docs/OPERATIONS.md").read_text()
    lines = [l for l in text[text.index("## People and roles"):].splitlines() if l.startswith("|")]
    roles = [c.strip(" `") for c in lines[0].strip("|").split("|")][1:]
    meaning = {"See alerts": "view", "Use the dashboard": "dashboard:view", "Simulate": "alerts:generate", "Start": "run", "Flush": "cache:flush", "Manage users": "users:manage"}
    for line in lines[2:]:
        cells = [c.strip() for c in line.strip("|").split("|")]
        for start, permission in {**meaning, "Approve": "approve:high_impact"}.items():
            if cells[0].startswith(start):
                assert {r for r, c in zip(roles, cells[1:]) if c == "✅"} == {r for r in roles if permission in auth.PERMISSIONS[r]}, cells[0]


@pytest.mark.parametrize("doc", ["README.md", "DEPLOY.md", "docs/SYSTEM_DESIGN.md", "docs/OPERATIONS.md", "docs/TESTING.md"])
def test_local_links_and_images_exist(doc):
    path = ROOT / doc
    for target in re.findall(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", path.read_text()):
        if not target.startswith("http"):
            assert (path.parent / target).exists(), target
