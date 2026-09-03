"""Regression test for the broad_permission (rule 7) MCP/tool-token grammar
fix: two entangled bugs used to make the classification depend on incidental
characters instead of structure.

  1. Classification was INVERTED for `mcp__` tokens: a fully specified
     `mcp__<server>__<tool>` grant (e.g. `mcp__github__create_issue`) was
     flagged broad, while a wildcarded `mcp__<server>__*` grant came back
     clean.
  2. Any token containing a `-` or `.` anywhere silently fell through to the
     path classifier and was cleared, regardless of whether it actually had
     a scoping specifier -- an undocumented lexical suppression that let a
     hyphenated/dotted MCP server name (`mcp__git-hub__x`,
     `mcp__server.name__tool`) escape rule 7 entirely, and would have let a
     hyphenated/dotted bare tool grant escape it too.

The fix classifies every permission string by STRUCTURE (path-style vs
`mcp__` token vs `(...)`-scopable tool), never by incidental characters.
This file is the full acceptance table from the task spec plus a
"realistic project" false-positive guard and the pointer-resolution
invariant.
"""
import json

import pytest

from hooklint.engine import scan
from hooklint.rules.broad_permission import _classify_pattern


# -- Table-driven unit coverage of _classify_pattern -----------------------

# (pattern, expect_flagged) -- mirrors the task spec's acceptance table
# exactly, both directions.
TABLE = [
    # specific MCP tool grants -- must be CLEAN regardless of separator
    # characters in the server name.
    ("mcp__github__create_issue", False),
    ("mcp__git-hub__create_issue", False),
    ("mcp__server.name__tool", False),
    # bare tool family -- always broad.
    ("Bash", True),
    # scoped tool invocation -- clean.
    ("Bash(npm test)", False),
    # server-only MCP grant (no tool segment) -- broad.
    ("mcp__github", True),
    # wildcard MCP tool grant -- broad.
    ("mcp__github__*", True),
    # bare unanchored wildcard -- broad.
    ("*", True),
    # separator-less path prefix -- unchanged, still broad.
    ("/srv/app", True),
]


@pytest.mark.parametrize("pattern,expect_flagged", TABLE)
def test_classify_pattern_table(pattern, expect_flagged):
    reason = _classify_pattern(pattern)
    if expect_flagged:
        assert reason is not None, f"{pattern!r} should be flagged broad but was clean"
    else:
        assert reason is None, f"{pattern!r} should be clean but was flagged: {reason!r}"


# -- Hyphen/dot consistency: MUST NOT change the verdict --------------------

def test_hyphen_and_dot_do_not_change_mcp_verdict():
    underscore = _classify_pattern("mcp__github__create_issue")
    hyphen = _classify_pattern("mcp__git-hub__create_issue")
    dot = _classify_pattern("mcp__server.name__tool")
    assert underscore is None and hyphen is None and dot is None


def test_hyphen_and_dot_do_not_suppress_a_genuine_broad_grant():
    # A server-only grant is broad no matter what characters the server
    # name contains -- the old lexical-suppression bug would have cleared
    # these because of the '-'/'.' anywhere in the token.
    assert _classify_pattern("mcp__git-hub") is not None
    assert _classify_pattern("mcp__server.name") is not None


def test_wildcard_in_either_mcp_segment_is_flagged():
    assert _classify_pattern("mcp__github__*") is not None
    assert _classify_pattern("mcp__*__create_issue") is not None
    assert _classify_pattern("mcp__*") is not None


# -- Full-scan regression: realistic settings.json with the whole table ---

def test_full_table_via_scan(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({
        "permissions": {"allow": [p for p, _ in TABLE]}
    }), encoding="utf-8")
    result = scan(str(tmp_path))
    flagged = {f.evidence for f in result.findings if f.rule_id == "broad_permission"}
    expected_flagged = {p for p, expect in TABLE if expect}
    expected_clean = {p for p, expect in TABLE if not expect}
    assert flagged == expected_flagged
    assert flagged.isdisjoint(expected_clean)


# -- Guard: a realistic project full of specific MCP tool grants must be
#    entirely clean (gate-2 direction). ------------------------------------

def test_realistic_mcp_tool_grants_are_all_clean(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({
        "permissions": {"allow": [
            "mcp__github__create_issue",
            "mcp__github__list_pull_requests",
            "mcp__filesystem__read_file",
            "mcp__filesystem__write_file",
            "mcp__playwright__browser_navigate",
            "mcp__playwright__browser_click",
            "mcp__git-hub__create_issue",
            "mcp__context7__get-library-docs",
            "mcp__server.name__tool",
            "Bash(npm test)",
            "Bash(git commit:*)",
            "Read(./config.local.json)",
        ]}
    }), encoding="utf-8")
    result = scan(str(tmp_path))
    findings = [f for f in result.findings if f.rule_id == "broad_permission"]
    assert not findings, f"unexpected broad_permission findings: {findings}"


# -- Guard: genuinely broad grants must stay flagged after the fix --------

def test_genuinely_broad_grants_still_flagged(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({
        "permissions": {"allow": [
            "Bash",
            "Read",
            "Write",
            "mcp__github",
            "mcp__github__*",
            "*",
            "/srv/app",
        ]}
    }), encoding="utf-8")
    result = scan(str(tmp_path))
    flagged = {f.evidence for f in result.findings if f.rule_id == "broad_permission"}
    assert flagged == {"Bash", "Read", "Write", "mcp__github", "mcp__github__*", "*", "/srv/app"}


# -- Pointer-resolution invariant still holds for every finding in this
#    file's scans. ----------------------------------------------------------

def test_findings_pointers_resolve(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({
        "permissions": {"allow": [p for p, expect in TABLE if expect]}
    }), encoding="utf-8")
    result = scan(str(tmp_path))
    data = json.loads((tmp_path / ".claude" / "settings.json").read_text(encoding="utf-8"))
    for f in result.findings:
        if f.rule_id != "broad_permission":
            continue
        # walk the RFC-6901 pointer manually to confirm it resolves
        parts = [p.replace("~1", "/").replace("~0", "~") for p in f.json_pointer.split("/")[1:]]
        node = data
        for part in parts:
            if isinstance(node, list):
                node = node[int(part)]
            else:
                node = node[part]
        assert node == f.evidence
