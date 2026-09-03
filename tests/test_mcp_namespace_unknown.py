"""Regression test for a defect found in review: a matcher targeting the mcp__ namespace
(`mcp__.*`, `mcp__memory__.*`, `mcp__github__create_issue`, ...) was
flagged `dead_matcher` "will never fire", violating hooklint's own design
rule: a construct outside the declared closed table is `unknown`,
reported, never guessed dead (or clean).

ROOT FIX: `mcp__<server>__<tool>` is an OPEN namespace -- MCP servers
register their tools at runtime and hooklint has no closed table for them
offline. `dead_matcher._matcher_is_dead` now classifies a matcher into
three states (see `hooklint.rules.dead_matcher`): "ok" (matches a declared
tool), "unknown" (matches no declared tool but CAN reach the mcp__
namespace), or "dead" (matches nothing at all, including mcp__). A matcher
that matches at least one static tool OR the mcp__ namespace is not dead;
a genuine typo remains dead.
"""
import json

import pytest

from hooklint.engine import scan


def _write(tmp_path, rel, content):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


@pytest.mark.parametrize("matcher", [
    "mcp__.*",
    "mcp__memory__.*",
    "mcp__github__create_issue",
])
def test_mcp_namespace_matcher_is_unknown_not_dead(tmp_path, matcher):
    _write(tmp_path, ".claude/settings.json", json.dumps({
        "hooks": {"PreToolUse": [
            {"matcher": matcher, "hooks": [{"type": "command", "command": "echo ok"}]}
        ]}
    }))
    result = scan(str(tmp_path))
    assert not any(f.rule_id == "dead_matcher" and f.severity == "error" for f in result.findings), (
        "an mcp__ matcher must not be reported dead_matcher -- it targets an open "
        "namespace hooklint cannot enumerate offline"
    )
    unknown_findings = [f for f in result.findings if "unknown" in f.message.lower()]
    assert unknown_findings
    assert result.ctx.unknown >= 1


def test_mcp_namespace_combined_with_static_tool_is_not_dead_and_not_unknown(tmp_path):
    # "matches at least one static tool OR the mcp__ namespace is not dead"
    # -- and here it resolves a real static tool, so it is fully decidable
    # (not even reported as unknown).
    _write(tmp_path, ".claude/settings.json", json.dumps({
        "hooks": {"PreToolUse": [
            {"matcher": "Bash|mcp__memory__.*", "hooks": [{"type": "command", "command": "echo ok"}]}
        ]}
    }))
    result = scan(str(tmp_path))
    assert not any(f.rule_id == "dead_matcher" for f in result.findings)


def test_genuine_typo_matcher_still_flagged_dead(tmp_path):
    _write(tmp_path, ".claude/settings.json", json.dumps({
        "hooks": {"PreToolUse": [
            {"matcher": "Bsah", "hooks": [{"type": "command", "command": "echo ok"}]}
        ]}
    }))
    result = scan(str(tmp_path))
    dead = [f for f in result.findings if f.rule_id == "dead_matcher" and f.severity == "error"]
    assert dead, "a genuine typo outside every declared table (including mcp__) must still be dead"


def test_unknown_event_name_typo_still_flagged_dead(tmp_path):
    _write(tmp_path, ".claude/settings.json", json.dumps({
        "hooks": {"PreToolUse": [
            {"matcher": "PreToolUseX", "hooks": [{"type": "command", "command": "echo ok"}]}
        ]}
    }))
    result = scan(str(tmp_path))
    dead = [f for f in result.findings if f.rule_id == "dead_matcher" and f.severity == "error"]
    assert dead
