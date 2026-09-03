"""Regression test for the contract fix: an `mcp__<server>__<tool>` matcher
is correctly classified `unknown` (severity `info`, message "...unknown,
not dead") -- but was still emitted with `rule_id="dead_matcher"`. A JSON
consumer filtering `rule_id == "dead_matcher"` would misread a genuinely
unknown/undecidable verdict as a confident dead one.

ROOT FIX: the unknown-matcher case now gets its own `rule_id`,
`"unknown_matcher"`, distinct from `"dead_matcher"`. `dead_matcher` is
reserved for confident dead verdicts (typos like `Bsah`, wrong event names
like `PreToolUseX`). Severity and the `unknown` accounting counter are
unchanged.
"""
import json

from hooklint.engine import scan


def _write(tmp_path, rel, content):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def test_mcp_namespace_matcher_gets_unknown_matcher_rule_id(tmp_path):
    _write(tmp_path, ".claude/settings.json", json.dumps({
        "hooks": {"PreToolUse": [
            {"matcher": "mcp__memory__.*", "hooks": [{"type": "command", "command": "echo ok"}]}
        ]}
    }))
    result = scan(str(tmp_path))

    # No finding is EVER emitted with rule_id "dead_matcher" for this
    # matcher -- a consumer filtering on that rule_id alone must not see it.
    assert not any(f.rule_id == "dead_matcher" for f in result.findings)

    unknown_findings = [f for f in result.findings if f.rule_id == "unknown_matcher"]
    assert unknown_findings, "the mcp__ namespace matcher must be reported under its own rule_id"
    assert unknown_findings[0].severity == "info"
    assert "unknown" in unknown_findings[0].message.lower()
    assert result.ctx.unknown >= 1


def test_genuine_dead_matcher_keeps_dead_matcher_rule_id(tmp_path):
    _write(tmp_path, ".claude/settings.json", json.dumps({
        "hooks": {"PreToolUse": [
            {"matcher": "Bsah", "hooks": [{"type": "command", "command": "echo ok"}]}
        ]}
    }))
    result = scan(str(tmp_path))
    dead = [f for f in result.findings if f.rule_id == "dead_matcher" and f.severity == "error"]
    assert dead, "a genuine typo must still be rule_id=dead_matcher, severity=error"
    assert not any(f.rule_id == "unknown_matcher" for f in result.findings)


def test_unknown_matcher_rule_id_also_applies_to_generic_yaml(tmp_path):
    _write(tmp_path, "agent-hooks.yaml", (
        "hooks:\n"
        "  pre_tool_use:\n"
        "    - match: shell\n"
        "      run: echo ok\n"
    ))
    # `shell` IS a declared generic tool, so this control should have no
    # matcher finding at all -- included here as a differential control
    # for the mcp__-namespace-shaped test below.
    result = scan(str(tmp_path))
    assert not any(f.rule_id in ("dead_matcher", "unknown_matcher") for f in result.findings)


def test_unknown_matcher_rule_id_also_applies_to_generic_toml(tmp_path):
    _write(tmp_path, "agent-hooks.toml", (
        "[[hooks.pre_tool_use]]\n"
        'match = "mcp__memory__.*"\n'
        'run = "echo ok"\n'
    ))
    result = scan(str(tmp_path))
    assert not any(f.rule_id == "dead_matcher" for f in result.findings)
    assert any(f.rule_id == "unknown_matcher" for f in result.findings)
