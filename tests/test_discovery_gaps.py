"""Regression test for a defect found in review and one README-claimed dialect gap.

Single-file mode -- `python -m hooklint .claude/settings.json` (single-FILE mode,
the README's flagship command) silently scanned 0 files and exited 0
clean, missing a planted defect, even though the same file inside a
directory scan is found correctly. ROOT CAUSE: single-file mode reduced
the path to `os.path.basename(path)` before classifying it, throwing away
the parent-directory context (`.claude`, `skills`, `commands`, ...) that
`classify()` needs. ROOT FIX: `hooklint.discovery.discover` now classifies
a file argument the same way directory mode does -- off the full given
path first, falling back to the resolved absolute path (whose real parent
directories still carry that context even if the caller didn't type it) --
for every supported config type, since it reuses the one `classify()`
table rather than special-casing settings.json.

Also fix -- generic `agent-hooks.toml`, `agent-hooks.json`, and top-level
`mcp.json` were silently unscanned (`checked=0`, no parse_error) while
`agent-hooks.yaml` worked, despite the README claiming a "declared generic
YAML/TOML hook and MCP manifest shape". ROOT FIX: extend discovery's
filename table to cover them.
"""
import json
import os

from hooklint.cli import main
from hooklint.engine import scan


def _write(tmp_path, rel, content):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


# -- single-file mode --------------------------------------------------------------

def test_single_file_mode_finds_defect_in_claude_settings(tmp_path):
    _write(tmp_path, ".claude/settings.json", json.dumps({
        "hooks": {"PreToolUse": [
            {"matcher": "Bahs", "hooks": [{"type": "command", "command": "echo checked"}]}
        ]}
    }))

    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        code = main([".claude/settings.json"])
        assert code == 1, "the README flagship command must find the planted defect, not scan 0 files"

        result = scan(".claude/settings.json")
    finally:
        os.chdir(cwd)

    assert result.files_scanned == [".claude/settings.json"]
    assert any(f.rule_id == "dead_matcher" for f in result.findings)


def test_single_file_mode_works_without_typed_parent_context(tmp_path):
    # `cd .claude && hooklint settings.json` -- the caller didn't type the
    # ".claude" segment, but it's still the file's real parent directory,
    # so classification must still succeed via the resolved absolute path.
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(json.dumps({
        "hooks": {"PreToolUse": [
            {"matcher": "Bahs", "hooks": [{"type": "command", "command": "x"}]}
        ]}
    }), encoding="utf-8")

    result = scan(str(settings))
    assert result.files_scanned, "single-file mode must not silently scan 0 files"
    assert any(f.rule_id == "dead_matcher" for f in result.findings)


def test_single_file_mode_scans_a_skill_md(tmp_path):
    _write(tmp_path, ".claude/skills/foo/SKILL.md", "---\nname: x\n---\nbody\n")
    result = scan(str(tmp_path / ".claude" / "skills" / "foo" / "SKILL.md"))
    assert result.files_scanned
    assert any(f.rule_id == "unreachable_skill" for f in result.findings)


def test_single_file_mode_still_returns_empty_for_unrecognized_filename(tmp_path):
    p = _write(tmp_path, "not_a_config.txt", "irrelevant content\n")
    result = scan(str(p))
    assert result.files_scanned == []


# -- Also fix: README-claimed generic manifests must be discovered --------

def test_agent_hooks_toml_is_discovered_and_scanned(tmp_path):
    _write(tmp_path, "agent-hooks.toml", (
        '[[hook]]\nevent = "pre_tool_use"\nmatcher = "totally_unknown_tool_zzz"\n'
        'command = "echo hi"\n'
    ))
    result = scan(str(tmp_path))
    assert result.files_scanned
    assert any(f.rule_id == "dead_matcher" for f in result.findings)


def test_agent_hooks_json_is_discovered_and_scanned(tmp_path):
    _write(tmp_path, "agent-hooks.json", json.dumps({
        "hooks": {"pre_tool_use": [{"match": "shell", "run": "echo $UNSAFE"}]}
    }))
    result = scan(str(tmp_path))
    assert result.files_scanned
    assert any(f.rule_id == "unquoted_interpolation" for f in result.findings)


def test_top_level_mcp_json_is_discovered_and_scanned(tmp_path):
    _write(tmp_path, "mcp.json", json.dumps({
        "mcpServers": {"foo": {"command": "./relative/path"}}
    }))
    result = scan(str(tmp_path))
    assert result.files_scanned
    assert any(f.rule_id == "mcp_unstartable" for f in result.findings)


def test_cursor_mcp_json_still_gets_cursor_dialect_not_generic(tmp_path):
    # Existing `.cursor/mcp.json` classification must be unaffected by
    # adding the top-level generic fallback.
    _write(tmp_path, ".cursor/mcp.json", json.dumps({
        "mcpServers": {"foo": {"command": "definitely-not-a-real-binary-xyz"}}
    }))
    result = scan(str(tmp_path))
    assert any(f.rule_id == "mcp_unstartable" for f in result.findings)
