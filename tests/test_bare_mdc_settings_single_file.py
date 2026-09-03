"""Regression test (cheap, same class as prior single-file-mode fixes):
`hooklint rule.mdc` (a Cursor rule file passed directly, not under
`.cursor/rules/`) and `hooklint settings.json` (passed directly, not under
`.claude/`) scanned 0 files and exited 0 -- a silent no-op on an
explicitly-passed config, the same fail-unsafe class as the earlier
`SKILL.md` single-file-mode gap (see test_skill_md_basename.py).

ROOT FIX: `discovery.discover`'s single-file-mode fallback (which already
special-cased bare `SKILL.md`) now also classifies by distinctive
extension/basename when the path arg is a file:
* any `*.mdc` basename -> cursor_mdc/cursor (Cursor rule files are always
  named with this extension; there is no other real use for it)
* the exact basename `settings.json` -> claude_settings/claude_code

This applies ONLY in single-file mode (the caller named the file
directly) -- directory-walk discovery (`classify()`) is unchanged, so a
random `settings.json` or `*.mdc` buried deep in a scanned tree is still
NOT auto-discovered unless it sits under the declared `.claude/` /
`.cursor/rules/` ancestor, same as before. `settings.local.json` is
unaffected (still requires the `.claude` ancestor even in single-file
mode) -- only the exact basename `settings.json` is widened, matching the
task's stated scope. A generically-named file (`notes.md`, `config.json`)
is still not classified at all.
"""
import json

from hooklint.engine import scan


def _write(tmp_path, rel, content):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def test_bare_mdc_single_file_mode_is_scanned(tmp_path):
    rule = _write(tmp_path, "rule.mdc", "---\ndescription: x\nunknownKey: 1\n---\nbody\n")
    result = scan(str(rule))
    assert result.files_scanned, "an explicitly-passed *.mdc must not silently scan 0 files"
    assert any(f.rule_id == "unknown_key" for f in result.findings)


def test_bare_settings_json_single_file_mode_is_scanned(tmp_path):
    settings = _write(tmp_path, "settings.json", json.dumps({
        "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "echo $FOO"}]}]}
    }))
    result = scan(str(settings))
    assert result.files_scanned, "an explicitly-passed settings.json must not silently scan 0 files"
    assert any(f.rule_id == "unquoted_interpolation" for f in result.findings)


def test_control_cursor_rules_dir_layout_still_works(tmp_path):
    _write(tmp_path, ".cursor/rules/foo.mdc", "---\ndescription: x\nunknownKey: 1\n---\nbody\n")
    result = scan(str(tmp_path))
    assert any(f.rule_id == "unknown_key" for f in result.findings)


def test_control_claude_settings_dir_layout_still_works(tmp_path):
    _write(tmp_path, ".claude/settings.json", json.dumps({
        "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "echo $FOO"}]}]}
    }))
    result = scan(str(tmp_path))
    assert any(f.rule_id == "unquoted_interpolation" for f in result.findings)


def test_bare_settings_local_json_still_requires_claude_ancestor(tmp_path):
    settings = _write(tmp_path, "settings.local.json", json.dumps({}))
    result = scan(str(settings))
    assert result.files_scanned == [], (
        "settings.local.json is unaffected -- only the exact basename "
        "settings.json is widened by this fix"
    )


def test_random_json_single_file_mode_still_not_classified(tmp_path):
    other = _write(tmp_path, "config.json", json.dumps({"hooks": {}}))
    result = scan(str(other))
    assert result.files_scanned == []


def test_random_md_single_file_mode_still_not_classified(tmp_path):
    notes = _write(tmp_path, "notes.md", "just notes\n")
    result = scan(str(notes))
    assert result.files_scanned == []
