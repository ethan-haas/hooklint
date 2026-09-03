"""OBS-3: a wrong-TYPE value for a known key is a fail-unsafe blind spot --
`skill name: [a,b]`, top-level `hooks: [...]`, `permissions.allow: "x"` all
currently pass clean even though the design rule says an out-of-shape
construct for a known key must be REPORTED, never defaulted to clean.

These are conservative, scoped additions: only keys this codebase already
treats as one concrete type via an existing `isinstance(...)` gate get a
type check, and `None`/absent values are left untouched (owned by the rule
that already handles missing/empty for that key) to avoid double-reporting.
"""
import json

from hooklint.engine import scan
from hooklint.pointer import resolve_pointer


def _write_settings(tmp_path, payload):
    d = tmp_path / ".claude"
    d.mkdir(exist_ok=True)
    (d / "settings.json").write_text(json.dumps(payload), encoding="utf-8")


def _write_skill(tmp_path, frontmatter_lines):
    d = tmp_path / ".claude" / "skills" / "myskill"
    d.mkdir(parents=True, exist_ok=True)
    body = "---\n" + "\n".join(frontmatter_lines) + "\n---\nBody text.\n"
    (d / "SKILL.md").write_text(body, encoding="utf-8")


# -- skill frontmatter name/description wrong type --------------------------

def test_skill_name_as_list_is_reported_not_silently_clean(tmp_path):
    _write_skill(tmp_path, ["name: [a, b]", "description: does a thing"])
    result = scan(str(tmp_path))
    findings = [f for f in result.findings if f.rule_id == "unknown_key"]
    assert findings, "wrong-type skill name must be reported, not silently clean"
    f = findings[0]
    assert "name" in f.message and "list" in f.message and "string" in f.message
    assert f.json_pointer == "/name"


def test_skill_name_as_number_is_reported(tmp_path):
    _write_skill(tmp_path, ["name: 123", "description: does a thing"])
    result = scan(str(tmp_path))
    findings = [f for f in result.findings if f.rule_id == "unknown_key" and f.json_pointer == "/name"]
    assert findings and "int" in findings[0].message


def test_skill_description_wrong_type_is_reported(tmp_path):
    _write_skill(tmp_path, ["name: myskill", "description: [1, 2]"])
    result = scan(str(tmp_path))
    findings = [f for f in result.findings if f.rule_id == "unknown_key" and f.json_pointer == "/description"]
    assert findings and "list" in findings[0].message


def test_skill_valid_string_name_and_description_stay_clean(tmp_path):
    _write_skill(tmp_path, ["name: myskill", "description: does a thing"])
    result = scan(str(tmp_path))
    assert not any(f.rule_id == "unknown_key" and f.json_pointer in ("/name", "/description")
                   for f in result.findings)


def test_skill_missing_name_is_not_double_reported_by_unknown_key(tmp_path):
    # unreachable_skill already owns the missing/empty case -- unknown_key's
    # wrong-type check must not ALSO fire for the same defect.
    _write_skill(tmp_path, ["description: does a thing"])
    result = scan(str(tmp_path))
    assert not any(f.rule_id == "unknown_key" and f.json_pointer == "/name" for f in result.findings)
    assert any(f.rule_id == "unreachable_skill" for f in result.findings)


def test_skill_null_name_is_not_double_reported_by_unknown_key(tmp_path):
    _write_skill(tmp_path, ["name:", "description: does a thing"])
    result = scan(str(tmp_path))
    assert not any(f.rule_id == "unknown_key" and f.json_pointer == "/name" for f in result.findings)
    assert any(f.rule_id == "unreachable_skill" for f in result.findings)


# -- claude_settings top-level hooks/permissions/mcpServers wrong type ------

def test_top_level_hooks_as_list_is_reported(tmp_path):
    _write_settings(tmp_path, {"hooks": [{"matcher": "Bash"}]})
    result = scan(str(tmp_path))
    findings = [f for f in result.findings if f.rule_id == "unknown_key" and f.json_pointer == "/hooks"]
    assert findings and "mapping" in findings[0].message and "list" in findings[0].message


def test_top_level_permissions_as_string_is_reported(tmp_path):
    _write_settings(tmp_path, {"permissions": "allow-all"})
    result = scan(str(tmp_path))
    findings = [f for f in result.findings if f.rule_id == "unknown_key" and f.json_pointer == "/permissions"]
    assert findings and "mapping" in findings[0].message and "str" in findings[0].message


def test_top_level_mcpservers_as_list_is_reported(tmp_path):
    _write_settings(tmp_path, {"mcpServers": [{"command": "npx"}]})
    result = scan(str(tmp_path))
    findings = [f for f in result.findings if f.rule_id == "unknown_key" and f.json_pointer == "/mcpServers"]
    assert findings and "mapping" in findings[0].message


def test_valid_dict_shaped_hooks_permissions_mcpservers_stay_clean(tmp_path):
    _write_settings(tmp_path, {
        "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "x"}]}]},
        "permissions": {"allow": ["Bash(git status:*)"]},
        "mcpServers": {"foo": {"type": "http", "url": "https://example.com"}},
    })
    result = scan(str(tmp_path))
    assert not any(f.rule_id == "unknown_key" and f.json_pointer in ("/hooks", "/permissions", "/mcpServers")
                   for f in result.findings)


# -- permissions.allow/deny/ask/additionalDirectories wrong type ------------

def test_permissions_allow_as_string_is_reported(tmp_path):
    _write_settings(tmp_path, {"permissions": {"allow": "Bash(git status:*)"}})
    result = scan(str(tmp_path))
    findings = [f for f in result.findings
                if f.rule_id == "unknown_key" and f.json_pointer == "/permissions/allow"]
    assert findings and "list" in findings[0].message and "str" in findings[0].message


def test_permissions_deny_as_dict_is_reported(tmp_path):
    _write_settings(tmp_path, {"permissions": {"deny": {"Bash": "rm"}}})
    result = scan(str(tmp_path))
    findings = [f for f in result.findings
                if f.rule_id == "unknown_key" and f.json_pointer == "/permissions/deny"]
    assert findings and "list" in findings[0].message


def test_permissions_valid_lists_stay_clean(tmp_path):
    _write_settings(tmp_path, {
        "permissions": {
            "allow": ["Bash(git status:*)"],
            "deny": ["Bash(rm -rf:*)"],
            "ask": ["Bash(git push:*)"],
            "additionalDirectories": ["./scripts/"],
        }
    })
    result = scan(str(tmp_path))
    assert not any(f.rule_id == "unknown_key" and f.json_pointer.startswith("/permissions/")
                   for f in result.findings)


# -- pointer discipline + unknown accounting --------------------------------

def test_wrong_type_finding_pointer_resolves(tmp_path):
    _write_settings(tmp_path, {"hooks": [], "permissions": {"allow": "x"}})
    result = scan(str(tmp_path))
    doc = json.loads((tmp_path / ".claude" / "settings.json").read_text(encoding="utf-8"))
    findings = [f for f in result.findings if f.rule_id == "unknown_key"]
    assert findings
    for f in findings:
        resolve_pointer(doc, f.json_pointer)  # raises PointerError on failure


def test_wrong_type_finding_increments_unknown_count(tmp_path):
    _write_settings(tmp_path, {"hooks": []})
    before = scan(str(tmp_path))
    assert before.ctx.unknown >= 1
