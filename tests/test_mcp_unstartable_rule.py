import json
import os

from hooklint.engine import scan
from hooklint.rules import mcp_unstartable


def _write_mcp(tmp_path, servers):
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")


def test_bare_command_resolvable_on_path_is_not_flagged(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp_unstartable.shutil, "which", lambda cmd: "/usr/bin/" + cmd)
    _write_mcp(tmp_path, {"foo": {"command": "npx", "args": ["-y", "some-server"]}})
    result = scan(str(tmp_path))
    assert not any(f.rule_id == "mcp_unstartable" for f in result.findings)


def test_bare_command_not_on_path_is_flagged(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp_unstartable.shutil, "which", lambda cmd: None)
    _write_mcp(tmp_path, {"foo": {"command": "npx"}})
    result = scan(str(tmp_path))
    findings = [f for f in result.findings if f.rule_id == "mcp_unstartable"]
    assert findings and "not resolvable on PATH" in findings[0].message


def test_absolute_path_that_exists_is_not_flagged(tmp_path):
    real_script = tmp_path / "server.js"
    real_script.write_text("// noop\n", encoding="utf-8")
    _write_mcp(tmp_path, {"foo": {"command": str(real_script)}})
    result = scan(str(tmp_path))
    assert not any(f.rule_id == "mcp_unstartable" for f in result.findings)


def test_absolute_path_that_does_not_exist_is_flagged(tmp_path):
    missing = str(tmp_path / "nope" / "server.js")
    _write_mcp(tmp_path, {"foo": {"command": missing}})
    result = scan(str(tmp_path))
    findings = [f for f in result.findings if f.rule_id == "mcp_unstartable"]
    assert findings and "does not exist" in findings[0].message


def test_relative_path_is_always_flagged_even_if_it_happens_to_exist(tmp_path):
    (tmp_path / "server.js").write_text("// noop\n", encoding="utf-8")
    _write_mcp(tmp_path, {"foo": {"command": "./server.js"}})
    result = scan(str(tmp_path))
    findings = [f for f in result.findings if f.rule_id == "mcp_unstartable"]
    assert findings and "relative path" in findings[0].message


def test_declared_env_var_present_is_not_flagged(tmp_path, monkeypatch):
    monkeypatch.setenv("MY_TOKEN", "x")
    monkeypatch.setattr(mcp_unstartable.shutil, "which", lambda cmd: "/usr/bin/" + cmd)
    _write_mcp(tmp_path, {"foo": {"command": "someserver", "env": {"TOKEN": "${MY_TOKEN}"}}})
    result = scan(str(tmp_path))
    assert not any(f.rule_id == "mcp_unstartable" for f in result.findings)


def test_declared_env_var_absent_is_flagged(tmp_path, monkeypatch):
    monkeypatch.delenv("DEFINITELY_NOT_SET_XYZ", raising=False)
    monkeypatch.setattr(mcp_unstartable.shutil, "which", lambda cmd: "/usr/bin/" + cmd)
    _write_mcp(tmp_path, {"foo": {"command": "someserver", "env": {"TOKEN": "${DEFINITELY_NOT_SET_XYZ}"}}})
    result = scan(str(tmp_path))
    findings = [f for f in result.findings if f.rule_id == "mcp_unstartable"]
    assert findings and "absent from the environment" in findings[0].message


def test_literal_env_value_is_not_treated_as_a_reference(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp_unstartable.shutil, "which", lambda cmd: "/usr/bin/" + cmd)
    _write_mcp(tmp_path, {"foo": {"command": "someserver", "env": {"MODE": "production"}}})
    result = scan(str(tmp_path))
    assert not any(f.rule_id == "mcp_unstartable" for f in result.findings)


def test_http_type_skips_command_check_entirely(tmp_path):
    _write_mcp(tmp_path, {"foo": {"type": "http", "url": "https://example.com/mcp"}})
    result = scan(str(tmp_path))
    assert not any(f.rule_id == "mcp_unstartable" for f in result.findings)


# -- OBS-1: message must name the actual cause, not always "command is empty" --

def test_non_string_list_command_message_names_the_real_cause(tmp_path):
    _write_mcp(tmp_path, {"foo": {"command": ["node", "server.js"]}})
    result = scan(str(tmp_path))
    findings = [f for f in result.findings if f.rule_id == "mcp_unstartable"]
    assert findings
    assert "not a string" in findings[0].message
    assert "got list" in findings[0].message
    assert "is empty" not in findings[0].message
    assert findings[0].evidence == repr(["node", "server.js"])


def test_non_string_dict_command_message_names_the_real_cause(tmp_path):
    _write_mcp(tmp_path, {"foo": {"command": {"exe": "node"}}})
    result = scan(str(tmp_path))
    findings = [f for f in result.findings if f.rule_id == "mcp_unstartable"]
    assert findings
    assert "not a string" in findings[0].message
    assert "got dict" in findings[0].message
    assert "is empty" not in findings[0].message


def test_non_string_number_command_message_names_the_real_cause(tmp_path):
    _write_mcp(tmp_path, {"foo": {"command": 123}})
    result = scan(str(tmp_path))
    findings = [f for f in result.findings if f.rule_id == "mcp_unstartable"]
    assert findings
    assert "not a string" in findings[0].message
    assert "got int" in findings[0].message
    assert "is empty" not in findings[0].message


def test_non_string_bool_command_message_names_the_real_cause(tmp_path):
    _write_mcp(tmp_path, {"foo": {"command": True}})
    result = scan(str(tmp_path))
    findings = [f for f in result.findings if f.rule_id == "mcp_unstartable"]
    assert findings
    assert "not a string" in findings[0].message
    assert "got bool" in findings[0].message
    assert "is empty" not in findings[0].message


def test_empty_string_command_still_says_empty(tmp_path):
    _write_mcp(tmp_path, {"foo": {"command": ""}})
    result = scan(str(tmp_path))
    findings = [f for f in result.findings if f.rule_id == "mcp_unstartable"]
    assert findings and findings[0].message.endswith("command is empty")


def test_whitespace_only_command_still_says_empty(tmp_path):
    _write_mcp(tmp_path, {"foo": {"command": "   "}})
    result = scan(str(tmp_path))
    findings = [f for f in result.findings if f.rule_id == "mcp_unstartable"]
    assert findings and findings[0].message.endswith("command is empty")


# -- OBS-2: present-but-null command flagged; genuinely absent stays clean --

def test_null_command_is_flagged_as_unstartable(tmp_path):
    _write_mcp(tmp_path, {"foo": {"command": None}})
    result = scan(str(tmp_path))
    findings = [f for f in result.findings if f.rule_id == "mcp_unstartable"]
    assert findings and "command is null" in findings[0].message
    assert findings[0].json_pointer == "/mcpServers/foo/command"


def test_absent_command_key_is_not_flagged(tmp_path):
    # No "command" key at all (distinct from an explicit null) -- OBS-2
    # scopes the fix strictly to present-but-null, leaving a genuinely
    # absent command's existing (unflagged) behavior untouched.
    _write_mcp(tmp_path, {"foo": {"args": ["-y", "some-server"]}})
    result = scan(str(tmp_path))
    assert not any(f.rule_id == "mcp_unstartable" for f in result.findings)
