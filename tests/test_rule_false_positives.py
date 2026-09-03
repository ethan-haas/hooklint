"""Rules 5-7 fire on shapes that are frequently legitimate -- do not
over-flag. Targeted false-positive-avoidance checks beyond the clean
corpus, isolating one construct at a time.
"""
import json

from hooklint.engine import scan


def test_benign_pipeline_grep_is_not_flagged(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({
        "hooks": {"SessionStart": [{"hooks": [
            {"type": "command", "command": "cat access.log | grep ERROR | wc -l"}
        ]}]}
    }), encoding="utf-8")
    result = scan(str(tmp_path))
    assert not any(f.rule_id == "fetch_pipe_interpreter" for f in result.findings)


def test_curl_piped_to_jq_not_a_shell_is_not_flagged(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({
        "hooks": {"SessionStart": [{"hooks": [
            {"type": "command", "command": "curl -s https://api.example.com/status | jq .ok"}
        ]}]}
    }), encoding="utf-8")
    result = scan(str(tmp_path))
    assert not any(f.rule_id == "fetch_pipe_interpreter" for f in result.findings)


def test_single_quoted_command_with_dollar_literal_is_not_flagged(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({
        "hooks": {"SessionStart": [{"hooks": [
            {"type": "command", "command": "echo 'price is $5'"}
        ]}]}
    }), encoding="utf-8")
    result = scan(str(tmp_path))
    assert not any(f.rule_id == "unquoted_interpolation" for f in result.findings)


def test_anchored_arg_scoped_permission_is_not_flagged(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({
        "permissions": {"allow": ["Bash(npm run build:*)", "Bash(git commit:*)"]}
    }), encoding="utf-8")
    result = scan(str(tmp_path))
    assert not any(f.rule_id == "broad_permission" for f in result.findings)


def test_file_extension_deny_pattern_is_not_flagged_as_directory_prefix(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({
        "permissions": {"deny": ["Read(./config.local.json)"]}
    }), encoding="utf-8")
    result = scan(str(tmp_path))
    assert not any(f.rule_id == "broad_permission" for f in result.findings)


def test_additional_directories_with_trailing_slash_is_not_flagged(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({
        "permissions": {"additionalDirectories": ["./scripts/", "./tools/"]}
    }), encoding="utf-8")
    result = scan(str(tmp_path))
    assert not any(f.rule_id == "broad_permission" for f in result.findings)


def test_additional_directories_root_drive_is_flagged(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({
        "permissions": {"additionalDirectories": ["/"]}
    }), encoding="utf-8")
    result = scan(str(tmp_path))
    findings = [f for f in result.findings if f.rule_id == "broad_permission"]
    assert findings and "entire drive" in findings[0].message
