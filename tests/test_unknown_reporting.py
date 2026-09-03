"""Acceptance gate 3: unknown is reported, not cleaned. A construct outside
the declared tables yields `unknown`, asserted directly -- never defaulted
to clean and never guessed at.
"""
import json

from hooklint.engine import scan


def test_unknown_hook_entry_type_is_reported_not_silently_clean(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({
        "hooks": {
            "PreToolUse": [
                {"matcher": "Bash", "hooks": [{"type": "script", "command": "x"}]}
            ]
        }
    }), encoding="utf-8")

    result = scan(str(tmp_path))
    unknown_findings = [f for f in result.findings if "unknown" in f.message.lower()]
    assert unknown_findings, "an unrecognized hook entry type must be reported as unknown, not silently accepted"
    assert result.ctx.unknown >= 1


def test_unknown_mcp_server_type_is_reported(tmp_path):
    (tmp_path / ".mcp.json").write_text(json.dumps({
        "mcpServers": {"foo": {"type": "grpc", "command": "x"}}
    }), encoding="utf-8")

    result = scan(str(tmp_path))
    assert any(f.rule_id == "mcp_unstartable" and "unknown type" in f.message for f in result.findings)


def test_unknown_rate_is_not_hidden_by_clean_result(clean_root):
    """A file with a construct hooklint cannot classify should raise
    unknown, not silently be swallowed into a 0-finding clean pass. We
    assert the machinery *can* produce a nonzero unknown count (exercised
    by the two tests above via engine internals) and that the metric is
    surfaced in both human and JSON CLI output.
    """
    from hooklint.cli import _json_report, _human_report

    result = scan(clean_root)
    payload = json.loads(_json_report(result))
    assert "unknown_rate" in payload
    assert "unknown" in payload
    human = _human_report(result)
    assert "unknown_rate=" in human
