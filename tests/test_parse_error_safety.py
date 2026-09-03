"""Regression tests for two confirmed escapes found by an independent
audit: a loader must turn EVERY way a file fails to become data into a
`parse_error` (exit 2), never an uncaught traceback, and must not
misreport a routine UTF-8 BOM as malformed.

Non-UTF-8 / binary config crashed with an uncaught
UnicodeDecodeError (exit 1, traceback on stderr). ROOT FIX: every text
loader reads via a BOM-tolerant decode that turns a decode failure into
`LoadError` -> `parse_error` -> exit 2, for every dialect, not just
claude_settings.

A ~20k-deep nested JSON document crashed with an uncaught
RecursionError (exit 1). ROOT FIX: every structured loader (json/yaml)
catches RecursionError and converts it to the same parse_error/exit-2
path, on any Python version (never fixed by raising the recursion limit).

A UTF-8 BOM on an otherwise-valid file was reported malformed,
hiding the real defect inside it. ROOT FIX: read text config files as
`utf-8-sig` so a leading BOM is stripped transparently before parsing.
"""
import json

import pytest

from hooklint.cli import main
from hooklint.engine import scan


def _write(tmp_path, rel, content, mode="w", encoding="utf-8"):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if "b" in mode:
        p.write_bytes(content)
    else:
        p.write_text(content, encoding=encoding)
    return p


# -- non-UTF-8 / binary config must never crash, always exit 2 --

def test_binary_settings_json_is_parse_error_not_traceback(tmp_path):
    _write(tmp_path, ".claude/settings.json", b"\x80\x81\x82garbage", mode="wb")
    result = scan(str(tmp_path))  # must not raise UnicodeDecodeError
    assert not result.findings
    assert len(result.parse_errors) == 1
    assert "decode" in result.parse_errors[0].error.lower()

    code = main([str(tmp_path)])
    assert code == 2


@pytest.mark.parametrize("rel", [
    "generic/agent-hooks.yaml",
    "generic/hooks.toml",
    ".claude/skills/foo/SKILL.md",
])
def test_binary_content_is_parse_error_across_dialects(tmp_path, rel):
    # ROOT FIX must cover every dialect's loader, not just claude_settings.
    _write(tmp_path, rel, b"\xff\xfe\x00\x01not-text", mode="wb")
    result = scan(str(tmp_path))
    assert not result.findings
    assert len(result.parse_errors) == 1


# -- deeply-nested JSON/YAML must not crash with RecursionError -

def test_deeply_nested_json_never_raises_recursionerror(tmp_path):
    """Whatever the interpreter does with a 20k-deep document, we do not crash.

    Whether that document PARSES is a property of the running interpreter's
    stack, not of hooklint: CPython on Linux decodes it fine, while the same
    input is a parse error elsewhere. So this asserts only what must hold
    everywhere -- no RecursionError escapes, and the result is well formed
    either way. Pinning "it is a parse error" made this test encode one
    platform's stack limit, and it failed on a clean Linux clone while the
    tool was behaving correctly (it parsed the document and reported a real
    unknown top-level key).
    """
    depth = 20000
    nested = ("{\"a\":" * depth) + "1" + ("}" * depth)
    _write(tmp_path, ".claude/settings.json", nested)

    result = scan(str(tmp_path))  # must not raise RecursionError

    if result.parse_errors:
        # rejected: it must say why, and the CLI must call it malformed input
        assert "nested too deeply" in result.parse_errors[0].error.lower()
        assert not result.findings
        assert main([str(tmp_path)]) == 2
    else:
        # decoded: any findings must still be well formed, and the exit code
        # must stay inside the documented contract
        for finding in result.findings:
            assert finding.rule_id and finding.json_pointer
        assert main([str(tmp_path)]) in (0, 1)


def test_deeply_nested_yaml_flow_mapping_is_parse_error(tmp_path):
    depth = 3000
    nested = ("{a: " * depth) + "1" + ("}" * depth)
    _write(tmp_path, "generic/agent-hooks.yaml", nested)

    result = scan(str(tmp_path))  # must not raise RecursionError
    assert len(result.parse_errors) == 1


# -- a UTF-8 BOM on an otherwise-valid file parses normally ----

def test_bom_prefixed_valid_settings_json_parses_and_lints(tmp_path):
    payload = json.dumps({
        "hooks": {"PreToolUse": [
            {"matcher": "Bahs", "hooks": [{"type": "command", "command": "echo checked"}]}
        ]}
    }).encode("utf-8")
    _write(tmp_path, ".claude/settings.json", b"\xef\xbb\xbf" + payload, mode="wb")

    result = scan(str(tmp_path))
    assert not result.parse_errors, "a BOM alone must not be treated as malformed input"
    assert any(f.rule_id == "dead_matcher" for f in result.findings), (
        "the real defect behind the BOM must still be found, not hidden by a parse error"
    )


@pytest.mark.parametrize("rel", [
    "generic/agent-hooks.yaml",
    "generic/hooks.toml",
])
def test_bom_prefixed_valid_config_parses_across_dialects(tmp_path, rel):
    content = ('hooks:\n  pre_tool_use:\n    - match: shall\n      run: x\n'
               if rel.endswith(".yaml") else
               '[[hook]]\nevent = "pre_tool_use"\nmatcher = "shall"\ncommand = "x"\n')
    _write(tmp_path, rel, b"\xef\xbb\xbf" + content.encode("utf-8"), mode="wb")

    result = scan(str(tmp_path))
    assert not result.parse_errors
    assert any(f.rule_id == "dead_matcher" for f in result.findings)
