"""Regression test for a defect found in review: `echo $((1+2))` was flagged
`unquoted_interpolation` ("if the expanded value is tool output ... this is
command injection"). `$((...))` is ARITHMETIC expansion, not `$(...)`
command substitution -- a constant arithmetic expression carries no
agent-controlled command and cannot inject anything.

ROOT FIX in `hooklint.shell._scan_word`: `$((` is now recognized and
handled distinctly from `$(` BEFORE the existing command-substitution
branch is ever reached. A pure arithmetic expansion is not itself recorded
as an Expansion at all (so it is never flagged). Its body IS still
recursively scanned with the ordinary scanner (matching how `$(...)` bodies
are already recursed into), so a REAL command substitution or
agent-controlled variable embedded inside the arithmetic body
(`$(( $(curl ...) ))`, `$(($AGENT_CONTROLLED))`) is still found and flagged
exactly as it would be anywhere else -- this is not a blanket "ignore
everything inside $((...))" carve-out.
"""
import json

from hooklint.engine import scan
from hooklint.shell import find_expansions


def _write(tmp_path, rel, content):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


# -- unit level: hooklint.shell.find_expansions --------------------------

def test_plain_arithmetic_expansion_produces_no_expansion_at_all():
    assert find_expansions("echo $((1+2))") == []


def test_arithmetic_expansion_with_nested_grouping_still_clean():
    assert find_expansions("echo $(( (1+2) * 3 ))") == []


def test_double_quoted_arithmetic_expansion_still_clean():
    assert find_expansions('echo "$((1+2))"') == []


def test_arithmetic_body_with_real_command_substitution_is_still_flagged():
    findings = find_expansions("echo $(( $(cat /etc/hostname) ))")
    assert any(e.kind == "cmdsub" and not e.safe for e in findings), (
        "a REAL command substitution embedded inside an arithmetic expansion "
        "must still be found and flagged -- arithmetic is not a blanket carve-out"
    )


def test_arithmetic_body_with_agent_controlled_variable_is_still_flagged():
    findings = find_expansions("echo $(($UNTRUSTED))")
    assert any(e.kind == "var" and not e.safe and e.text == "$UNTRUSTED" for e in findings)


def test_command_substitution_itself_is_unaffected_by_the_arithmetic_fix():
    # Plain $(...) command substitution (no arithmetic involved at all)
    # must still be flagged exactly as before.
    findings = find_expansions("echo $(cat /etc/hostname)")
    assert any(e.kind == "cmdsub" and not e.safe for e in findings)


# -- rule level: unquoted_interpolation via the full engine ---------------

def test_plain_arithmetic_expansion_hook_command_is_clean(tmp_path):
    _write(tmp_path, ".claude/settings.json", json.dumps({
        "hooks": {"SessionStart": [{"hooks": [
            {"type": "command", "command": "echo $((1+2))"}
        ]}]}
    }))
    result = scan(str(tmp_path))
    assert not any(f.rule_id == "unquoted_interpolation" for f in result.findings), (
        "a pure arithmetic expansion must not be reported as command injection"
    )


def test_arithmetic_wrapped_real_substitution_hook_command_is_still_flagged(tmp_path):
    _write(tmp_path, ".claude/settings.json", json.dumps({
        "hooks": {"SessionStart": [{"hooks": [
            {"type": "command", "command": "echo $(( $(cat /etc/hostname) ))"}
        ]}]}
    }))
    result = scan(str(tmp_path))
    assert any(f.rule_id == "unquoted_interpolation" for f in result.findings), (
        "a real command substitution hidden inside an arithmetic wrapper must still be flagged"
    )
