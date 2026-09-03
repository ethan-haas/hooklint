"""Regression test for a defect found in review: a LITERAL matcher in the `mcp__` open
namespace (`mcp__filesystem__read_file`, `mcp__playwright__browser_click`,
`mcp__context7__get-library-docs`, `mcp__memory__read_graph`,
`mcp__srv__tool`) was still wrongly reported `rule_id="dead_matcher"`,
`severity="error"`, while `mcp__github__create_issue` and the regex
`mcp__.*` correctly came back `unknown_matcher`/info. Both are the SAME
open, offline-unenumerable namespace -- the split was a bug, not a rule.

ROOT CAUSE: `_matcher_is_dead` only tested a matcher's compiled regex
against a small FIXED probe list (`MCP_NAMESPACE_PROBES`); a literal that
did not happen to equal one of those exact strings fell through to `dead`.

ROOT FIX: `_matcher_is_dead` now checks the raw matcher string against the
`mcp__` prefix DIRECTLY (a literal/regex-prefix check, independent of any
probe list) before ever compiling it as a regex, so classification does not
depend on which specific server/tool spelling happens to be in a fixture or
probe table. The probe-list path (used for non-`mcp__`-prefixed regexes
like `^(Bash|mcp__.*)$`) is now also a GENERATED family
(`hooklint.tables._generate_mcp_namespace_family`), not a tiny fixed list.
"""
import json

import pytest

from hooklint.engine import scan


def _write(tmp_path, rel, content):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


# The exact literal matchers named in the escape report, plus one built from
# server/tool segment names that do NOT appear anywhere in hooklint's own
# generated probe pool -- proving the fix is not "we happened to add this
# exact literal to the pool" but a genuine prefix-shape check.
@pytest.mark.parametrize("matcher", [
    "mcp__filesystem__read_file",
    "mcp__playwright__browser_click",
    "mcp__context7__get-library-docs",
    "mcp__memory__read_graph",
    "mcp__srv__tool",
    "mcp__zzq7-totally-unlisted-server__zzq7-totally-unlisted-tool",
])
def test_literal_mcp_matcher_is_unknown_not_dead(tmp_path, matcher):
    _write(tmp_path, ".claude/settings.json", json.dumps({
        "hooks": {"PreToolUse": [
            {"matcher": matcher, "hooks": [{"type": "command", "command": "echo ok"}]}
        ]}
    }))
    result = scan(str(tmp_path))
    assert not any(f.rule_id == "dead_matcher" and f.severity == "error" for f in result.findings), (
        f"literal mcp__ matcher {matcher!r} must not be reported dead_matcher -- it targets "
        f"the open mcp__ namespace hooklint cannot enumerate offline"
    )
    unknown = [f for f in result.findings if f.rule_id == "unknown_matcher"]
    assert unknown, f"literal mcp__ matcher {matcher!r} must be reported unknown_matcher"
    assert unknown[0].severity == "info"


def test_literal_and_regex_mcp_matchers_are_classified_identically(tmp_path):
    # mcp__github__create_issue (a probe-list hit even before the fix) and
    # a never-listed literal must land on the SAME rule_id/severity -- the
    # bug was exactly this inconsistency.
    for i, matcher in enumerate(("mcp__github__create_issue", "mcp__filesystem__read_file", "mcp__.*")):
        _write(tmp_path, f"proj{i}/.claude/settings.json", json.dumps({
            "hooks": {"PreToolUse": [
                {"matcher": matcher, "hooks": [{"type": "command", "command": "echo ok"}]}
            ]}
        }))
    result = scan(str(tmp_path))
    rule_severity_pairs = {(f.rule_id, f.severity) for f in result.findings}
    assert rule_severity_pairs == {("unknown_matcher", "info")}


def test_genuine_typo_still_dead_after_literal_prefix_fix(tmp_path):
    # The literal-prefix short-circuit must not swallow real typos that
    # merely happen to be strings -- only `mcp__`-prefixed ones.
    _write(tmp_path, ".claude/settings.json", json.dumps({
        "hooks": {"PreToolUse": [
            {"matcher": "Bsah", "hooks": [{"type": "command", "command": "echo ok"}]}
        ]}
    }))
    result = scan(str(tmp_path))
    dead = [f for f in result.findings if f.rule_id == "dead_matcher" and f.severity == "error"]
    assert dead
