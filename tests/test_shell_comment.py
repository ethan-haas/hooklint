"""Regression test for a defect found in review: rule 5 (unquoted_interpolation) flagged
an expansion inside a shell COMMENT (`echo hi # $FOO`), which a real shell
never expands -- everything after an unquoted `#` that begins a word
(start of command, or preceded by whitespace/an unquoted metacharacter) is
literal text to end-of-line.

ROOT FIX: `hooklint.shell._scan_word` now recognizes that comment
introducer and skips to end-of-line without scanning for expansions,
while a `#` mid-word (`foo#bar`), inside quotes, or consumed as part of
`${#VAR}` is unaffected -- and a heredoc BODY line starting with `#` is
still data, not a shell comment.
"""
import json

import pytest

from hooklint.engine import scan
from hooklint.shell import find_expansions


def _write(tmp_path, rel, content):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


@pytest.mark.parametrize("command", [
    "echo hi # $FOO",
    "echo hi #$FOO",
    "npm run build # deploy $STAGING",
])
def test_dollar_after_comment_hash_is_not_flagged(tmp_path, command):
    _write(tmp_path, ".claude/settings.json", json.dumps({
        "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": command}]}]}
    }))
    result = scan(str(tmp_path))
    assert not any(f.rule_id == "unquoted_interpolation" for f in result.findings)


def test_hash_mid_word_is_still_scanned_for_expansion():
    # 'foo#bar$SECRET' -- '#' is not preceded by whitespace/start/an
    # unquoted metacharacter, so it is NOT a comment introducer; the
    # expansion right after it must still be flagged (no regression of
    # ordinary scanning).
    unsafe = [e for e in find_expansions("echo foo#bar$SECRET") if not e.safe]
    assert len(unsafe) == 1
    assert unsafe[0].text == "$SECRET"


def test_hash_var_length_expansion_unaffected_by_comment_fix():
    # '${#VAR}' -- the '#' is inside a parameter expansion, not a comment.
    unsafe = [e for e in find_expansions("echo ${#VAR}") if not e.safe]
    assert len(unsafe) == 1


def test_hash_inside_single_quotes_is_still_literal_and_unaffected():
    unsafe = [e for e in find_expansions("echo '# $FOO'") if not e.safe]
    assert unsafe == []


def test_heredoc_body_hash_is_data_not_a_comment():
    # A '#'-led line inside an UNQUOTED heredoc body is not a shell
    # comment -- it is literal data, and any '$VAR' on that line is still
    # expanded exactly as it was before this fix.
    cmd = "cat <<EOF\n# $SECRET is expanded here\nEOF\n"
    unsafe = [e for e in find_expansions(cmd) if not e.safe]
    assert len(unsafe) == 1
    assert unsafe[0].text == "$SECRET"


def test_comment_after_semicolon_no_space_is_still_recognized():
    unsafe = [e for e in find_expansions("cmd1;#comment $FOO") if not e.safe]
    assert unsafe == []
