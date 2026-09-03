"""Regression test for E-r4-2: a hook command with `$(...)` command
substitution nested deeply (`echo $($($(...)))`) raised an uncaught
``RecursionError`` inside ``hooklint.shell._scan_word`` -- the shell
scanner recursed once per nesting level with no bound, so hostile pasted
content past CPython's default recursion limit (1000) crashed the process:
exit 1, EMPTY stdout (breaks `--json` consumers), traceback on stderr.
Only `$(...)` command substitution lacked a depth guard -- `$((...))`
arithmetic and `${...}` parameter expansion were already safe (neither one
recurses on nested `(`/`{`).

ROOT FIX: `hooklint.shell._scan_word` takes an explicit `depth` parameter,
threaded through every recursive call it makes into a substitution's inner
text (command substitution, backtick, and arithmetic-expansion bodies).
Past `_MAX_EXPANSION_DEPTH` (120, well under CPython's default recursion
limit even with the rest of the call stack) the scanner stops descending
into further nesting -- but the OUTER expansion at that level has already
been recorded (each `findings.append(...)` call runs BEFORE its
corresponding recursive call), so the pathologically-deep unquoted
`$(...)` is still reported via the existing unquoted_interpolation
(rule 5) verdict; `find_expansions` never raises and never returns
findings for a well-formed but merely deep input. This holds regardless of
the local interpreter's actual configured stack size, since the bound is
an explicit counter, not a change to `sys.setrecursionlimit` (which would
just move the cliff, not remove it) -- verified below with a nesting depth
(1200) that overflows CPython's DEFAULT recursion limit (1000).
"""
import json
import subprocess
import sys

from hooklint.engine import scan
from hooklint.shell import find_expansions


def _write(tmp_path, rel, content):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def _deeply_nested_cmdsub(depth: int) -> str:
    return "echo " + ("$(" * depth) + "true" + (")" * depth)


def test_find_expansions_does_not_raise_past_default_recursion_limit():
    # 1200 > sys.getrecursionlimit()'s default of 1000 -- if _scan_word
    # were still recursing one Python call per nesting level unbounded,
    # this alone would raise RecursionError before hooklint's own bound is
    # ever consulted.
    cmd = _deeply_nested_cmdsub(1200)
    expansions = find_expansions(cmd)  # must not raise
    assert expansions, "the outermost $(...) must still be recorded as an expansion"


def test_scan_in_process_does_not_raise_and_still_finds_the_outer_expansion(tmp_path):
    cmd = _deeply_nested_cmdsub(1200)
    _write(tmp_path, ".claude/settings.json", json.dumps({
        "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": cmd}]}]}
    }))
    result = scan(str(tmp_path))  # must not raise RecursionError
    assert not result.parse_errors
    assert any(f.rule_id == "unquoted_interpolation" for f in result.findings), (
        "a deeply-nested unquoted $(...) is still an unquoted expansion -- "
        "the existing rule-5 verdict must still fire"
    )


def test_cli_subprocess_survives_hostile_depth_valid_json_sensible_exit(tmp_path):
    # Full end-to-end check via a fresh subprocess (own interpreter/own
    # stack, not reusing whatever recursion headroom the current pytest
    # process happens to have already consumed) -- the exact failure mode
    # described in E-r4-2: exit 1 + traceback on stderr + EMPTY stdout.
    cmd = _deeply_nested_cmdsub(1200)
    _write(tmp_path, ".claude/settings.json", json.dumps({
        "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": cmd}]}]}
    }))
    proc = subprocess.run(
        [sys.executable, "-m", "hooklint", "--json", str(tmp_path)],
        capture_output=True, text=True,
    )
    assert "Traceback" not in proc.stderr, f"must never traceback on hostile input: {proc.stderr}"
    assert proc.stdout.strip(), "stdout must not be empty -- --json consumers must get valid JSON"
    payload = json.loads(proc.stdout)  # must parse as valid JSON
    assert any(f["rule_id"] == "unquoted_interpolation" for f in payload["findings"])
    assert proc.returncode in (0, 1, 2), f"exit code must be sensible, got {proc.returncode}"
    assert proc.returncode == 1  # findings present, no parse error


def test_moderate_nesting_still_fully_scanned_no_behavior_change():
    # Nesting well under the depth bound must still walk every level (no
    # observable change for realistic, non-hostile input).
    cmd = _deeply_nested_cmdsub(5)
    expansions = find_expansions(cmd)
    cmdsub_expansions = [e for e in expansions if e.kind == "cmdsub"]
    assert len(cmdsub_expansions) == 5
