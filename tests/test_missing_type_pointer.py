"""Regression test for a defect found in review: a hook entry using `kind:` instead of
`type:` (so `type` is absent) produced a `dead_matcher` finding with
`json_pointer=/hooks/PreToolUse/0/hooks/0/type` -- a pointer that does NOT
resolve (the file has no `type` key at all), and `evidence` was the literal
string `"None"`. SPEC: "The pointer MUST resolve in the supplied file -- a
finding that cannot point at its own evidence is a bug, not a finding."

ROOT FIX (general, not special-cased to this one field):

* When a finding is about a MISSING key, `json_pointer` stops at the
  nearest EXISTING ancestor (here the hook-entry object itself,
  `/hooks/PreToolUse/0/hooks/0`) instead of a child key that isn't there.
* `evidence` names the missing key explicitly and is never the bare string
  `"None"` (repr(None) is exactly that string -- a smoking gun that the
  code path treated "absent" and "present but None" identically).
* The check moved from `dead_matcher` (reserved for a confident DEAD
  matcher verdict) to `unknown_key` (rule_id="unknown_key") -- the entry's
  MATCHER was never in question here, only the entry's own `type` field, so
  double-reporting it as "dead matcher" was also a classification bug, not
  just a pointer bug.

Also added: a GENERAL invariant swept across every fixture in
`tests/fixtures/` (clean + planted, not just the per-rule directories the
existing `test_planted_corpus.py::test_every_pointer_resolves` already
covers) asserting every emitted finding's pointer resolves via the
independent `hooklint.pointer.resolve_pointer` RFC-6901 resolver -- this is
the general form of "a finding that cannot point at its own evidence is a
bug", not scoped to this one escape.
"""
import json
import os

from hooklint.engine import scan
from hooklint.pointer import resolve_pointer, PointerError
from hooklint import loaders
from hooklint.discovery import discover

from tests.conftest import PLANTED_ROOT, CLEAN_ROOT


def _write(tmp_path, rel, content):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def test_missing_type_key_pointer_resolves_and_evidence_names_the_key(tmp_path):
    payload = {
        "hooks": {"PreToolUse": [
            {"matcher": "Bash", "hooks": [{"kind": "command", "command": "echo x"}]}
        ]}
    }
    _write(tmp_path, ".claude/settings.json", json.dumps(payload))

    result = scan(str(tmp_path))
    missing_type = [
        f for f in result.findings
        if "type" in f.message.lower() and "missing" in f.message.lower()
    ]
    assert missing_type, f"expected a missing-'type'-key finding; got {[f.to_dict() for f in result.findings]}"

    finding = missing_type[0]
    assert finding.evidence != "None", "evidence for a MISSING key must never be the literal string 'None'"
    assert finding.rule_id == "unknown_key", (
        "a missing/misspelled type field is a key/value-level unknown, not a confident "
        "dead-matcher verdict -- the matcher itself is fine here"
    )

    # The pointer MUST resolve against the ACTUAL file contents (via an
    # independent RFC-6901 resolver), proving it points at the nearest
    # EXISTING ancestor rather than the nonexistent `type` key.
    resolve_pointer(payload, finding.json_pointer)
    assert finding.json_pointer == "/hooks/PreToolUse/0/hooks/0"


def test_present_but_unknown_type_value_pointer_still_points_at_the_field(tmp_path):
    # Contrast case: when `type` IS present (just an unrecognized value),
    # the pointer should point directly AT it -- that key does exist and
    # resolves fine, so there is no reason to back off to the ancestor.
    payload = {
        "hooks": {"PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "scirpt", "command": "echo x"}]}
        ]}
    }
    _write(tmp_path, ".claude/settings.json", json.dumps(payload))

    result = scan(str(tmp_path))
    unknown_type = [f for f in result.findings if "unknown hook entry type" in f.message]
    assert unknown_type
    finding = unknown_type[0]
    assert finding.json_pointer == "/hooks/PreToolUse/0/hooks/0/type"
    resolve_pointer(payload, finding.json_pointer)
    assert finding.evidence == "'scirpt'"


def _load_doc(cfg):
    if cfg.kind in ("skill_md", "command_md", "cursor_mdc"):
        doc, _body, _has_fm, _err = loaders.load_frontmatter_file(cfg.path)
        return doc
    if cfg.kind in ("claude_settings", "mcp_json"):
        return loaders.load_json_file(cfg.path)
    if cfg.kind in ("mcp_toml", "hooks_toml", "policy_toml"):
        return loaders.load_toml_file(cfg.path)
    if cfg.kind in ("hooks_yaml", "policy_yaml"):
        return loaders.load_yaml_file(cfg.path)
    return None


def test_every_finding_pointer_resolves_across_the_whole_fixture_corpus():
    """General invariant (not scoped to one escape): for every fixture
    under tests/fixtures/ (clean AND planted), every emitted finding's
    json_pointer resolves in its own file via an independent RFC-6901
    resolver."""
    checked = 0
    for root in (CLEAN_ROOT, PLANTED_ROOT):
        result = scan(root)
        cfgs = {cfg.rel: cfg for cfg in discover(root)}
        for f in result.findings:
            cfg = cfgs.get(f.file)
            if cfg is None:
                continue
            doc = _load_doc(cfg)
            if doc is None:
                continue
            try:
                resolve_pointer(doc, f.json_pointer)
            except PointerError as e:
                raise AssertionError(
                    f"finding {f.to_dict()} has a pointer that does not resolve: {e}"
                )
            checked += 1
    assert checked > 0, "the corpus sweep must actually exercise some findings"
