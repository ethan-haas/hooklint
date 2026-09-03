"""Acceptance gate 1: each of the >=8 planted defect classes is detected
with the correct rule_id and a pointer that resolves in its own file."""
import os

import pytest

from hooklint.engine import scan
from hooklint.pointer import resolve_pointer, PointerError
from tests.conftest import PLANTED_RULE_IDS


@pytest.mark.parametrize("rule_id", PLANTED_RULE_IDS)
def test_planted_class_detected(planted_root, rule_id):
    root = os.path.join(planted_root, rule_id)
    result = scan(root)
    assert not result.parse_errors, f"unexpected parse errors: {result.parse_errors}"
    rule_ids_found = {f.rule_id for f in result.findings}
    assert rule_id in rule_ids_found, (
        f"planted {rule_id} fixture produced no {rule_id} finding; "
        f"got: {[f.to_dict() for f in result.findings]}"
    )


def test_detection_rate_is_8_of_8(planted_root):
    detected = 0
    for rule_id in PLANTED_RULE_IDS:
        root = os.path.join(planted_root, rule_id)
        result = scan(root)
        rule_ids_found = {f.rule_id for f in result.findings}
        if rule_id in rule_ids_found:
            detected += 1
    detection_rate = detected / len(PLANTED_RULE_IDS)
    assert detection_rate == 1.0, f"detection_rate={detection_rate}, expected 1.0 ({detected}/{len(PLANTED_RULE_IDS)})"


@pytest.mark.parametrize("rule_id", PLANTED_RULE_IDS)
def test_every_pointer_resolves(planted_root, rule_id):
    """A finding that cannot point at its own evidence is a bug, not a
    finding (SPEC verdict contract)."""
    root = os.path.join(planted_root, rule_id)
    result = scan(root)

    from hooklint import loaders
    from hooklint.discovery import discover

    for cfg in discover(root):
        finding_for_file = [f for f in result.findings if f.file == cfg.rel]
        if not finding_for_file:
            continue
        if cfg.kind in ("skill_md", "command_md", "cursor_mdc"):
            doc, _body, _has_fm, _err = loaders.load_frontmatter_file(cfg.path)
        elif cfg.kind in ("claude_settings", "mcp_json"):
            doc = loaders.load_json_file(cfg.path)
        elif cfg.kind in ("mcp_toml", "hooks_toml", "policy_toml"):
            doc = loaders.load_toml_file(cfg.path)
        elif cfg.kind in ("hooks_yaml", "policy_yaml"):
            doc = loaders.load_yaml_file(cfg.path)
        else:
            continue
        for f in finding_for_file:
            try:
                resolve_pointer(doc, f.json_pointer)
            except PointerError as e:
                pytest.fail(f"finding {f.to_dict()} has a pointer that does not resolve: {e}")
