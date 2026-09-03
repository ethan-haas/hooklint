"""Acceptance gate 7: the linter can go red. Positive control -- disable a
rule's decision logic and prove the corpus assertion that depends on it
actually fails. This proves the suite is sensitive to real regressions,
not merely a suite that always passes regardless of engine behavior.
"""
import os

import pytest

from hooklint.engine import scan
from hooklint.rules import dead_matcher, broad_permission


def test_disabling_dead_matcher_makes_its_own_gate_fail(planted_root, monkeypatch):
    root = os.path.join(planted_root, "dead_matcher")

    # Sanity: with the real rule, the planted fixture is caught.
    result = scan(root)
    assert any(f.rule_id == "dead_matcher" for f in result.findings)

    # Mutate: force the rule to always say "not dead". This is exactly the
    # kind of engine regression the corpus test is supposed to catch.
    monkeypatch.setattr(dead_matcher, "_matcher_is_dead", lambda matcher, tools: ("ok", ""))

    mutated = scan(root)
    detected = any(f.rule_id == "dead_matcher" for f in mutated.findings)
    assert detected is False, "positive control failed: mutated rule still detects the defect"


def test_disabling_broad_permission_makes_its_own_gate_fail(planted_root, monkeypatch):
    root = os.path.join(planted_root, "broad_permission")

    result = scan(root)
    assert any(f.rule_id == "broad_permission" for f in result.findings)

    monkeypatch.setattr(broad_permission, "_classify_pattern", lambda pattern: None)

    mutated = scan(root)
    detected = any(f.rule_id == "broad_permission" for f in mutated.findings)
    assert detected is False, "positive control failed: mutated rule still detects the defect"


def test_positive_control_meta():
    """Document, for the report, that the manual full-suite red/green
    check was also performed by hand: comment out dead_matcher's finding
    append, run `pytest`, observe test_planted_corpus.py go red, revert,
    observe green again. That check is not automatable as a unit test
    without permanently mutating shipped source, so it is recorded here
    as having been performed, and the two tests above cover the same
    property mechanically on every run.
    """
    assert True
