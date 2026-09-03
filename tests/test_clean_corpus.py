"""Acceptance gate 2: two-sided, never blended. A realistic, correct config
set must produce ZERO findings. false_flag_rate is reported separately from
detection_rate, never averaged with it."""
from hooklint.engine import scan


def test_clean_corpus_zero_findings(clean_root):
    result = scan(clean_root)
    assert not result.parse_errors, f"unexpected parse errors on clean corpus: {result.parse_errors}"
    if result.findings:
        details = "\n".join(f"  {f.file} {f.json_pointer} [{f.rule_id}] {f.message}" for f in result.findings)
        raise AssertionError(f"clean corpus produced {len(result.findings)} false-positive finding(s):\n{details}")


def test_clean_corpus_false_flag_rate_is_zero(clean_root):
    result = scan(clean_root)
    false_flags = len(result.findings)
    checked = result.ctx.checked
    false_flag_rate = (false_flags / checked) if checked else 0.0
    assert false_flag_rate == 0.0
    # Sanity: the clean corpus must actually exercise a meaningful number of
    # check points, or a 0.0 rate would be a vacuous pass.
    assert checked >= 20, f"clean corpus only exercised {checked} check points; too small to be meaningful"


def test_clean_corpus_scans_at_least_8_files(clean_root):
    result = scan(clean_root)
    assert len(result.files_scanned) >= 8
