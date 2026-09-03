"""Regression test for a defect found in review: `SKILL.md` discovery required a `.claude/`
ancestor. `hooklint ./SKILL.md` (bare, passed directly, no directory
context at all) and a plugin-layout `skills/<name>/SKILL.md` (a real Claude
plugin skill location -- no `.claude/` ancestor) both silently scanned 0
files and exited 0 clean, while the control `.claude/skills/foo/SKILL.md`
worked.

ROOT FIX:
* Directory-walk classification (`discovery.classify`) now recognizes
  `SKILL.md` under ANY `skills/<name>/` layout, `.claude` ancestor or not
  (a Claude plugin skill genuinely has no `.claude/` ancestor).
* Single-file mode (`discovery.discover` when the caller names the file
  directly) additionally falls back to basename-only classification when
  the file is named exactly `SKILL.md` and no directory context resolves
  it -- an explicitly-named, distinctively-named config scanning 0 and
  exiting 0 clean is the fail-unsafe direction.
* An arbitrary `README.md` (or any other filename) is unaffected by either
  change -- both rules gate on the exact basename `SKILL.md`.
"""
from hooklint.engine import scan


def _write(tmp_path, rel, content):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def test_bare_skill_md_single_file_mode_is_scanned(tmp_path):
    skill = _write(tmp_path, "SKILL.md", "body only, no frontmatter\n")
    result = scan(str(skill))
    assert result.files_scanned, "an explicitly-passed SKILL.md must not silently scan 0 files"
    assert any(f.rule_id == "unreachable_skill" for f in result.findings)


def test_plugin_layout_skill_md_no_claude_ancestor_directory_walk(tmp_path):
    _write(tmp_path, "skills/foo/SKILL.md", "body only, no frontmatter\n")
    result = scan(str(tmp_path))
    assert result.files_scanned, "a plugin-layout skills/<name>/SKILL.md must be discovered"
    assert any(f.rule_id == "unreachable_skill" for f in result.findings)


def test_plugin_layout_skill_md_single_file_mode(tmp_path):
    skill = _write(tmp_path, "skills/foo/SKILL.md", "body only, no frontmatter\n")
    result = scan(str(skill))
    assert result.files_scanned
    assert any(f.rule_id == "unreachable_skill" for f in result.findings)


def test_control_claude_skills_still_works(tmp_path):
    _write(tmp_path, ".claude/skills/foo/SKILL.md", "body only, no frontmatter\n")
    result = scan(str(tmp_path))
    assert any(f.rule_id == "unreachable_skill" for f in result.findings)


def test_random_readme_is_still_not_a_skill(tmp_path):
    _write(tmp_path, "README.md", "# hello\nnot a skill file\n")
    result = scan(str(tmp_path))
    assert result.files_scanned == [], "an unrelated README.md must not be classified as a skill"


def test_random_readme_single_file_mode_still_not_a_skill(tmp_path):
    readme = _write(tmp_path, "README.md", "# hello\nnot a skill file\n")
    result = scan(str(readme))
    assert result.files_scanned == []
