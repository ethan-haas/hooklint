"""Rule 2 -- unreachable_skill: frontmatter missing/empty name|description,
or malformed YAML, so the skill/command/rule can never be selected.

Applicable dialects: skill_md (Claude Code), command_md (Claude Code),
cursor_mdc (Cursor).
"""
from __future__ import annotations

from typing import List

from hooklint.context import Loaded, LintContext
from hooklint.finding import Finding
from hooklint.pointer import json_pointer

RULE_ID = "unreachable_skill"


def _empty(v) -> bool:
    return v is None or (isinstance(v, str) and v.strip() == "")


def _check_skill_md(loaded: Loaded, ctx: LintContext) -> List[Finding]:
    findings: List[Finding] = []
    fm = loaded.data if isinstance(loaded.data, dict) else {}
    ctx.mark(False)
    if not loaded.has_frontmatter:
        findings.append(Finding(RULE_ID, "error", loaded.cfg.rel, "", "no frontmatter block",
                                 "SKILL.md has no YAML frontmatter block; the skill can never be discovered"))
        return findings
    if loaded.malformed_error:
        findings.append(Finding(RULE_ID, "error", loaded.cfg.rel, "", loaded.malformed_error,
                                 f"SKILL.md frontmatter is malformed ({loaded.malformed_error}); the skill can never be discovered"))
        return findings
    if _empty(fm.get("name")):
        findings.append(Finding(RULE_ID, "error", loaded.cfg.rel, "",
                                 f"name={fm.get('name')!r}",
                                 "SKILL.md frontmatter is missing or has an empty 'name'; the skill can never be selected"))
    if _empty(fm.get("description")):
        findings.append(Finding(RULE_ID, "error", loaded.cfg.rel, "",
                                 f"description={fm.get('description')!r}",
                                 "SKILL.md frontmatter is missing or has an empty 'description'; the skill can never be selected"))
    return findings


def _check_command_md(loaded: Loaded, ctx: LintContext) -> List[Finding]:
    findings: List[Finding] = []
    ctx.mark(False)
    if loaded.has_frontmatter and loaded.malformed_error:
        findings.append(Finding(RULE_ID, "error", loaded.cfg.rel, "", loaded.malformed_error,
                                 f"command frontmatter is malformed ({loaded.malformed_error}); this command file will fail to load"))
    return findings


def _check_cursor_mdc(loaded: Loaded, ctx: LintContext) -> List[Finding]:
    findings: List[Finding] = []
    fm = loaded.data if isinstance(loaded.data, dict) else {}
    ctx.mark(False)
    if not loaded.has_frontmatter:
        findings.append(Finding(RULE_ID, "error", loaded.cfg.rel, "", "no frontmatter block",
                                 "Cursor rule has no frontmatter block; it can never be activated"))
        return findings
    if loaded.malformed_error:
        findings.append(Finding(RULE_ID, "error", loaded.cfg.rel, "", loaded.malformed_error,
                                 f"Cursor rule frontmatter is malformed ({loaded.malformed_error}); it can never be activated"))
        return findings
    always_apply = fm.get("alwaysApply") is True
    globs = fm.get("globs")
    has_globs = bool(globs) if not isinstance(globs, str) else bool(globs.strip())
    has_description = not _empty(fm.get("description"))
    if not (always_apply or has_globs or has_description):
        findings.append(Finding(
            RULE_ID, "error", loaded.cfg.rel, "",
            f"alwaysApply={fm.get('alwaysApply')!r} globs={globs!r} description={fm.get('description')!r}",
            "Cursor rule has alwaysApply=false, no globs and no description; it has no path to ever being activated",
        ))
    return findings


def check(loaded: Loaded, ctx: LintContext) -> List[Finding]:
    if loaded.cfg.kind == "skill_md":
        return _check_skill_md(loaded, ctx)
    if loaded.cfg.kind == "command_md":
        return _check_command_md(loaded, ctx)
    if loaded.cfg.kind == "cursor_mdc":
        return _check_cursor_mdc(loaded, ctx)
    return []
