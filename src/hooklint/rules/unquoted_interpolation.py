"""Rule 5 -- unquoted_interpolation: an expansion in a word that is not
single-quoted, decided by real shell tokenization (see hooklint.shell).

Applicable dialects: claude_settings hook commands (JSON), hooks_yaml `run`
(generic YAML), hooks_toml `command` (generic TOML).
"""
from __future__ import annotations

from typing import List

from hooklint.context import Loaded, LintContext
from hooklint.finding import Finding
from hooklint.pointer import json_pointer
from hooklint.shell import find_expansions
from hooklint.tables import CLAUDE_CODE_EVENTS, GENERIC_HOOK_EVENTS

RULE_ID = "unquoted_interpolation"


def _check_command_string(findings: List[Finding], ctx: LintContext, rel: str,
                           command: str, pointer_path: list) -> None:
    if not isinstance(command, str):
        return
    expansions = find_expansions(command)
    for exp in expansions:
        ctx.mark(False)
        if not exp.safe:
            findings.append(Finding(
                RULE_ID, "error", rel, json_pointer(pointer_path),
                exp.text,
                f"unquoted/double-quoted shell expansion {exp.text!r}; if the expanded value is "
                f"tool output or fetched content this is command injection",
            ))


def _check_claude(loaded: Loaded, ctx: LintContext) -> List[Finding]:
    findings: List[Finding] = []
    data = loaded.data
    if not isinstance(data, dict):
        return findings
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return findings
    for event_name, groups in hooks.items():
        if event_name not in CLAUDE_CODE_EVENTS or not isinstance(groups, list):
            continue
        for idx, group in enumerate(groups):
            if not isinstance(group, dict):
                continue
            entries = group.get("hooks")
            if not isinstance(entries, list):
                continue
            for eidx, entry in enumerate(entries):
                if not isinstance(entry, dict):
                    continue
                command = entry.get("command")
                _check_command_string(findings, ctx, loaded.cfg.rel, command,
                                       ["hooks", event_name, idx, "hooks", eidx, "command"])
    return findings


def _check_generic_hooks_dict(findings: List[Finding], ctx: LintContext, rel: str, hooks) -> None:
    """Shared extractor for the generic `hooks: {<event>: [{run: ...}, ...]}`
    shape -- identical whether it came from YAML (``hooks:`` mapping) or TOML
    (``[[hooks.<event>]]`` array-of-tables; both parse to the same nested
    dict-of-lists), so a defect planted in either surface is found the same
    way, with the same `hooks/<event>/<idx>/run` pointer.
    """
    if not isinstance(hooks, dict):
        return
    for event_name, entries in hooks.items():
        if event_name not in GENERIC_HOOK_EVENTS or not isinstance(entries, list):
            continue
        for idx, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            _check_command_string(findings, ctx, rel, entry.get("run"),
                                   ["hooks", event_name, idx, "run"])


def _check_hooks_yaml(loaded: Loaded, ctx: LintContext) -> List[Finding]:
    findings: List[Finding] = []
    data = loaded.data
    if isinstance(data, dict):
        _check_generic_hooks_dict(findings, ctx, loaded.cfg.rel, data.get("hooks"))
    return findings


def _check_hooks_toml(loaded: Loaded, ctx: LintContext) -> List[Finding]:
    findings: List[Finding] = []
    data = loaded.data
    if not isinstance(data, dict):
        return findings
    # Flat `[[hook]]` array-of-tables shape: {event, command}.
    entries = data.get("hook")
    if isinstance(entries, list):
        for idx, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            if entry.get("event") not in GENERIC_HOOK_EVENTS:
                continue
            _check_command_string(findings, ctx, loaded.cfg.rel, entry.get("command"),
                                   ["hook", idx, "command"])
    # Nested `[[hooks.<event>]]` array-of-tables shape -- TOML's idiomatic
    # equivalent of the YAML `hooks: {<event>: [...]}` mapping.
    _check_generic_hooks_dict(findings, ctx, loaded.cfg.rel, data.get("hooks"))
    return findings


def check(loaded: Loaded, ctx: LintContext) -> List[Finding]:
    if loaded.cfg.kind == "claude_settings":
        return _check_claude(loaded, ctx)
    if loaded.cfg.kind == "hooks_yaml":
        return _check_hooks_yaml(loaded, ctx)
    if loaded.cfg.kind == "hooks_toml":
        return _check_hooks_toml(loaded, ctx)
    return []
