"""Rule 1 -- dead_matcher (flagship): a hook matcher that cannot match any
tool name in the declared table for its dialect.

Applicable dialects: claude_settings (JSON), hooks_yaml (generic YAML),
hooks_toml (generic TOML).

Two distinct rule_ids are emitted:

* ``dead_matcher`` (severity ``error``) -- a confident dead verdict: the
  matcher matches nothing at all, including the open ``mcp__`` namespace
  (a typo like ``Bsah``, a wrong event name like ``PreToolUseX``, or a
  regex that matches nothing).
* ``unknown_matcher`` (severity ``info``) -- the matcher matches none of the
  *declared* (closed-table) tool names, but CAN reach the open ``mcp__``
  namespace (MCP-server-provided tools hooklint cannot enumerate offline).
  This is deliberately a different, machine-readable `rule_id` from
  ``dead_matcher`` so a JSON consumer filtering on ``rule_id ==
  "dead_matcher"`` never misreads an unknown verdict as a confident dead
  one -- `dead_matcher` is reserved for cases hooklint is actually sure
  about.
"""
from __future__ import annotations

import re
from typing import List

from hooklint.context import Loaded, LintContext
from hooklint.finding import Finding
from hooklint.pointer import json_pointer
from hooklint.tables import (
    CLAUDE_CODE_EVENTS,
    CLAUDE_CODE_TOOL_NAMES,
    GENERIC_HOOK_EVENTS,
    GENERIC_TOOL_NAMES,
    MCP_NAMESPACE_PREFIX,
    MCP_NAMESPACE_PROBES,
)

RULE_ID = "dead_matcher"
UNKNOWN_MATCHER_RULE_ID = "unknown_matcher"


def _matcher_is_dead(matcher, tool_names) -> "tuple[str, str]":
    """Classify a matcher against a dialect's declared tool-name table.

    Returns (status, reason) where status is one of:
      "ok"      -- matches at least one declared tool name (or is the
                   empty/None/"*" wildcard).
      "unknown" -- matches none of the declared (closed-table) tool names,
                   but CAN reach the open `mcp__` namespace (MCP-provided
                   tools hooklint cannot enumerate offline). Reported as
                   unknown, never asserted dead.
      "dead"    -- matches nothing at all, including the open namespace
                   (a typo, wrong event, or a regex matching nothing).
    """
    if matcher is None or matcher == "" or matcher == "*":
        return "ok", ""
    if not isinstance(matcher, str):
        return "dead", f"matcher is not a string: {matcher!r}"
    # Path (a) LITERAL: a matcher whose raw text starts with the `mcp__`
    # prefix reaches the open mcp namespace directly -- checked BEFORE
    # regex-compiling and BEFORE any probe-list search, so a literal like
    # `mcp__filesystem__read_file` is never dependent on that exact
    # server/tool spelling happening to be one of the probe strings tested
    # below (root cause of the original bug: testing only against a tiny
    # fixed probe set). No declared tool name starts with `mcp__`, so this
    # can never shadow a genuine "ok" classification.
    if matcher.startswith(MCP_NAMESPACE_PREFIX):
        return "unknown", (
            f"matcher {matcher!r} references the mcp__ namespace directly (MCP-server-provided "
            f"tools are not in a closed table hooklint can verify offline); unknown, not dead"
        )
    try:
        pat = re.compile(matcher)
    except re.error as e:
        return "dead", f"matcher {matcher!r} is not a valid regex: {e}"
    for name in tool_names:
        if pat.search(name):
            return "ok", ""
    # Path (b) REGEX: the matcher is not a literal `mcp__`-prefixed string,
    # but the compiled pattern may still be able to reach the namespace
    # (e.g. `mcp__.*`, `^(Bash|mcp__.*)$`) -- tested against a GENERATED
    # family of varied `mcp__<server>__<tool>` strings, not a tiny fixed
    # list (see hooklint.tables).
    for probe in MCP_NAMESPACE_PROBES:
        if pat.search(probe):
            return "unknown", (
                f"matcher {matcher!r} matches none of the declared tool names, but can reach "
                f"the mcp__ namespace (MCP-server-provided tools are not in a closed table "
                f"hooklint can verify offline); unknown, not dead"
            )
    return "dead", f"matcher {matcher!r} matches none of the declared tool names"


def _check_claude(loaded: Loaded, ctx: LintContext) -> List[Finding]:
    findings: List[Finding] = []
    data = loaded.data
    if not isinstance(data, dict):
        return findings
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return findings
    for event_name, groups in hooks.items():
        if event_name not in CLAUDE_CODE_EVENTS:
            continue  # unknown event name is unknown_key's concern
        if not isinstance(groups, list):
            continue
        for idx, group in enumerate(groups):
            if not isinstance(group, dict):
                continue
            matcher = group.get("matcher")
            status, reason = _matcher_is_dead(matcher, CLAUDE_CODE_TOOL_NAMES)
            ctx.mark(status == "unknown")
            pointer = json_pointer(["hooks", event_name, idx, "matcher"]) if matcher is not None \
                else json_pointer(["hooks", event_name, idx])
            if status == "dead":
                findings.append(Finding(
                    rule_id=RULE_ID,
                    severity="error",
                    file=loaded.cfg.rel,
                    json_pointer=pointer,
                    evidence=repr(matcher),
                    message=f"{event_name} hook #{idx}: {reason}; this hook will never fire",
                ))
            elif status == "unknown":
                findings.append(Finding(
                    rule_id=UNKNOWN_MATCHER_RULE_ID,
                    severity="info",
                    file=loaded.cfg.rel,
                    json_pointer=pointer,
                    evidence=repr(matcher),
                    message=f"{event_name} hook #{idx}: {reason}",
                ))
    return findings


def _check_generic_hooks_dict(loaded: Loaded, ctx: LintContext, hooks) -> List[Finding]:
    """Shared extractor for the generic `hooks: {<event>: [{match, run}, ...]}`
    shape -- identical whether it came from YAML (``hooks:`` mapping) or TOML
    (``[[hooks.<event>]]`` array-of-tables, which tomllib/tomli parse to the
    exact same nested dict-of-lists). Used by both dialects so a defect
    planted in either surface is found the same way, with the same
    `hooks/<event>/<idx>/match` pointer shape.
    """
    findings: List[Finding] = []
    if not isinstance(hooks, dict):
        return findings
    for event_name, entries in hooks.items():
        if event_name not in GENERIC_HOOK_EVENTS:
            continue
        if not isinstance(entries, list):
            continue
        for idx, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            matcher = entry.get("match")
            status, reason = _matcher_is_dead(matcher, GENERIC_TOOL_NAMES)
            ctx.mark(status == "unknown")
            pointer = json_pointer(["hooks", event_name, idx, "match"]) if matcher is not None \
                else json_pointer(["hooks", event_name, idx])
            if status == "dead":
                findings.append(Finding(
                    rule_id=RULE_ID,
                    severity="error",
                    file=loaded.cfg.rel,
                    json_pointer=pointer,
                    evidence=repr(matcher),
                    message=f"{event_name} hook #{idx}: {reason}; this hook will never fire",
                ))
            elif status == "unknown":
                findings.append(Finding(
                    rule_id=UNKNOWN_MATCHER_RULE_ID,
                    severity="info",
                    file=loaded.cfg.rel,
                    json_pointer=pointer,
                    evidence=repr(matcher),
                    message=f"{event_name} hook #{idx}: {reason}",
                ))
    return findings


def _check_generic_yaml(loaded: Loaded, ctx: LintContext) -> List[Finding]:
    data = loaded.data
    if not isinstance(data, dict):
        return []
    return _check_generic_hooks_dict(loaded, ctx, data.get("hooks"))


def _check_generic_toml(loaded: Loaded, ctx: LintContext) -> List[Finding]:
    findings: List[Finding] = []
    data = loaded.data
    if not isinstance(data, dict):
        return findings
    # Flat `[[hook]]` array-of-tables shape: {event, matcher, command}.
    entries = data.get("hook")
    if isinstance(entries, list):
        for idx, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            event_name = entry.get("event")
            if event_name not in GENERIC_HOOK_EVENTS:
                continue
            matcher = entry.get("matcher")
            status, reason = _matcher_is_dead(matcher, GENERIC_TOOL_NAMES)
            ctx.mark(status == "unknown")
            pointer = json_pointer(["hook", idx, "matcher"]) if matcher is not None \
                else json_pointer(["hook", idx])
            if status == "dead":
                findings.append(Finding(
                    rule_id=RULE_ID,
                    severity="error",
                    file=loaded.cfg.rel,
                    json_pointer=pointer,
                    evidence=repr(matcher),
                    message=f"hook #{idx}: {reason}; this hook will never fire",
                ))
            elif status == "unknown":
                findings.append(Finding(
                    rule_id=UNKNOWN_MATCHER_RULE_ID,
                    severity="info",
                    file=loaded.cfg.rel,
                    json_pointer=pointer,
                    evidence=repr(matcher),
                    message=f"hook #{idx}: {reason}",
                ))
    # Nested `[[hooks.<event>]]` array-of-tables shape -- TOML's idiomatic
    # equivalent of the YAML `hooks: {<event>: [...]}` mapping, and parses to
    # the identical structure, so it reuses the identical extractor.
    findings.extend(_check_generic_hooks_dict(loaded, ctx, data.get("hooks")))
    return findings


def check(loaded: Loaded, ctx: LintContext) -> List[Finding]:
    if loaded.cfg.kind == "claude_settings":
        return _check_claude(loaded, ctx)
    if loaded.cfg.kind == "hooks_yaml":
        return _check_generic_yaml(loaded, ctx)
    if loaded.cfg.kind == "hooks_toml":
        return _check_generic_toml(loaded, ctx)
    return []
