"""Rule 4 -- unknown_key: a setting the client ignores, so the config reads
as configured while doing nothing.

Applicable dialects: claude_settings (JSON), hooks_yaml (generic YAML),
hooks_toml (generic TOML), cursor_mdc (Cursor frontmatter).
"""
from __future__ import annotations

from typing import Iterable, List

from hooklint.context import Loaded, LintContext
from hooklint.finding import Finding
from hooklint.pointer import json_pointer
from hooklint.tables import (
    CLAUDE_SETTINGS_TOP_KEYS,
    CLAUDE_CODE_EVENTS,
    CLAUDE_HOOK_GROUP_KEYS,
    CLAUDE_HOOK_ENTRY_KEYS,
    CLAUDE_HOOK_ENTRY_TYPES,
    PERMISSION_TOP_KEYS,
    MCP_SERVER_KEYS,
    GENERIC_HOOK_EVENTS,
    GENERIC_HOOKS_YAML_EVENT_KEYS,
    GENERIC_HOOKS_TOML_ENTRY_KEYS,
    CURSOR_MDC_KEYS,
)

RULE_ID = "unknown_key"


def _flag_wrong_value_type(findings: List[Finding], ctx: LintContext, rel: str,
                            obj: dict, key: str, expected_types: tuple,
                            expected_label: str, base_path: list, what: str) -> None:
    """A known key whose value's TYPE cannot match its declared shape is an
    out-of-shape construct exactly like an unrecognized key -- report it,
    never default it to clean (see tables.py module docstring). SCOPED
    STRICTLY to keys this module (or a sibling rule) already treats as one
    concrete type via an `isinstance` check elsewhere -- never invented for
    a genuinely free-form value.

    `None` is deliberately excluded here: a missing/null value for these
    keys is already handled (as absent/empty) by the rule that owns that
    key's semantics (e.g. `unreachable_skill` for skill name/description),
    so flagging it again here would double-report the same defect under
    two rule_ids.
    """
    if not isinstance(obj, dict) or key not in obj:
        return
    value = obj[key]
    if value is None or isinstance(value, expected_types):
        return
    ctx.mark(True)
    findings.append(Finding(
        RULE_ID, "warning", rel, json_pointer(base_path + [key]),
        f"{value!r} (type={type(value).__name__})",
        f"{what} key {key!r} has unexpected value type "
        f"(got {type(value).__name__}, expected {expected_label})",
    ))


def _flag_extra_keys(findings: List[Finding], ctx: LintContext, rel: str,
                      obj: dict, known: Iterable[str], base_path: list, what: str) -> None:
    if not isinstance(obj, dict):
        return
    for key in obj.keys():
        ctx.mark(key not in known)
        if key not in known:
            findings.append(Finding(
                RULE_ID, "warning", rel, json_pointer(base_path + [key]),
                repr(key),
                f"unknown {what} key {key!r}; the client ignores this so the config reads as set while doing nothing",
            ))


def _check_hook_entry_type(findings: List[Finding], ctx: LintContext, rel: str,
                            entry: dict, entry_path: list) -> None:
    """A hook entry's `type` field decides whether the client will ever run
    the entry at all -- but the entry's own MATCHER can be perfectly fine
    (`Bash`) while `type` is absent (e.g. a `kind:` typo) or misspelled
    (`"scirpt"` for `"command"`). This is a KEY/VALUE-level unknown, not a
    confident "this matcher is dead" verdict, so it lives here as
    `rule_id="unknown_key"` rather than under `dead_matcher` -- the matcher
    itself was never in question.

    Pointer discipline (contract: a finding's json_pointer MUST resolve in
    the file): when `type` is entirely ABSENT, the pointer stops at the
    nearest EXISTING ancestor (the hook-entry object itself) -- pointing at
    `.../type` when that key does not exist in the document would produce a
    pointer that fails RFC 6901 resolution. When `type` IS present (just an
    unrecognized value), the pointer points directly at it since that key
    does exist and resolves fine.
    """
    has_type = "type" in entry
    etype = entry.get("type")
    if not has_type:
        ctx.mark(True)
        findings.append(Finding(
            RULE_ID, "info", rel, json_pointer(entry_path),
            "<missing 'type' key>",
            "hook entry is missing the required 'type' key; cannot determine if this hook fires",
        ))
    elif etype not in CLAUDE_HOOK_ENTRY_TYPES:
        ctx.mark(True)
        findings.append(Finding(
            RULE_ID, "info", rel, json_pointer(entry_path + ["type"]),
            repr(etype),
            f"unknown hook entry type {etype!r}; cannot determine if this hook fires",
        ))
    else:
        ctx.mark(False)


def _check_claude_settings(loaded: Loaded, ctx: LintContext) -> List[Finding]:
    findings: List[Finding] = []
    data = loaded.data
    if not isinstance(data, dict):
        return findings

    _flag_extra_keys(findings, ctx, loaded.cfg.rel, data, CLAUDE_SETTINGS_TOP_KEYS, [], "top-level")

    # Wrong-TYPE value for a known top-level key: the shape is declared
    # (hooks/permissions/mcpServers are always mappings) and every consumer
    # below already gates on `isinstance(..., dict)`, silently skipping a
    # wrong-shaped value with zero finding. Report it instead of letting it
    # pass clean -- an out-of-shape construct for a KNOWN key, same as an
    # unrecognized key (OBS-3).
    _flag_wrong_value_type(findings, ctx, loaded.cfg.rel, data, "hooks",
                            (dict,), "mapping", [], "top-level")
    _flag_wrong_value_type(findings, ctx, loaded.cfg.rel, data, "permissions",
                            (dict,), "mapping", [], "top-level")
    _flag_wrong_value_type(findings, ctx, loaded.cfg.rel, data, "mcpServers",
                            (dict,), "mapping", [], "top-level")

    hooks = data.get("hooks")
    if isinstance(hooks, dict):
        for event_name, groups in hooks.items():
            ctx.mark(event_name not in CLAUDE_CODE_EVENTS)
            if event_name not in CLAUDE_CODE_EVENTS:
                findings.append(Finding(
                    RULE_ID, "warning", loaded.cfg.rel, json_pointer(["hooks", event_name]),
                    repr(event_name),
                    f"unknown hook event {event_name!r}; every hook under it is silently ignored",
                ))
                continue
            if not isinstance(groups, list):
                continue
            for idx, group in enumerate(groups):
                if not isinstance(group, dict):
                    continue
                _flag_extra_keys(findings, ctx, loaded.cfg.rel, group, CLAUDE_HOOK_GROUP_KEYS,
                                  ["hooks", event_name, idx], "hook-group")
                entries = group.get("hooks")
                if isinstance(entries, list):
                    for eidx, entry in enumerate(entries):
                        if not isinstance(entry, dict):
                            continue
                        _flag_extra_keys(findings, ctx, loaded.cfg.rel, entry, CLAUDE_HOOK_ENTRY_KEYS,
                                          ["hooks", event_name, idx, "hooks", eidx], "hook-entry")
                        _check_hook_entry_type(findings, ctx, loaded.cfg.rel, entry,
                                                ["hooks", event_name, idx, "hooks", eidx])

    perms = data.get("permissions")
    if isinstance(perms, dict):
        _flag_extra_keys(findings, ctx, loaded.cfg.rel, perms, PERMISSION_TOP_KEYS, ["permissions"], "permissions")
        # allow/deny/ask/additionalDirectories are always lists (rule 7's
        # own scanners already gate on `isinstance(..., list)` and silently
        # skip anything else) -- a scalar like `"allow": "Bash(*)"` is a
        # common hand-edit typo for `"allow": ["Bash(*)"]` and currently
        # passes clean.
        for key in ("allow", "deny", "ask", "additionalDirectories"):
            _flag_wrong_value_type(findings, ctx, loaded.cfg.rel, perms, key,
                                    (list,), "list", ["permissions"], "permissions")

    mcp = data.get("mcpServers")
    if isinstance(mcp, dict):
        for name, server in mcp.items():
            if isinstance(server, dict):
                _flag_extra_keys(findings, ctx, loaded.cfg.rel, server, MCP_SERVER_KEYS,
                                  ["mcpServers", name], "mcp-server")
    return findings


def _check_mcp_json(loaded: Loaded, ctx: LintContext) -> List[Finding]:
    findings: List[Finding] = []
    data = loaded.data
    if not isinstance(data, dict):
        return findings
    mcp = data.get("mcpServers")
    if isinstance(mcp, dict):
        for name, server in mcp.items():
            if isinstance(server, dict):
                _flag_extra_keys(findings, ctx, loaded.cfg.rel, server, MCP_SERVER_KEYS,
                                  ["mcpServers", name], "mcp-server")
    return findings


def _check_generic_hooks_dict(findings: List[Finding], ctx: LintContext, rel: str, hooks) -> None:
    """Shared extractor for the generic `hooks: {<event>: [{match, run}, ...]}`
    shape -- identical whether it came from YAML (``hooks:`` mapping) or TOML
    (``[[hooks.<event>]]`` array-of-tables; both parse to the same nested
    dict-of-lists).
    """
    if not isinstance(hooks, dict):
        return
    for event_name, entries in hooks.items():
        ctx.mark(event_name not in GENERIC_HOOK_EVENTS)
        if event_name not in GENERIC_HOOK_EVENTS:
            findings.append(Finding(
                RULE_ID, "warning", rel, json_pointer(["hooks", event_name]),
                repr(event_name),
                f"unknown hook event {event_name!r}; every hook under it is silently ignored",
            ))
            continue
        if isinstance(entries, list):
            for idx, entry in enumerate(entries):
                if isinstance(entry, dict):
                    _flag_extra_keys(findings, ctx, rel, entry, GENERIC_HOOKS_YAML_EVENT_KEYS,
                                      ["hooks", event_name, idx], "hook-entry")


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
    # Flat `[[hook]]` array-of-tables shape: {event, matcher, command}.
    entries = data.get("hook")
    if isinstance(entries, list):
        for idx, entry in enumerate(entries):
            if isinstance(entry, dict):
                _flag_extra_keys(findings, ctx, loaded.cfg.rel, entry, GENERIC_HOOKS_TOML_ENTRY_KEYS,
                                  ["hook", idx], "hook-entry")
    # Nested `[[hooks.<event>]]` array-of-tables shape -- TOML's idiomatic
    # equivalent of the YAML `hooks: {<event>: [...]}` mapping.
    _check_generic_hooks_dict(findings, ctx, loaded.cfg.rel, data.get("hooks"))
    return findings


def _check_cursor_mdc(loaded: Loaded, ctx: LintContext) -> List[Finding]:
    findings: List[Finding] = []
    fm = loaded.data if isinstance(loaded.data, dict) else {}
    if loaded.has_frontmatter and not loaded.malformed_error:
        _flag_extra_keys(findings, ctx, loaded.cfg.rel, fm, CURSOR_MDC_KEYS, [], "cursor-rule")
    return findings


def _check_skill_md(loaded: Loaded, ctx: LintContext) -> List[Finding]:
    """`name`/`description` are declared string fields -- a present-but-
    wrong-type value (`name: [a, b]`, `name: 123`) is silently accepted as
    clean today because `unreachable_skill`'s emptiness check only fires on
    None or an empty string. `None`/absent is left to that rule (see
    `_flag_wrong_value_type`'s docstring) so this only covers the
    wrong-TYPE case, never duplicating the missing/empty finding.
    """
    findings: List[Finding] = []
    if not loaded.has_frontmatter or loaded.malformed_error:
        return findings
    fm = loaded.data if isinstance(loaded.data, dict) else {}
    for key in ("name", "description"):
        _flag_wrong_value_type(findings, ctx, loaded.cfg.rel, fm, key,
                                (str,), "string", [], "skill frontmatter")
    return findings


def check(loaded: Loaded, ctx: LintContext) -> List[Finding]:
    if loaded.cfg.kind == "claude_settings":
        return _check_claude_settings(loaded, ctx)
    if loaded.cfg.kind == "mcp_json" or loaded.cfg.kind == "mcp_toml":
        return _check_mcp_json(loaded, ctx)
    if loaded.cfg.kind == "hooks_yaml":
        return _check_hooks_yaml(loaded, ctx)
    if loaded.cfg.kind == "hooks_toml":
        return _check_hooks_toml(loaded, ctx)
    if loaded.cfg.kind == "cursor_mdc":
        return _check_cursor_mdc(loaded, ctx)
    if loaded.cfg.kind == "skill_md":
        return _check_skill_md(loaded, ctx)
    return []
