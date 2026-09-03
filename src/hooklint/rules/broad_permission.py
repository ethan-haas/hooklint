"""Rule 7 -- broad_permission: unanchored patterns, and prefixes without a
separator (`/srv/app` also matching `/srv/appdata`).

Applicable dialects: claude_settings `permissions` (JSON), policy_yaml
(generic YAML), policy_toml (generic TOML).

## Permission-token grammar

Every permission string is classified by its STRUCTURE (never by incidental
characters like `-` or `.`), in this order:

1. **Path-style** -- starts with `/`, `./`, `~/`, `../`, or a Windows drive
   letter (`C:\\`). Handled entirely by the existing separator-less-prefix
   heuristic (`/srv/app` also matches `/srv/appdata`) and the file-vs-
   directory dot heuristic documented below and in the README -- both of
   which apply to PATHS ONLY.

2. **MCP token** -- starts with `mcp__`. Parsed structurally into
   `mcp__<server>` or `mcp__<server>__<tool>` by splitting the remainder on
   the FIRST `__` after the prefix:
   * `mcp__<server>` (no tool segment) -- broad: grants every tool the
     server exposes.
   * `mcp__<server>__<tool>`, fully specified, no wildcard -- clean: grants
     exactly one tool.
   * a wildcard (`*`) anywhere in the server or tool segment
     (`mcp__gh__*`, `mcp__*__x`) -- broad.
   `server` and `tool` may contain hyphens or dots (`mcp__git-hub__x`,
   `mcp__server.name__tool`) -- those are ORDINARY name characters and MUST
   NOT change the verdict relative to an all-underscore name. This is a
   *closed*, table-driven decision: hyphen/dot presence never suppresses or
   flips a finding.

3. **`(...)`-scopable tool** -- any other token. `Tool` with no parens at
   all has no scoping specifier and is broad, regardless of what characters
   its name contains. `Tool(scope)` with `scope` empty, `*`, or `**` is
   unanchored and broad; any other scope is delegated to the path-prefix
   check (a scope can itself look like a path, e.g. `Read(/srv/app)`).

The old implementation's tool/scope split relied on a strict
`[A-Za-z_][A-Za-z0-9_]*` identifier regex for the WHOLE non-path branch.
Two bugs fell out of that: (a) any `mcp__server__tool` token composed only
of word characters satisfied that regex as a bare "tool" with no scoping
specifier and was flagged broad even though it is fully specific, while a
wildcarded `mcp__server__*` failed the regex, fell through to the path
classifier, and came back clean -- classification was inverted for MCP
tokens; (b) any token containing a `-` or `.` (MCP or not) failed that same
regex and fell straight to the path classifier, which silently cleared the
finding for anything not path-shaped -- an undocumented lexical suppression
that had nothing to do with the permission's actual scope. See
`tests/test_broad_permission_mcp_grammar.py` for the regression coverage.
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

from hooklint.context import Loaded, LintContext
from hooklint.finding import Finding
from hooklint.pointer import json_pointer

RULE_ID = "broad_permission"

_TOOL_SCOPE_RE = re.compile(r"^(.+)\((.*)\)$", re.DOTALL)
_PATH_LIKE_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|[~/.]|\.\.[\\/])")
_MCP_PREFIX = "mcp__"


def _is_path_like(pattern: str) -> bool:
    return bool(_PATH_LIKE_RE.match(pattern))


def _split_mcp_token(rest: str) -> Tuple[str, Optional[str]]:
    """Split the text after the `mcp__` prefix into (server, tool) on the
    FIRST `__` separator. `tool` is None when no `__` is present (a
    server-only grant). Hyphens and dots inside either segment are ordinary
    name characters and never affect the split."""
    if "__" in rest:
        server, tool = rest.split("__", 1)
        return server, tool
    return rest, None


def _classify_mcp_token(pattern: str) -> Optional[str]:
    rest = pattern[len(_MCP_PREFIX):]
    server, tool = _split_mcp_token(rest)

    if not server:
        return f"{pattern!r} is an MCP grant with no server name; grants every MCP tool"

    if "*" in server or (tool is not None and "*" in tool):
        return (f"{pattern!r} contains a wildcard MCP segment: matches every tool "
                f"it expands to, not one specific tool")

    if tool is None:
        return (f"{pattern!r} has no tool segment; grants every tool exposed by the "
                f"{server!r} MCP server")

    return None  # fully specified server + tool, no wildcard: specific grant


def _classify_pattern(pattern: str) -> Optional[str]:
    """Return a finding reason string, or None if the pattern is fine.

    Dispatch is purely structural (path vs mcp__ vs (...)-scopable tool),
    never based on incidental characters like `-` or `.` -- see the module
    docstring for the full grammar."""
    if pattern == "*" or pattern == "**":
        return "pattern is bare '*', unanchored: matches everything"

    if _is_path_like(pattern):
        return _classify_path_spec(pattern)

    if pattern.startswith(_MCP_PREFIX):
        return _classify_mcp_token(pattern)

    m = _TOOL_SCOPE_RE.match(pattern)
    if m:
        tool, spec = m.group(1), m.group(2)
        spec = spec.strip()
        if spec in ("*", "**", ""):
            return f"{tool}({spec!r}) is unanchored: matches every invocation of {tool}"
        return _classify_path_spec(spec)

    return f"{pattern!r} has no scoping specifier; grants every invocation of {pattern} unrestricted"


def _looks_like_directory_name(core: str) -> bool:
    """Heuristic: a bare final path segment with a dotted extension, or a
    dotfile (.env, .gitignore), reads as a FILE reference -- there is no
    sibling-collision hazard for those (no "/srv/appdata"-style analog for
    a single file). A final segment with no dot reads as a directory name,
    which is exactly the exportkit prefix-collision shape.

    DOCUMENTED PRECISION BOUNDARY: file-vs-directory is undecidable
    offline (hooklint never touches the filesystem being described, only
    the config text). A directory whose name happens to contain a `.`
    (`/etc/nginx.d`, `/srv/data.backup`) is therefore read as a file and
    NOT flagged for the prefix-collision hazard, even though it is really
    a directory -- a real, if less common, escape from this heuristic.
    This is a deliberate precision tradeoff (favoring fewer false
    positives on the much more common `app.py`/`config.json`-style file
    grants) rather than a silent blind spot; see the README Limitations
    section for the same note."""
    last = core.rstrip("/\\").replace("\\", "/").rsplit("/", 1)[-1]
    if last.startswith(".") and last.count(".") == 1:
        return False  # dotfile, e.g. .env
    if "." in last:
        return False  # has an extension, e.g. app.py / config.json
    return True


def _classify_path_spec(spec: str) -> Optional[str]:
    # Strip a trailing ":*" arg-wildcard suffix some clients use, e.g.
    # "git diff:*" -- that suffix scopes the *arguments*, not the path, so
    # it does not by itself make the path prefix issue below moot.
    core = spec
    if core.endswith(":*"):
        core = core[:-2]

    if "*" in core:
        return None  # explicit glob wildcard is an anchored, declared shape

    if (_PATH_LIKE_RE.match(core) and not core.endswith(("/", "\\"))
            and _looks_like_directory_name(core)):
        sibling = core.rstrip("/\\") + "data"
        return (f"{core!r} is a directory-shaped prefix with no trailing separator and no "
                f"glob; a naive prefix match also matches {sibling!r}")
    return None


def _scan_permission_list(findings: List[Finding], ctx: LintContext, rel: str,
                           patterns, base_path: list) -> None:
    if not isinstance(patterns, list):
        return
    for idx, pattern in enumerate(patterns):
        if not isinstance(pattern, str):
            continue
        reason = _classify_pattern(pattern)
        ctx.mark(False)
        if reason is not None:
            findings.append(Finding(
                RULE_ID, "warning", rel, json_pointer(base_path + [idx]),
                pattern, f"broader than it reads: {reason}",
            ))


def _scan_perm_dict(findings: List[Finding], ctx: LintContext, rel: str,
                     perms: dict, base_path: list) -> None:
    if not isinstance(perms, dict):
        return
    for key in ("allow", "deny", "ask"):
        _scan_permission_list(findings, ctx, rel, perms.get(key), base_path + [key])
    add_dirs = perms.get("additionalDirectories")
    if isinstance(add_dirs, list):
        for idx, d in enumerate(add_dirs):
            if not isinstance(d, str):
                continue
            ctx.mark(False)
            if d in ("/", "\\") or (len(d) == 3 and d[1] == ":" and d[2] in "\\/"):
                findings.append(Finding(
                    RULE_ID, "warning", rel, json_pointer(base_path + ["additionalDirectories", idx]),
                    d, "additionalDirectories entry is a filesystem root: grants access to the entire drive",
                ))
            elif not d.endswith(("/", "\\")):
                sibling = d.rstrip("/\\") + "data"
                findings.append(Finding(
                    RULE_ID, "warning", rel, json_pointer(base_path + ["additionalDirectories", idx]),
                    d, f"additionalDirectories entry {d!r} has no trailing separator; a naive prefix "
                       f"match also matches {sibling!r}",
                ))


def check(loaded: Loaded, ctx: LintContext) -> List[Finding]:
    findings: List[Finding] = []
    data = loaded.data
    if not isinstance(data, dict):
        return findings

    if loaded.cfg.kind == "claude_settings":
        perms = data.get("permissions")
        if isinstance(perms, dict):
            _scan_perm_dict(findings, ctx, loaded.cfg.rel, perms, ["permissions"])
    elif loaded.cfg.kind in ("policy_yaml", "policy_toml"):
        # generic dialect: the file's root IS the permissions dict
        _scan_perm_dict(findings, ctx, loaded.cfg.rel, data, [])

    return findings
