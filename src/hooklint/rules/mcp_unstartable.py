"""Rule 8 -- mcp_unstartable: command not resolvable on PATH, a relative
path that will not resolve from the client working directory, or a declared
env var absent.

Applicable dialects: claude_settings `mcpServers` + mcp_json (JSON, claude
and cursor), mcp_toml (generic TOML) -- all normalized to the same
`mcpServers` top-level key.
"""
from __future__ import annotations

import os
import re
import shutil
from typing import List

from hooklint.context import Loaded, LintContext
from hooklint.finding import Finding
from hooklint.pointer import json_pointer
from hooklint.tables import MCP_SERVER_TYPES

RULE_ID = "mcp_unstartable"

_ENV_REF_RE = re.compile(r"^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$")


def _is_relative_path_like(command: str) -> bool:
    if command.startswith(("/", "~")):
        return False
    if len(command) >= 2 and command[1] == ":" and command[0].isalpha():
        return False  # C:\... absolute
    return "/" in command or "\\" in command


def _check_server(findings: List[Finding], ctx: LintContext, rel: str,
                   name: str, server: dict, base_path: list) -> None:
    if not isinstance(server, dict):
        return

    stype = server.get("type")
    if stype is not None and stype not in MCP_SERVER_TYPES:
        ctx.mark(True)
        findings.append(Finding(
            RULE_ID, "info", rel, json_pointer(base_path + ["type"]),
            repr(stype),
            f"mcp server {name!r}: unknown type {stype!r}; cannot determine startability",
        ))
        return

    if stype in ("http", "sse"):
        ctx.mark(False)
        url = server.get("url")
        if not url:
            findings.append(Finding(
                RULE_ID, "error", rel, json_pointer(base_path),
                repr(url), f"mcp server {name!r}: type={stype} but no url declared",
            ))
        return

    has_command = "command" in server
    command = server.get("command")
    if not has_command:
        return
    ctx.mark(False)
    if command is None:
        # Present-but-null is a present, non-runnable command -- unlike a
        # genuinely ABSENT key (handled by the `has_command` guard above,
        # left untouched), this key exists in the document so the pointer
        # resolves directly to it. Kept distinct from the empty-string case
        # so the message names the actual cause instead of overloading
        # "command is empty" for a value that was never a string at all.
        findings.append(Finding(
            RULE_ID, "error", rel, json_pointer(base_path + ["command"]),
            repr(command), f"mcp server {name!r}: command is null",
        ))
    elif not isinstance(command, str):
        # Non-string, non-null (list/dict/number/bool): the message must
        # name the actual type, not claim "empty" -- evidence already shows
        # the real value (e.g. ['node', 'server.js']), so a message that
        # says "empty" directly contradicts its own evidence.
        findings.append(Finding(
            RULE_ID, "error", rel, json_pointer(base_path + ["command"]),
            repr(command),
            f"mcp server {name!r}: command is not a string "
            f"(got {type(command).__name__})",
        ))
    elif not command.strip():
        findings.append(Finding(
            RULE_ID, "error", rel, json_pointer(base_path + ["command"]),
            repr(command), f"mcp server {name!r}: command is empty",
        ))
    elif _is_relative_path_like(command):
        findings.append(Finding(
            RULE_ID, "error", rel, json_pointer(base_path + ["command"]),
            repr(command),
            f"mcp server {name!r}: command {command!r} is a relative path; it will not "
            f"reliably resolve from the client's working directory",
        ))
    elif command.startswith(("/", "~")) or (len(command) >= 2 and command[1] == ":"):
        expanded = os.path.expanduser(command)
        if not os.path.exists(expanded):
            findings.append(Finding(
                RULE_ID, "error", rel, json_pointer(base_path + ["command"]),
                repr(command), f"mcp server {name!r}: absolute path {command!r} does not exist",
            ))
    else:
        if shutil.which(command) is None:
            findings.append(Finding(
                RULE_ID, "error", rel, json_pointer(base_path + ["command"]),
                repr(command), f"mcp server {name!r}: {command!r} is not resolvable on PATH",
            ))

    env = server.get("env")
    if isinstance(env, dict):
        for key, value in env.items():
            if not isinstance(value, str):
                continue
            m = _ENV_REF_RE.match(value.strip())
            if not m:
                continue
            ctx.mark(False)
            var_name = m.group(1)
            if var_name not in os.environ:
                findings.append(Finding(
                    RULE_ID, "error", rel, json_pointer(base_path + ["env", key]),
                    repr(value),
                    f"mcp server {name!r}: env var {key!r} references ${var_name} which is "
                    f"absent from the environment",
                ))


def check(loaded: Loaded, ctx: LintContext) -> List[Finding]:
    findings: List[Finding] = []
    data = loaded.data
    if not isinstance(data, dict):
        return findings

    mcp = data.get("mcpServers")
    if not isinstance(mcp, dict):
        return findings

    for name, server in mcp.items():
        _check_server(findings, ctx, loaded.cfg.rel, name, server, ["mcpServers", name])
    return findings
