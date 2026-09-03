"""Rule 3 -- shadowed_definition: two skills/commands/mcp-servers share a
name; one silently wins. Report which, and why.

Cross-file rule: operates over every Loaded file in one scan, not a single
file. Precedence is a declared, deterministic approximation (see
hooklint.tables.DIALECT_RANK) -- documented as informative, not a claim
about any specific client's exact override semantics.

CROSS-CLIENT NAMESPACE NOTE (documented limitation, not a bug -- see
README "Limitations"): hooklint scans the whole tree as ONE declared
namespace with a single precedence order. So an MCP server (or skill/
command) with the SAME name defined once under a Claude Code path
(`.claude/settings.json`) and once under a Cursor path (`.cursor/mcp.json`)
is reported `shadowed_definition` even though the two clients are
genuinely separate runtimes that never actually collide with each other in
practice -- each client only ever loads its OWN config file, so nothing is
really "shadowed" from either client's point of view. Read a
`shadowed_definition` finding that spans a `claude_code` and a `cursor`
entry as "these two clients each declare a server under the same name" (a
naming-collision heads-up worth deduplicating for clarity), not as "one of
these is dead code" the way a same-dialect collision would be.
"""
from __future__ import annotations

from typing import Dict, List, Tuple

from hooklint.context import Loaded, LintContext
from hooklint.finding import Finding
from hooklint.pointer import json_pointer
from hooklint.tables import DIALECT_RANK

RULE_ID = "shadowed_definition"


def _precedence_key(loaded: Loaded):
    return (DIALECT_RANK.get(loaded.cfg.dialect, 99), loaded.cfg.rel)


def _pick_winner(candidates: List[Loaded]) -> Tuple[Loaded, List[Loaded]]:
    ordered = sorted(candidates, key=_precedence_key)
    winner = ordered[0]
    losers = ordered[1:]
    return winner, losers


def _why(winner: Loaded) -> str:
    return (f"declared precedence: dialect '{winner.cfg.dialect}' ranks first "
            f"(rank order claude_code > cursor > generic), tie-broken by path; "
            f"'{winner.cfg.rel}' wins")


def _check_skill_names(all_loaded: List[Loaded], ctx: LintContext) -> List[Finding]:
    findings: List[Finding] = []
    groups: Dict[str, List[Loaded]] = {}
    for loaded in all_loaded:
        if loaded.cfg.kind != "skill_md":
            continue
        fm = loaded.data if isinstance(loaded.data, dict) else {}
        name = fm.get("name")
        if isinstance(name, str) and name.strip():
            groups.setdefault(name, []).append(loaded)

    for name, group in groups.items():
        ctx.mark(False)
        if len(group) < 2:
            continue
        winner, losers = _pick_winner(group)
        for loser in losers:
            findings.append(Finding(
                RULE_ID, "warning", loser.cfg.rel, json_pointer(["name"]),
                repr(name),
                f"skill name {name!r} is also declared in {winner.cfg.rel!r}; {_why(winner)}, "
                f"this definition is shadowed",
            ))
    return findings


def _command_stem(rel: str) -> str:
    base = rel.rsplit("/", 1)[-1]
    if base.endswith(".md"):
        base = base[:-3]
    return base.lower()


def _check_command_names(all_loaded: List[Loaded], ctx: LintContext) -> List[Finding]:
    findings: List[Finding] = []
    groups: Dict[str, List[Loaded]] = {}
    for loaded in all_loaded:
        if loaded.cfg.kind != "command_md":
            continue
        stem = _command_stem(loaded.cfg.rel)
        groups.setdefault(stem, []).append(loaded)

    for stem, group in groups.items():
        ctx.mark(False)
        if len(group) < 2:
            continue
        winner, losers = _pick_winner(group)
        for loser in losers:
            findings.append(Finding(
                RULE_ID, "warning", loser.cfg.rel, "",
                repr(stem),
                f"command name {stem!r} (from filename) is also declared in {winner.cfg.rel!r}; "
                f"{_why(winner)}, this definition is shadowed",
            ))
    return findings


def _check_mcp_server_names(all_loaded: List[Loaded], ctx: LintContext) -> List[Finding]:
    findings: List[Finding] = []
    groups: Dict[str, List[Tuple[Loaded, str]]] = {}
    for loaded in all_loaded:
        if loaded.cfg.kind not in ("claude_settings", "mcp_json", "mcp_toml"):
            continue
        data = loaded.data if isinstance(loaded.data, dict) else {}
        mcp = data.get("mcpServers")
        if not isinstance(mcp, dict):
            continue
        for name in mcp.keys():
            groups.setdefault(name, []).append((loaded, name))

    for name, entries in groups.items():
        ctx.mark(False)
        if len(entries) < 2:
            continue
        # dedupe by file (a name can't collide with itself)
        by_file: Dict[str, Loaded] = {}
        for loaded, _ in entries:
            by_file[loaded.cfg.rel] = loaded
        if len(by_file) < 2:
            continue
        winner, losers = _pick_winner(list(by_file.values()))
        for loser in losers:
            findings.append(Finding(
                RULE_ID, "warning", loser.cfg.rel, json_pointer(["mcpServers", name]),
                repr(name),
                f"mcp server name {name!r} is also declared in {winner.cfg.rel!r}; {_why(winner)}, "
                f"this definition is shadowed",
            ))
    return findings


def check_all(all_loaded: List[Loaded], ctx: LintContext) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(_check_skill_names(all_loaded, ctx))
    findings.extend(_check_command_names(all_loaded, ctx))
    findings.extend(_check_mcp_server_names(all_loaded, ctx))
    return findings
