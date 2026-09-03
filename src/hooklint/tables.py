"""Closed-set declared tables.

Every set here is a hard boundary: a construct outside it is `unknown`,
reported directly, never guessed and never defaulted to clean. Update these
tables (with a version bump in CHANGELOG) as clients evolve; hooklint never
infers membership from shape or name similarity.
"""

# -- Claude Code -------------------------------------------------------

CLAUDE_CODE_EVENTS = frozenset({
    "PreToolUse",
    "PostToolUse",
    "UserPromptSubmit",
    "Notification",
    "Stop",
    "SubagentStop",
    "PreCompact",
    "SessionStart",
    "SessionEnd",
})

CLAUDE_CODE_TOOL_NAMES = frozenset({
    "Bash", "Read", "Write", "Edit", "MultiEdit", "Glob", "Grep",
    "WebFetch", "WebSearch", "Task", "TodoWrite", "NotebookEdit",
    "BashOutput", "KillShell", "SlashCommand", "AskUserQuestion",
})

CLAUDE_SETTINGS_TOP_KEYS = frozenset({
    "hooks", "permissions", "env", "model", "mcpServers",
    "includeCoAuthoredBy", "cleanupPeriodDays", "apiKeyHelper",
    "forceLoginMethod", "enableAllProjectMcpServers",
    "enabledMcpjsonServers", "disabledMcpjsonServers", "statusLine",
    "outputStyle",
})

# The `mcp__<server>__<tool>` namespace is OPEN: MCP servers register their
# tools at runtime, so there is no closed table hooklint can consult offline
# to know which `mcp__...` names exist for a given user. A matcher that can
# reach into this namespace is therefore never confidently "dead" -- per
# hooklint's own design rule, a construct outside the declared table is
# `unknown`, reported, never guessed clean *or* guessed dead.
#
# Two independent paths classify a matcher as reaching this namespace (see
# `dead_matcher._matcher_is_dead`):
#
#  (a) LITERAL -- the raw matcher string itself starts with `mcp__`. This is
#      checked directly (not via probe matching) so a literal like
#      `mcp__filesystem__read_file` is always caught regardless of whether
#      that exact server/tool spelling happens to appear in any probe list
#      below -- the earlier bug was testing a literal matcher against a tiny
#      FIXED probe set and falling through to `dead` whenever the literal
#      wasn't one of those exact strings.
#
#  (b) REGEX -- for matchers that are not simple `mcp__`-prefixed literals
#      (e.g. `mcp__.*`, `^(Bash|mcp__.*)$`), the compiled pattern is tested
#      against a GENERATED family of `mcp__<server>__<tool>` strings built
#      from a cross product of varied segment pools below (different
#      lengths, casing, digits, hyphens/underscores) -- not a tiny fixed
#      list -- to check whether the pattern CAN reach the namespace. These
#      probe strings are synthetic, varied-shape representatives of that
#      namespace (never asserted to be real installed tools).
MCP_NAMESPACE_PREFIX = "mcp__"

_MCP_SEGMENT_POOL = (
    "a", "b2", "x9y", "srv", "server", "tool", "filesystem", "playwright",
    "context7", "memory", "github", "custom-server", "custom_server",
    "Server1", "SERVER", "s", "tool-name", "tool_name", "get-library-docs",
    "read_file", "browser_click", "read_graph", "create_issue", "t1", "T",
    "abc123", "123abc", "a_b_c", "a-b-c", "probe_server", "probe_tool",
)


def _generate_mcp_namespace_family() -> "frozenset[str]":
    return frozenset(
        f"mcp__{server}__{tool}"
        for server in _MCP_SEGMENT_POOL
        for tool in _MCP_SEGMENT_POOL
    )


MCP_NAMESPACE_PROBES = _generate_mcp_namespace_family()

CLAUDE_HOOK_GROUP_KEYS = frozenset({"matcher", "hooks"})
CLAUDE_HOOK_ENTRY_KEYS = frozenset({"type", "command", "timeout"})
CLAUDE_HOOK_ENTRY_TYPES = frozenset({"command"})

PERMISSION_TOP_KEYS = frozenset({
    "allow", "deny", "ask", "additionalDirectories", "defaultMode",
})

MCP_SERVER_KEYS = frozenset({
    "command", "args", "env", "cwd", "type", "url", "headers", "timeout",
})
MCP_SERVER_TYPES = frozenset({"stdio", "http", "sse"})

SKILL_FRONTMATTER_KEYS = frozenset({
    "name", "description", "allowed-tools", "argument-hint", "model",
    "disable-model-invocation",
})

COMMAND_FRONTMATTER_KEYS = frozenset({
    "description", "argument-hint", "allowed-tools", "model",
})

CURSOR_MDC_KEYS = frozenset({"description", "globs", "alwaysApply"})

# -- Generic / other AGENTS.md-compatible clients -----------------------
# These two dialects are declared, synthetic-but-representative formats for
# clients that are not Claude Code or Cursor -- documented as such rather
# than attributed to a specific named product. They exist to prove rules 1,
# 5 and 6 generalise beyond one vendor's schema (SPEC gate 4).

GENERIC_HOOK_EVENTS = frozenset({
    "pre_tool_use", "post_tool_use", "on_start", "on_stop",
})
GENERIC_TOOL_NAMES = frozenset({
    "shell", "read_file", "write_file", "edit_file", "http_fetch", "search",
})
GENERIC_HOOKS_YAML_EVENT_KEYS = frozenset({"match", "run"})
GENERIC_HOOKS_TOML_ENTRY_KEYS = frozenset({"event", "matcher", "command"})

# -- Shell / process tables (versioned, declared) ------------------------

FETCH_BINARIES = frozenset({
    "curl", "wget", "fetch", "iwr", "invoke-webrequest",
})
SHELL_INTERPRETERS = frozenset({
    "sh", "bash", "zsh", "dash", "ksh", "ash",
    "python", "python3", "perl", "ruby", "node",
    "powershell", "powershell.exe", "pwsh", "pwsh.exe",
})

# Command WRAPPERS: argv[0] is not the command that actually runs -- it
# passes execution through to a REAL command named later in the same argv
# (`sudo bash` really runs `bash`; `sudo curl ...` really runs `curl`).
# Rule 6 (fetch_pipe_interpreter) strips a leading run of these (and their
# flags, and `env`'s leading `VAR=val` assignments) before classifying a
# pipeline stage's argv[0] as a fetch binary or a shell interpreter, on
# BOTH the fetch stage and the interpreter stage -- otherwise `curl ... |
# sudo bash` is reported completely clean because argv[0] of the sink
# stage is `sudo`, not `bash`. Closed, declared set; a wrapper not in this
# table is not unwrapped (its real command stays unclassified/unknown
# rather than guessed).
COMMAND_WRAPPERS = frozenset({
    "sudo", "env", "command", "xargs", "nohup", "time", "doas", "stdbuf", "setsid",
})

# -- Precedence (declared, structural approximation) ---------------------
# hooklint does not claim to replicate every client's exact override
# semantics. When two definitions collide it reports a winner using this
# declared, deterministic rule and says so in the message: dialect rank
# first (claude_code > cursor > generic), then path sorted ascending, last
# wins. This is informative, not an authoritative claim about any specific
# client's real load order.
DIALECT_RANK = {"claude_code": 0, "cursor": 1, "generic": 2}
