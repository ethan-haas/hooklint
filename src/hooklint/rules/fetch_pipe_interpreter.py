"""Rule 6 -- fetch_pipe_interpreter: a download command piped into a shell
(or equivalent) inside a hook. Matched over parsed argv and pipeline
structure via hooklint.shell, never over prose.

Applicable dialects: same 3 as unquoted_interpolation.

Detection is over the whole top-level pipeline, not just adjacent stages:
a fetch-binary stage followed, anywhere later in the SAME pipeline, by a
shell-interpreter stage is flagged even with intermediate stages between
them (``curl ... | tee /tmp/x | bash``) -- the intermediate stage does not
neutralize the fetch->execute path. A pipeline with a fetch but no
downstream interpreter, or an interpreter with no upstream fetch, stays
clean.

Wrapper unwrapping: a stage's argv[0] is not always the command that
actually runs -- a command WRAPPER (see ``tables.COMMAND_WRAPPERS``:
``sudo``, ``env``, ``command``, ``xargs``, ``nohup``, ``time``, ``doas``,
``stdbuf``, ``setsid``, plus ``env``'s leading ``VAR=val`` assignments)
passes execution through to a real command named later in the same argv.
Before classifying a stage as fetch or interpreter, ``_unwrap_argv`` strips
a leading run of these (and their flags) to reach the real command, so
``sudo bash`` classifies as interpreter ``bash`` and ``sudo curl`` as
fetch ``curl``. Applied on BOTH the fetch stage and the interpreter stage.
False-positive guard is unchanged: this only ever fires when a declared
fetch binary is actually present reaching a declared interpreter -- a bare
wrapper with no fetch (``sudo apt update``) or a fetch with no downstream
interpreter stays clean.

Process substitution (``bash <(curl ...)``, ``source <(curl ...)``,
``. <(curl ...)``) IS detected: when a stage's (unwrapped) argv[0] is a
shell interpreter (``bash``/``sh``/``zsh``/``dash``) or a source builtin
(``source``/``.``), each ``<(...)``/``>(...)`` argument in that stage is
re-tokenized as its own pipeline (``hooklint.shell.find_process_substitutions``,
paren-depth matched the same way ``$(...)`` is) and checked for a declared
fetch binary anywhere in it, same false-positive guard: a process
substitution with no fetch binary in it (``diff <(sort a) <(sort b)``)
stays clean.

``interpreter -c '<script>'`` (or PowerShell's ``-Command``) is also
detected: when a pipeline stage's argv is a shell interpreter invoked with
that flag, the outer shell has ALREADY stripped the quotes around the
script argument before hooklint ever sees the parsed argv -- so a
fetch-to-execute pattern hidden behind single quotes (which would render a
*top-level* ``$(...)`` inert) is not actually neutralized: the interpreter
named by argv[0] re-parses the script argument as its OWN shell input,
where it is unquoted again. The script argument is therefore re-tokenized
and re-scanned exactly like a fresh command string (recursively, so nested
``interpreter -c '...'`` is also handled), checking for the same two
patterns as the top-level command: a fetch piped into an interpreter, or a
fetch binary as the argv[0] of a command substitution whose *output* the
re-parsing interpreter would evaluate as code. False-positive guard: this
only fires when a declared FETCH binary actually appears in the re-parsed
argument -- ``bash -c '<no fetch>'`` stays clean.
"""
from __future__ import annotations

import re
from typing import List

from hooklint.context import Loaded, LintContext
from hooklint.finding import Finding
from hooklint.pointer import json_pointer
from hooklint.shell import (
    split_pipeline, tokenize_argv, basename_lower, find_expansions,
    find_process_substitutions,
)
from hooklint.tables import (
    CLAUDE_CODE_EVENTS, GENERIC_HOOK_EVENTS, FETCH_BINARIES, SHELL_INTERPRETERS,
    COMMAND_WRAPPERS,
)

RULE_ID = "fetch_pipe_interpreter"

# Interpreters/builtins whose argument can be a `<(...)`/`>(...)` process
# substitution that they read and execute as shell -- deliberately narrower
# than SHELL_INTERPRETERS (which also includes python/node/etc: those
# don't treat a bare positional argument as "re-parse this as MY shell
# input" the way bash/sh/zsh/dash/source/`.` do for process substitution).
_PROCSUB_INTERPRETERS = frozenset({"bash", "sh", "zsh", "dash", "source", "."})

_ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _unwrap_argv(argv: List[str]) -> List[str]:
    """Strip a leading run of declared command WRAPPERS (``sudo``, ``env``,
    ``command``, ``xargs``, ``nohup``, ``time``, ``doas``, ``stdbuf``,
    ``setsid``) -- including their flags and, for ``env``, leading
    ``VAR=val`` assignments -- to reach the argv of the REAL command a
    pipeline stage will actually run. Chained wrappers (``sudo env FOO=bar
    bash``) are unwrapped in one pass since the loop re-checks the new
    head after each strip. Flag-stripping is a declared approximation (any
    leading ``-``-prefixed token after a wrapper is treated as a no-value
    flag of that wrapper); it is enough to reach the real command for the
    fetch/interpreter classification below, not a full per-wrapper flag
    grammar. Returns ``argv`` unchanged if it does not start with a
    declared wrapper, or ``[]`` if nothing remains after unwrapping."""
    argv = list(argv)
    while argv:
        head = basename_lower(argv[0])
        if head not in COMMAND_WRAPPERS:
            break
        argv = argv[1:]
        while argv and argv[0].startswith("-") and argv[0] != "--":
            argv = argv[1:]
        if argv and argv[0] == "--":
            argv = argv[1:]
        while argv and _ENV_ASSIGNMENT_RE.match(argv[0]):
            argv = argv[1:]
    return argv


def _real_bin(stage: str) -> "str | None":
    """The basename of the REAL command a pipeline stage runs, after
    wrapper-unwrapping (or None for an empty/unparseable stage)."""
    argv = _unwrap_argv(tokenize_argv(stage))
    return basename_lower(argv[0]) if argv else None

# Interpreters whose `-c` (or PowerShell's `-Command`) argument is itself
# re-parsed as a NEW shell script by that interpreter -- as opposed to
# python/perl/ruby/node, whose `-c`/equivalent argument is a different
# language entirely, so shell-substitution syntax embedded in it (e.g.
# `$(curl ...)`) is not re-executed as shell by them and flagging it there
# would be a false positive.
_SHELL_C_INTERPRETERS = frozenset({
    "sh", "bash", "zsh", "dash", "ksh", "ash",
    "pwsh", "pwsh.exe", "powershell", "powershell.exe",
})
_C_FLAG_TOKENS = frozenset({"-c", "-command"})


def _pipe_has_fetch_to_interpreter(script: str) -> bool:
    """True iff `script`'s top-level `|` pipeline has a fetch-binary stage
    followed later by a shell-interpreter stage (the same pattern the main
    pipeline scan below detects, factored out so it can also be applied to
    a re-tokenized `interpreter -c` argument)."""
    stages = split_pipeline(script)
    if len(stages) < 2:
        return False
    bins = [_real_bin(stage) for stage in stages]
    fetch_seen = False
    for b in bins:
        if not fetch_seen:
            if b in FETCH_BINARIES:
                fetch_seen = True
            continue
        if b in SHELL_INTERPRETERS:
            return True
        if b in FETCH_BINARIES:
            fetch_seen = True
    return False


def _fetch_binary_in_substitution(script: str) -> bool:
    """True iff `script` contains a `$(...)` or `` `...` `` command
    substitution whose own first token (argv[0] basename) is a declared
    FETCH binary -- i.e. the substitution's OUTPUT (the fetched content)
    would be evaluated as code by whatever re-parses `script` as shell
    (used for `interpreter -c '<script>'`, where a real command
    substitution runs regardless of the quote style the OUTER shell saw,
    since those quotes were already stripped before the inner interpreter
    ever reads the argument)."""
    for exp in find_expansions(script):
        if exp.kind == "cmdsub":
            inner = exp.text[2:-1] if exp.text.endswith(")") else exp.text[2:]
        elif exp.kind == "backtick":
            inner = exp.text[1:-1] if exp.text.endswith("`") else exp.text[1:]
        else:
            continue
        argv = _unwrap_argv(tokenize_argv(inner))
        if argv and basename_lower(argv[0]) in FETCH_BINARIES:
            return True
    return False


def _script_has_fetch(script: str) -> bool:
    """True iff any top-level pipeline stage of `script` invokes a
    declared FETCH binary (after wrapper-unwrapping) -- used to check the
    body of a `<(...)`/`>(...)` process substitution, where the fetched
    bytes are exactly what the substitution stream evaluates to (a bare
    fetch, or a fetch feeding a downstream processing stage, both count --
    the substitution's SINK is the interpreter/source reading it, already
    established by the caller)."""
    for stage in split_pipeline(script):
        b = _real_bin(stage)
        if b in FETCH_BINARIES:
            return True
    return False


def _procsub_reaches_fetch(stage: str) -> bool:
    """True iff `stage`'s (unwrapped) argv[0] is a shell interpreter or
    source builtin that reads a `<(...)`/`>(...)` argument, and that
    argument's content fetches (declared FETCH binary present)."""
    if _real_bin(stage) not in _PROCSUB_INTERPRETERS:
        return False
    for inner in find_process_substitutions(stage):
        if _script_has_fetch(inner):
            return True
    return False


def _fetch_reaches_interpreter(script: str, _depth: int = 0) -> bool:
    """True iff `script` (a full shell command/script string) contains a
    fetch-binary pattern that will execute as code: a top-level fetch->
    interpreter pipe, a fetch binary inside a command substitution, or
    (recursively) either of those hidden behind a NESTED
    `interpreter -c '<script>'` stage."""
    stages = split_pipeline(script)
    if (_pipe_has_fetch_to_interpreter(script) or _fetch_binary_in_substitution(script)
            or any(_procsub_reaches_fetch(stage) for stage in stages)):
        return True
    if _depth >= 5:  # bounded recursion -- deterministic, no unbounded work
        return False
    for stage in stages:
        for nested_script in _interpreter_dash_c_scripts(stage):
            if _fetch_reaches_interpreter(nested_script, _depth + 1):
                return True
    return False


def _interpreter_dash_c_scripts(stage: str) -> "List[str]":
    """If `stage`'s (unwrapped) argv is a shell interpreter invoked with
    `-c`/`-Command`, return the script argument(s) that interpreter will
    itself re-parse as shell."""
    argv = _unwrap_argv(tokenize_argv(stage))
    if not argv or basename_lower(argv[0]) not in _SHELL_C_INTERPRETERS:
        return []
    scripts = []
    for i, tok in enumerate(argv[1:], start=1):
        if tok.lower() in _C_FLAG_TOKENS and i + 1 < len(argv):
            scripts.append(argv[i + 1])
    return scripts


def _check_command_string(findings: List[Finding], ctx: LintContext, rel: str,
                           command: str, pointer_path: list) -> None:
    if not isinstance(command, str) or not command.strip():
        return
    stages = split_pipeline(command)
    ctx.mark(False)
    if len(stages) >= 2:
        # REAL argv[0] basename for every stage (after wrapper-unwrapping),
        # computed once.
        bins = [_real_bin(stage) for stage in stages]

        # A fetch stage followed, anywhere later in the SAME pipeline, by a
        # shell-interpreter stage is flagged -- not only directly-adjacent
        # fetch|interpreter pairs. Once a fetch->interpreter pair is
        # reported, resume scanning for a NEW fetch stage after the
        # interpreter stage (rather than after the fetch stage) so a
        # distinct, later fetch->interpreter chain in the same pipeline is
        # still found, while the same fetch stage is not re-reported
        # against every later interpreter stage.
        fetch_idx = None
        for i, sink_bin in enumerate(bins):
            if fetch_idx is None:
                if sink_bin in FETCH_BINARIES:
                    fetch_idx = i
                continue
            if sink_bin in SHELL_INTERPRETERS:
                fetch_bin = bins[fetch_idx]
                findings.append(Finding(
                    RULE_ID, "error", rel, json_pointer(pointer_path),
                    f"{stages[fetch_idx]!r} | ... | {stages[i]!r}" if i > fetch_idx + 1
                    else f"{stages[fetch_idx]!r} | {stages[i]!r}",
                    f"{fetch_bin} piped into interpreter {sink_bin} "
                    f"({i - fetch_idx} pipeline stage(s) downstream): downloaded content "
                    f"executes with no review step",
                ))
                fetch_idx = None
            elif sink_bin in FETCH_BINARIES:
                fetch_idx = i

    # `interpreter -c '<script>'`: the script argument is re-parsed as shell
    # by that interpreter regardless of the quote style the outer shell saw
    # (those quotes are already stripped from argv by the time hooklint --
    # or the real interpreter -- sees them), so a fetch pattern hidden
    # inside single quotes is not actually neutralized. Checked
    # independently of the top-level pipe scan above (a single-stage
    # command with no top-level `|` at all can still hide this).
    for stage in stages:
        for script in _interpreter_dash_c_scripts(stage):
            if _fetch_reaches_interpreter(script):
                findings.append(Finding(
                    RULE_ID, "error", rel, json_pointer(pointer_path),
                    repr(script),
                    f"interpreter argv {stage!r} re-parses its -c/-Command argument as shell, "
                    f"and that argument itself fetches and executes content: downloaded content "
                    f"executes with no review step, regardless of the quote style used to pass it",
                ))
                break

    # Process substitution: `bash <(curl ...)`, `source <(curl ...)`,
    # `. <(curl ...)` -- the interpreter/source builtin reads the
    # substitution stream as its own script, so a fetch anywhere inside it
    # executes exactly like a piped fetch would. Checked per top-level
    # stage (after wrapper-unwrapping) so `sudo bash <(curl ...)` is also
    # caught. False-positive guard: a process substitution with no
    # declared fetch binary inside it (`diff <(sort a) <(sort b)`) stays
    # clean -- `_procsub_reaches_fetch` requires both a shell-interpreter/
    # source sink AND a fetch binary actually present in the substitution.
    for stage in stages:
        if _procsub_reaches_fetch(stage):
            findings.append(Finding(
                RULE_ID, "error", rel, json_pointer(pointer_path),
                repr(stage),
                f"interpreter/source argv {stage!r} reads a <(...)/>(...) process substitution "
                f"whose content invokes a declared fetch binary: downloaded content executes "
                f"with no review step",
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
                _check_command_string(findings, ctx, loaded.cfg.rel, entry.get("command"),
                                       ["hooks", event_name, idx, "hooks", eidx, "command"])
    return findings


def _check_generic_hooks_dict(findings: List[Finding], ctx: LintContext, rel: str, hooks) -> None:
    """Shared extractor for the generic `hooks: {<event>: [{run: ...}, ...]}`
    shape -- identical whether it came from YAML (``hooks:`` mapping) or TOML
    (``[[hooks.<event>]]`` array-of-tables; both parse to the same nested
    dict-of-lists).
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
