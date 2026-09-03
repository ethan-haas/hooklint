"""A real, char-level POSIX-ish shell scanner.

Two things live here:

1. ``find_expansions`` -- tracks quote state (none/single/double) across a
   command string and returns every ``$VAR`` / ``${VAR}`` / ``$(...)`` /
   `` `...` `` expansion, each tagged ``safe=True`` iff it occurs while
   inside single quotes. Handles nested command substitution, backslash
   escaping (including a literal ``\\$``), and heredocs (quoted delimiter
   body is never scanned -- it is literal; unquoted delimiter body is
   scanned as if unquoted).

2. ``split_pipeline`` / ``tokenize_argv`` -- split a command string into
   ``|``-separated pipeline stages at the top level only (never inside
   quotes or ``$(...)``), then tokenize each stage into argv-like words on
   unquoted whitespace, for rule 6 (fetch-piped-to-interpreter) to inspect
   parsed argv/pipeline structure instead of prose.

This is NOT a full POSIX shell grammar (no full arithmetic expansion, no
brace expansion, no full glob semantics) -- it implements exactly the
constructs the SPEC's quoting-edge-case gate names, deterministically, with
no regex-over-meaning shortcuts.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

NONE, SINGLE, DOUBLE = "none", "single", "double"

# Hard, explicit bound on how many levels of nested command/arithmetic
# substitution (`$(...)`, `` `...` ``, `$((...))`) the scanner will recurse
# into. `_scan_word` recurses once per nesting level to scan each
# substitution's *inner* text for further expansions -- hostile pasted
# input (`echo $($($(...)))` nested thousands deep) can otherwise exceed
# CPython's own default recursion limit (1000) and crash with an uncaught
# ``RecursionError``, regardless of how much real stack the host machine
# has (raising `sys.setrecursionlimit` would just move the cliff, not
# remove it). Once this bound is hit, the scanner stops descending into
# further nesting but the OUTER expansion at that level has already been
# recorded (see the `findings.append(...)` calls below, each of which runs
# before its corresponding recursive call) -- so a pathologically deep
# unquoted `$(...)` is still reported via the existing unquoted-expansion
# rule, it just is not walked past this depth for additional inner
# findings. This is a deliberate, documented precision boundary, not a
# silent truncation: `find_expansions` never raises or returns nothing for
# such input.
_MAX_EXPANSION_DEPTH = 120

_HEREDOC_RE = re.compile(
    r"<<-?\s*(?:'([A-Za-z_][A-Za-z0-9_]*)'|\"([A-Za-z_][A-Za-z0-9_]*)\"|([A-Za-z_][A-Za-z0-9_]*))"
)


@dataclass(frozen=True)
class Expansion:
    start: int
    end: int
    text: str
    safe: bool  # True = inside single quotes (not flagged)
    kind: str  # "var" | "param" | "cmdsub" | "backtick" | "special"


def _mask_span(s: str, start: int, end: int) -> str:
    return s[:start] + (" " * (end - start)) + s[end:]


def _extract_heredocs(s: str) -> Tuple[str, List[Tuple[int, int, bool]]]:
    """Return (masked_command, [(body_start, body_end, quoted), ...]).

    masked_command has every heredoc body replaced with spaces (same length,
    offsets preserved) so the main scanner does not re-walk heredoc bodies
    as ordinary command text. Callers scan each unquoted body separately.
    """
    bodies: List[Tuple[int, int, bool]] = []
    masked = s
    search_from = 0
    while True:
        m = _HEREDOC_RE.search(masked, search_from)
        if not m:
            break
        delim = m.group(1) or m.group(2) or m.group(3)
        quoted = m.group(1) is not None or m.group(2) is not None
        nl = masked.find("\n", m.end())
        if nl == -1:
            search_from = m.end()
            continue
        body_start = nl + 1
        # find a line consisting solely of the delimiter (optionally
        # tab-indented for the `<<-` variant)
        term_re = re.compile(r"(?m)^[ \t]*" + re.escape(delim) + r"[ \t]*$")
        tm = term_re.search(masked, body_start)
        body_end = tm.start() if tm else len(masked)
        bodies.append((body_start, body_end, quoted))
        masked = _mask_span(masked, body_start, body_end)
        search_from = body_end
    return masked, bodies


# Characters that, when found immediately before an unquoted `#`, mean the
# `#` begins a fresh word position (so it introduces a comment) rather than
# continuing the previous word: whitespace, or a top-level unquoted shell
# operator that separates commands/words. Deliberately conservative -- it
# does NOT include `(` / `)`, since those also close constructs (like
# `$(...)`) that leave a `#` stuck mid-word (`$(cmd)#not_a_comment`), where
# a real shell does not start a comment either.
_COMMENT_INTRODUCERS = " \t\n;&|"


def _scan_word(s: str, start_state: str = NONE, base_offset: int = 0,
                scan_comments: bool = True, depth: int = 0) -> List[Expansion]:
    findings: List[Expansion] = []
    state = start_state
    i = 0
    n = len(s)
    while i < n:
        c = s[i]

        if c == "#" and state == NONE and scan_comments:
            prev = s[i - 1] if i > 0 else None
            if prev is None or prev in _COMMENT_INTRODUCERS:
                # Unquoted `#` at the start of a word begins a shell
                # comment: everything to end-of-line is literal text, never
                # scanned for expansions (a `#` inside a word, e.g.
                # `foo#bar`, or inside quotes, or consumed as part of
                # `${#VAR}` before this branch is ever reached, is NOT a
                # comment and is unaffected by this branch).
                nl = s.find("\n", i)
                end = nl if nl != -1 else n
                i = end
                continue

        if c == "'":
            if state == SINGLE:
                state = NONE
            elif state == NONE:
                state = SINGLE
            # else: state == DOUBLE -> a literal quote char, no toggle
            i += 1
            continue

        if c == "\\" and state != SINGLE:
            # backslash is NOT an escape character inside single quotes at
            # all (a real shell treats '\' as a literal char there)
            if state == DOUBLE:
                # inside double quotes backslash only escapes $ ` " \ and newline
                if i + 1 < n and s[i + 1] in ("$", "`", '"', "\\", "\n"):
                    i += 2
                    continue
                i += 1
                continue
            else:
                # unquoted: backslash escapes the next char literally,
                # including a literal `\$` -> not an expansion
                i += 2
                continue

        if c == '"' and state != SINGLE:
            state = DOUBLE if state == NONE else NONE
            i += 1
            continue

        if state == SINGLE:
            # Inside single quotes NOTHING is special except a literal `'`
            # (handled above), which real shells will never expand. We
            # still record `$`/backtick sightings here -- marked safe, with
            # a short, non-consuming span -- purely so callers/tests can
            # audit that hooklint *saw* the construct rather than skipped
            # scanning silently. Crucially this must NOT attempt matching-
            # paren/backtick lookahead: a stray quote char inside such a
            # lookahead could desync the real close-quote position.
            if c == "`":
                findings.append(Expansion(base_offset + i, base_offset + i + 1, c, True, "backtick"))
                i += 1
                continue
            if c == "$":
                end = min(i + 2, n)
                findings.append(Expansion(base_offset + i, base_offset + end, s[i:end], True, "var"))
                i += 1
                continue
            i += 1
            continue

        if c == "`":
            j = i + 1
            while j < n:
                if s[j] == "\\":
                    j += 2
                    continue
                if s[j] == "`":
                    break
                j += 1
            end = min(j + 1, n)
            findings.append(Expansion(base_offset + i, base_offset + end, s[i:end], False, "backtick"))
            inner = s[i + 1:j] if j < n else s[i + 1:n]
            if depth < _MAX_EXPANSION_DEPTH:
                findings.extend(_scan_word(inner, NONE, base_offset + i + 1, depth=depth + 1))
            i = end
            continue

        if c == "$":
            if i + 2 < n and s[i + 1] == "(" and s[i + 2] == "(":
                # Arithmetic expansion `$((expr))` -- distinct from command
                # substitution `$(cmd)`. A pure arithmetic expression
                # carries no agent-controlled command by itself and is NOT
                # flagged as an expansion at all. But its body can still
                # embed a REAL command substitution or variable
                # (`$(( $(curl ...) ))`, `$(($AGENT_CONTROLLED))`) -- so the
                # body is recursively scanned with the ordinary scanner
                # (fresh, unquoted state, matching how `$(...)` bodies are
                # already recursed into) and any real construct inside is
                # still found and flagged per the normal rules.
                pdepth = 2
                j = i + 3
                while j < n and pdepth > 0:
                    if s[j] == "\\":
                        j += 2
                        continue
                    if s[j] == "(":
                        pdepth += 1
                    elif s[j] == ")":
                        pdepth -= 1
                    j += 1
                end = j
                inner = s[i + 3:end]
                if depth < _MAX_EXPANSION_DEPTH:
                    findings.extend(_scan_word(inner, NONE, base_offset + i + 3, depth=depth + 1))
                i = end
                continue
            if i + 1 < n and s[i + 1] == "(":
                pdepth = 1
                j = i + 2
                while j < n and pdepth > 0:
                    if s[j] == "\\":
                        j += 2
                        continue
                    if s[j] == "(":
                        pdepth += 1
                    elif s[j] == ")":
                        pdepth -= 1
                        if pdepth == 0:
                            break
                    j += 1
                end = min(j + 1, n)
                safe = state == SINGLE
                findings.append(Expansion(base_offset + i, base_offset + end, s[i:end], safe, "cmdsub"))
                inner = s[i + 2:j] if j < n else s[i + 2:n]
                if depth < _MAX_EXPANSION_DEPTH:
                    findings.extend(_scan_word(inner, NONE, base_offset + i + 2, depth=depth + 1))
                i = end
                continue
            if i + 1 < n and s[i + 1] == "{":
                close = s.find("}", i + 2)
                end = (close + 1) if close != -1 else n
                safe = state == SINGLE
                findings.append(Expansion(base_offset + i, base_offset + end, s[i:end], safe, "param"))
                i = end
                continue
            if i + 1 < n and (s[i + 1].isalpha() or s[i + 1] == "_"):
                j = i + 1
                while j < n and (s[j].isalnum() or s[j] == "_"):
                    j += 1
                safe = state == SINGLE
                findings.append(Expansion(base_offset + i, base_offset + j, s[i:j], safe, "var"))
                i = j
                continue
            if i + 1 < n and s[i + 1] in "@*#?$!0123456789":
                end = i + 2
                safe = state == SINGLE
                findings.append(Expansion(base_offset + i, base_offset + end, s[i:end], safe, "special"))
                i = end
                continue
            i += 1
            continue

        i += 1

    return findings


def find_expansions(command: str) -> List[Expansion]:
    """Scan a full shell command/script string, honoring heredocs."""
    masked, bodies = _extract_heredocs(command)
    findings = _scan_word(masked, NONE, 0)
    for body_start, body_end, quoted in bodies:
        if quoted:
            continue  # quoted-delimiter heredoc body is entirely literal
        body = command[body_start:body_end]
        # A heredoc body is data, not shell command syntax -- a line
        # starting with `#` inside it is literal text, never a comment.
        findings.extend(_scan_word(body, NONE, body_start, scan_comments=False))
    findings.sort(key=lambda e: (e.start, e.end))
    return findings


# -- pipeline / argv parsing (rule 6) ------------------------------------

def split_pipeline(command: str) -> List[str]:
    """Split on top-level unquoted `|` (not `||`), respecting quote state
    and not descending into $(...) / backticks."""
    masked, _bodies = _extract_heredocs(command)
    segments: List[str] = []
    state = NONE
    depth = 0
    start = 0
    i = 0
    n = len(masked)
    while i < n:
        c = masked[i]
        if state == SINGLE:
            if c == "'":
                state = NONE
            i += 1
            continue
        if c == "\\":
            i += 2
            continue
        if c == "'" and state == NONE:
            state = SINGLE
            i += 1
            continue
        if c == '"' and state != SINGLE:
            state = DOUBLE if state == NONE else NONE
            i += 1
            continue
        if state == NONE and c == "$" and i + 1 < n and masked[i + 1] == "(":
            depth += 1
            i += 2
            continue
        if state == NONE and c in "<>" and i + 1 < n and masked[i + 1] == "(":
            # Process substitution `<(...)` / `>(...)` -- opens the same
            # paren-depth counter as `$(...)` so a `|` inside it (e.g.
            # `bash <(curl x | tee y)`) is not misread as a top-level
            # pipeline split.
            depth += 1
            i += 2
            continue
        if state == NONE and depth > 0 and c == "(":
            depth += 1
            i += 1
            continue
        if state == NONE and depth > 0 and c == ")":
            depth -= 1
            i += 1
            continue
        if state == NONE and depth == 0 and c == "|":
            if i + 1 < n and masked[i + 1] == "|":
                i += 2
                continue
            segments.append(command[start:i])
            i += 1
            start = i
            continue
        i += 1
    segments.append(command[start:n])
    return [seg.strip() for seg in segments]


def find_process_substitutions(command: str) -> List[str]:
    """Return the inner script text of every top-level `<(...)` / `>(...)`
    process substitution in `command` (quote-aware; paren-depth matched the
    same way `$(...)` is matched in `_scan_word` -- backslash-escaped
    parens don't close early). Each returned string is the exact
    substitution body, ready for the caller to re-tokenize/re-scan as its
    own command/pipeline (used by rule 6 to check whether a process
    substitution's content fetches and executes)."""
    masked, _bodies = _extract_heredocs(command)
    results: List[str] = []
    state = NONE
    i = 0
    n = len(masked)
    while i < n:
        c = masked[i]
        if state == SINGLE:
            if c == "'":
                state = NONE
            i += 1
            continue
        if c == "\\":
            i += 2
            continue
        if c == "'" and state == NONE:
            state = SINGLE
            i += 1
            continue
        if c == '"' and state != SINGLE:
            state = DOUBLE if state == NONE else NONE
            i += 1
            continue
        if state == NONE and c in "<>" and i + 1 < n and masked[i + 1] == "(":
            depth = 1
            j = i + 2
            while j < n and depth > 0:
                if masked[j] == "\\":
                    j += 2
                    continue
                if masked[j] == "(":
                    depth += 1
                elif masked[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            inner_end = j
            results.append(command[i + 2:inner_end])
            i = (inner_end + 1) if inner_end < n else inner_end
            continue
        i += 1
    return results


def tokenize_argv(segment: str) -> List[str]:
    """Tokenize one pipeline stage into argv-like words on unquoted
    whitespace. Quote characters are stripped from the token; this is a
    lint-time approximation, not a real exec-argv builder."""
    tokens: List[str] = []
    state = NONE
    cur: List[str] = []
    i = 0
    n = len(segment)

    def flush():
        if cur:
            tokens.append("".join(cur))
            cur.clear()

    while i < n:
        c = segment[i]
        if state == SINGLE:
            if c == "'":
                state = NONE
            else:
                cur.append(c)
            i += 1
            continue
        if c == "\\" and state != SINGLE:
            if i + 1 < n:
                cur.append(segment[i + 1])
                i += 2
            else:
                i += 1
            continue
        if c == "'" and state == NONE:
            state = SINGLE
            i += 1
            continue
        if c == '"' and state != SINGLE:
            state = DOUBLE if state == NONE else NONE
            i += 1
            continue
        if state == NONE and c.isspace():
            flush()
            i += 1
            continue
        cur.append(c)
        i += 1
    flush()
    return tokens


def basename_lower(tok: str) -> str:
    tok = tok.strip().strip('"').strip("'")
    for sep in ("/", "\\"):
        if sep in tok:
            tok = tok.rsplit(sep, 1)[-1]
    return tok.lower()
