# hooklint

You pasted a hook out of a 53,000-star awesome-list into a tool that executes shell on your
machine. Two failure modes look identical in the config file: a hook whose matcher can never
fire, and a hook that splices tool-output or fetched content into a shell command unquoted.
`hooklint` finds both, and six more, anchored to a JSON Pointer into the offending file. It
parses; it never executes a hook.

```
$ hooklint .claude/settings.json
ERROR  .claude/settings.json  /hooks/PreToolUse/0/matcher  [dead_matcher]
       PreToolUse hook #0: matcher 'Bahs' matches none of the declared tool names; this hook will never fire
       evidence: 'Bahs'

hooklint: scanned 1 file(s), 1 finding(s), 0 parse error(s), unknown_rate=0.0000 (0/9)
```

That's a typo (`Bahs` for `Bash`) that JSON-validates fine and silently does nothing, forever.
Here's the other failure mode, from a generic YAML hook manifest:

```
$ hooklint agent-hooks.yaml
ERROR  agent-hooks.yaml  /hooks/pre_tool_use/0/run  [unquoted_interpolation]
       unquoted/double-quoted shell expansion '$USER_MESSAGE'; if the expanded value is tool output or fetched content this is command injection
       evidence: $USER_MESSAGE

hooklint: scanned 1 file(s), 1 finding(s), 0 parse error(s), unknown_rate=0.0000 (0/6)
```

That one runs. It just runs whatever `$USER_MESSAGE` happens to contain, unquoted, in a shell.

## Why this one

| what exists | stars |
|---|---|
| `hesreallyhim/awesome-claude-code` | 53.4k |
| `PatrickJS/awesome-cursorrules` | 40.7k |
| `wshobson/agents` | 39.4k |
| **any linter for these configs** | **63** |

The ecosystem produced collections, not verification.

## Install

```
pipx run hooklint /path/to/repo
```

No account, no API key, no network, no client installed. Or:

```
pip install hooklint
hooklint .                 # scan the current directory
hooklint --json .          # machine-readable
python -m hooklint .       # also works
```

## What it checks

Hook commands are parsed as **shell**, with a real character-level tokenizer that tracks quote
state -- not a regex over the text. Config files are JSON/TOML/YAML with declared schemas. Tool
names, event names and permission patterns are **closed sets**: a construct outside the
declared table is reported as `unknown`, never guessed and never defaulted to clean.

**Silent no-ops** -- the hook that does nothing:

1. `dead_matcher` -- a matcher that cannot match any tool name in the declared table (typo,
   wrong event name, a regex that matches nothing). The flagship rule.
2. `unreachable_skill` -- frontmatter missing/empty `name`/`description`, malformed YAML, or (for
   Cursor rules) no `alwaysApply`/`globs`/`description` path to ever being activated.
3. `shadowed_definition` -- two skills, commands, or MCP servers share a name; one silently
   wins. Reports which, and the declared precedence rule that decided it.
4. `unknown_key` -- a setting, event name, or hook field the client ignores, so the config reads
   as configured while doing nothing.

**Too much** -- the hook that does more than it looks like:

5. `unquoted_interpolation` -- a `$VAR` / `${VAR}` / `$(...)` / `` `...` `` expansion in a word
   that is not single-quoted. Decided purely by shell tokenization.
6. `fetch_pipe_interpreter` -- a download command piped directly into a shell interpreter,
   matched over **parsed argv and pipeline structure**, never prose. Also catches the fetch/
   interpreter hidden behind a command wrapper (`sudo curl ... | bash`, `curl ... | xargs bash`)
   and behind process substitution (`bash <(curl ...)`, `source <(curl ...)`).
7. `broad_permission` -- unanchored patterns (`Bash(*)`), and directory-shaped prefixes with no
   trailing separator (`/srv/app` also matching `/srv/appdata`). Classification is purely
   structural: **path-style** tokens (`/srv/app`, `./x`, `~/x`) use the prefix-collision check
   above; **MCP tokens** (`mcp__<server>` or `mcp__<server>__<tool>`) are broad with no tool
   segment or a `*` in either segment, and clean when fully specified -- a hyphen or dot in the
   server/tool name (`mcp__git-hub__x`, `mcp__server.name__tool`) never changes the verdict;
   **`(...)`-scopable tools** (`Bash`, `Read`, ...) are broad with no parens at all, or an empty/
   `*` scope. See `src/hooklint/rules/broad_permission.py` for the full grammar.
8. `mcp_unstartable` -- an MCP server command that isn't on `PATH`, a relative path that won't
   resolve from the client's working directory, or a declared env var that's absent.

## Rule 5, in detail: real shell parsing

A regex over "does this line contain a `$`" cannot tell these two lines apart; hooklint's
char-level scanner, tracking quote state, can:

```
echo '$SECRET'        # safe -- single quotes suppress ALL expansion
echo "$SECRET"        # flagged -- double quotes still expand
echo $SECRET          # flagged -- unquoted
echo \$SECRET         # safe -- escaped dollar is a literal, not an expansion
echo "it's $SECRET"   # flagged -- a literal ' inside double quotes has no effect
echo 'say "hi" $SECRET'   # safe -- a literal " inside single quotes has no effect
echo $(cat /etc/passwd)   # flagged -- command substitution, and its own
                          #           contents are recursively scanned
echo '$(cat /etc/passwd)' # safe -- single-quoted: not executed at all
cat <<'EOF'
$SECRET is literal here   # safe -- quoted heredoc delimiter
EOF
cat <<EOF
$SECRET is expanded here  # flagged -- unquoted heredoc delimiter
EOF
```

## Multi-dialect

Every applicable rule is exercised against at least three config surfaces: Claude Code
(`settings.json` hooks/permissions/mcpServers, `SKILL.md`/command frontmatter), Cursor
(`.mdc` rule frontmatter, `.cursor/mcp.json`), and a declared generic YAML/TOML hook and MCP
manifest shape for other AGENTS.md-compatible clients. See `tests/test_dialects.py`.

## Two-sided, never blended

```
$ hooklint tests/fixtures/clean
hooklint: scanned 14 file(s), 0 findings, unknown_rate=0.0000 (0/79)
```

`detection_rate` (planted corpus) and `false_flag_rate` (clean corpus) are reported separately
and never averaged -- a linter that flags every hook would look "80% accurate" on a blended
metric while failing every real user. `unknown_rate` is reported alongside both, for coverage
honesty: it is the fraction of decidable checks where hooklint could not classify a construct
against its declared tables and said so, instead of guessing clean.

## Exit codes

`0` clean · `1` findings · `2` malformed input or usage.

## Verdict contract

```json
{"rule_id": "dead_matcher", "severity": "error", "file": ".claude/settings.json",
 "json_pointer": "/hooks/PreToolUse/0/matcher", "evidence": "'Bahs'",
 "message": "PreToolUse hook #0: matcher 'Bahs' matches none of the declared tool names; this hook will never fire"}
```

`json_pointer` is RFC 6901 and MUST resolve inside `file`. For markdown files (`SKILL.md`,
command `.md`, Cursor `.mdc`), the pointer resolves against the parsed YAML **frontmatter**
dict, not the raw markdown text -- documented in `src/hooklint/pointer.py`.

`rule_id="dead_matcher"` (severity `error`) is reserved for a **confident** dead verdict.
A matcher that reaches none of the declared tool names but CAN reach the open `mcp__<server>__<tool>`
namespace (MCP servers register tools at runtime -- there is no closed table to check offline) is a
different, undecidable case and gets its own `rule_id="unknown_matcher"` (severity `info`), so a
consumer filtering on `rule_id == "dead_matcher"` never mistakes "hooklint doesn't know" for
"hooklint is sure this is dead" -- documented in `src/hooklint/rules/dead_matcher.py`. A matcher is
classified into the `mcp__` namespace via EITHER a literal check (the raw matcher string starts with
`mcp__`) or a regex check (the compiled pattern is tested against a generated family of
`mcp__<server>__<tool>` strings) -- not a single narrow probe list, so a literal like
`mcp__filesystem__read_file` is caught the same way a hand-written regex is.

A hook entry's `type` field is a **separate** concern from its matcher: an entry with a fine matcher
but a missing or misspelled `type` (e.g. `kind:` instead of `type:`) is reported as
`rule_id="unknown_key"` (severity `info`), never `dead_matcher` -- the matcher was never in question,
only the entry's own key/value. When `type` is entirely absent, its finding's `json_pointer` stops at
the hook-entry object itself (the nearest ancestor that actually exists in the file) rather than
pointing at a `/type` key that isn't there -- documented in `src/hooklint/rules/unknown_key.py`.

## Ship it in CI

**pre-commit** — `.pre-commit-hooks.yaml` lives at this repo's root, so consumers reference it
directly:

```yaml
repos:
  - repo: https://github.com/ethan-haas/hooklint
    rev: v0.1.0
    hooks:
      - id: hooklint
```

**GitHub Actions** — hooklint exits non-zero on findings, which is the point, so a workflow
step needs nothing special:

```yaml
- uses: actions/setup-python@v5
  with: { python-version: "3.x" }
- run: pip install hooklint
- run: hooklint .
```

One shell caveat worth stating, because it bit this repo's own CI: under `bash -e` (the
Actions default), a non-zero exit aborts the step immediately. If you want to *assert* a
non-zero exit rather than fail on it, capture it explicitly:

```yaml
- run: |
    set +e
    hooklint . ; code=$?
    set -e
    test "$code" = "1"
```

## Guardrails

Offline. No network, no API key, no model call, ever, in the linter or its tests. It never
executes a hook -- it only parses one. All fixtures are synthetic.

## Limitations

Documented, honest boundaries rather than silent blind spots:

* `broad_permission` (rule 7) decides file-vs-directory for a path prefix by whether its final
  segment contains a `.` -- undecidable offline without touching the real filesystem. A
  directory whose name happens to contain a dot (`Read(/etc/nginx.d)`, `Read(/srv/data.backup)`)
  is read as a file and is **not** flagged for the prefix-collision hazard, even though it really
  is a directory. This is a deliberate precision tradeoff favoring fewer false positives on the
  far more common `app.py`/`config.json`-style single-file grant, not an oversight.

* `shadowed_definition` (rule 3) treats the whole scanned tree as ONE namespace with a single
  declared precedence order (`hooklint.tables.DIALECT_RANK`: claude_code > cursor > generic). A
  server/skill/command with the same name declared once for Claude Code (e.g.
  `.claude/settings.json`) and once for Cursor (e.g. `.cursor/mcp.json`) is reported
  `shadowed_definition`, even though the two clients are separate runtimes that never actually
  read each other's config -- nothing is really "shadowed" from either client's own point of
  view. Read a cross-client hit as "these two clients each declare a server under the same name"
  rather than "one of these is dead code"; see the rule-3 module docstring for the full note.

* Discovery (`hooklint/discovery.py`) matches exact, case-sensitive basenames and extensions
  (`settings.json`, `SKILL.md`, `.mdc`, ...) with no filesystem case-folding and no alternate
  extensions. A config saved as `SETTINGS.JSON` or `settings.jsonc` is not recognized and is
  silently excluded from `files_scanned` -- an honest empty result (0 findings because 0 files
  were scanned), not a false "clean" verdict, but worth knowing if a project's tooling produces
  non-canonical filenames.

## Development

```
pip install -e .
pytest
```

227 tests: an 8-class planted-defect corpus (each detected with the correct `rule_id` and a
resolving pointer), a zero-finding clean corpus across 14 files / 8 config dialects, a
25-case shell-quoting test (gate 5), a 3-subprocess determinism check across differing
`PYTHONHASHSEED`, a positive control that mutates a rule and asserts the corpus test that
depends on it goes red, and regression coverage for the TOML `hooks.*` nested-table shape,
basename-only `SKILL.md`/bare `*.mdc`/bare `settings.json` single-file discovery, the
`unknown_matcher` vs `dead_matcher` rule_id split, multi-stage `fetch_pipe_interpreter`
pipelines, command-wrapper unwrapping (`sudo`/`env`/`xargs`/`command`/`nohup`/...) and
`<(...)`/`>(...)` process substitution for rule 6, a depth-bounded shell scanner that
survives a hostile, thousands-deep nested `$(...)` command substitution without crashing,
and the `broad_permission` MCP/tool-token grammar (specific `mcp__<server>__<tool>` grants
clean, wildcard/server-only grants flagged, hyphens/dots in server or tool names never
changing the verdict).
