"""Zero-config discovery of lint-worthy files under a root directory.

Classification is by declared path/filename convention only (never by
sniffing content and guessing) -- an unrecognized filename is simply not
discovered, it is never guessed at.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", ".tox",
    ".pytest_cache", "dist", "build", ".mypy_cache", ".ruff_cache",
}


@dataclass(frozen=True)
class ConfigFile:
    path: str  # absolute or relative filesystem path, as given
    rel: str  # POSIX-style path relative to scan root, used in Finding.file
    kind: str
    dialect: str


def _posix(p: str) -> str:
    return p.replace(os.sep, "/")


def classify(rel_posix: str) -> "tuple[str, str] | None":
    parts = rel_posix.split("/")
    base = parts[-1]

    if base in ("settings.json", "settings.local.json") and ".claude" in parts:
        return "claude_settings", "claude_code"

    if base == ".mcp.json":
        if ".cursor" in parts:
            return "mcp_json", "cursor"
        return "mcp_json", "claude_code"

    if base == "mcp.json":
        if ".cursor" in parts:
            return "mcp_json", "cursor"
        return "mcp_json", "generic"

    if base == "mcp.toml":
        return "mcp_toml", "generic"

    if base in ("agent-hooks.yaml", "agent-hooks.yml"):
        return "hooks_yaml", "generic"

    if base == "agent-hooks.json":
        # Same declared generic hooks schema as agent-hooks.yaml, just
        # JSON-serialized. JSON is a valid subset of YAML, so it reuses the
        # "hooks_yaml" kind (and loader) rather than duplicating the schema
        # under a second kind.
        return "hooks_yaml", "generic"

    if base in ("hooks.toml", "agent-hooks.toml"):
        return "hooks_toml", "generic"

    if base == "policy.yaml":
        return "policy_yaml", "generic"

    if base == "policy.toml":
        return "policy_toml", "generic"

    if base == "SKILL.md" and "skills" in parts:
        # Claude Code skills live at `.claude/skills/<name>/SKILL.md`, but a
        # Claude *plugin* skill lives at `skills/<name>/SKILL.md` with no
        # `.claude/` ancestor at all -- both are real, discoverable skill
        # locations, so the `.claude` ancestor is not required here, only
        # the `skills/<name>/` layout that makes `SKILL.md` unambiguous in a
        # directory walk (an arbitrary `SKILL.md` dropped elsewhere is not
        # classified this way; see the single-file-mode basename fallback in
        # `discover()` for the case where the caller names the file directly
        # and there is no directory-walk context to consult at all).
        return "skill_md", "claude_code"

    if base.endswith(".md") and ".claude" in parts and "commands" in parts:
        return "command_md", "claude_code"

    if base.endswith(".mdc") and ".cursor" in parts and "rules" in parts:
        return "cursor_mdc", "cursor"

    if base == "AGENTS.md":
        return "agents_md", "generic"

    return None


def discover(root: str) -> List[ConfigFile]:
    if os.path.isfile(root):
        # Single-file mode: classify the SAME way directory-mode does, off
        # the full path (not just the basename) -- a config like
        # `settings.json` or `SKILL.md` is only recognizable when its
        # parent-directory context (`.claude`, `skills`, `commands`, ...)
        # is visible, and truncating to basename before classify() throws
        # that context away, silently scanning 0 files. Try the path as the
        # caller gave it first (so `hooklint .claude/settings.json` matches
        # exactly what README shows); if that alone doesn't carry enough
        # context (e.g. the caller `cd`ed into `.claude` and typed just
        # `settings.json`), retry against the resolved absolute path, whose
        # real parent directories still carry it. Classification is always
        # by declared path/filename convention only, never content.
        given_posix = _posix(os.path.normpath(root))
        kind_dialect = classify(given_posix)
        if kind_dialect is None:
            abs_posix = _posix(os.path.normpath(os.path.abspath(root)))
            kind_dialect = classify(abs_posix)
        if kind_dialect is None and os.path.basename(given_posix) == "SKILL.md":
            # Single-file mode, explicitly-named `SKILL.md` with no `skills/`
            # ancestor visible at all (e.g. `hooklint ./SKILL.md`, or a
            # caller who piped in just the one file with no surrounding
            # directory structure). classify()'s directory-walk rule
            # requires a `skills/<name>/` layout to disambiguate `SKILL.md`
            # from an arbitrary file among thousands during a full scan --
            # but here the caller EXPLICITLY named this one, distinctively-
            # named file, so there is nothing left to disambiguate against.
            # Classifying it by basename alone is the fail-unsafe direction:
            # scanning 0 and exiting clean on an explicitly-passed skill
            # manifest is exactly the silent no-op class hooklint exists to
            # catch. A generically-named file (e.g. `README.md`) is
            # unaffected -- this fallback only ever fires for the exact
            # basename `SKILL.md`.
            kind_dialect = ("skill_md", "claude_code")
        if kind_dialect is None and os.path.basename(given_posix).endswith(".mdc"):
            # Single-file mode, an explicitly-named `*.mdc` (Cursor rule)
            # file with no `.cursor/rules/` ancestor visible at all (e.g.
            # `hooklint rule.mdc`). `.mdc` is a distinctive, Cursor-specific
            # extension -- classify() ordinarily requires the directory
            # ancestor to disambiguate it from unrelated files during a
            # full-tree walk, but the caller named this one file directly,
            # so (as with the `SKILL.md` fallback above) there is nothing
            # left to disambiguate against; scanning 0 and exiting clean on
            # an explicitly-passed Cursor rule is the same silent no-op
            # class this fallback exists to close.
            kind_dialect = ("cursor_mdc", "cursor")
        if kind_dialect is None and os.path.basename(given_posix) == "settings.json":
            # Single-file mode, an explicitly-named `settings.json` with no
            # `.claude/` ancestor visible at all (e.g. a caller who `cd`ed
            # into `.claude` and typed just `settings.json`, or piped the
            # file in directly). `settings.json` is the exact, distinctive
            # basename Claude Code uses for this config -- classify() only
            # requires the `.claude` ancestor to avoid auto-scanning an
            # unrelated `settings.json` buried somewhere during a full
            # directory walk; that risk does not exist when the caller
            # named this one file directly. `settings.local.json` is
            # unaffected -- both directory-walk and single-file mode still
            # require the `.claude` ancestor for that name, matching
            # existing behavior; only the exact basename `settings.json` is
            # widened here.
            kind_dialect = ("claude_settings", "claude_code")
        if kind_dialect is None:
            return []
        kind, dialect = kind_dialect
        return [ConfigFile(os.path.abspath(root), given_posix, kind, dialect)]

    root = os.path.abspath(root)
    results: List[ConfigFile] = []

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fname in sorted(filenames):
            full = os.path.join(dirpath, fname)
            rel = os.path.relpath(full, root)
            rel_posix = _posix(rel)
            kind_dialect = classify(rel_posix)
            if kind_dialect is None:
                continue
            kind, dialect = kind_dialect
            results.append(ConfigFile(full, rel_posix, kind, dialect))

    results.sort(key=lambda c: c.rel)
    return results
