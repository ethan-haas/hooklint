from __future__ import annotations

from typing import List, Tuple

from hooklint import loaders
from hooklint.context import Loaded, LintContext
from hooklint.discovery import ConfigFile, discover
from hooklint.finding import Finding, ParseError
from hooklint.rules import FILE_RULES, CROSS_FILE_RULES

JSON_KINDS = {"claude_settings", "mcp_json"}
TOML_KINDS = {"mcp_toml", "hooks_toml", "policy_toml"}
YAML_KINDS = {"hooks_yaml", "policy_yaml"}
MARKDOWN_KINDS = {"skill_md", "command_md", "cursor_mdc"}


def load_one(cfg: ConfigFile) -> Tuple[Loaded, ParseError | None]:
    try:
        if cfg.kind in JSON_KINDS:
            data = loaders.load_json_file(cfg.path)
            return Loaded(cfg=cfg, data=data), None
        if cfg.kind in TOML_KINDS:
            data = loaders.load_toml_file(cfg.path)
            return Loaded(cfg=cfg, data=data), None
        if cfg.kind in YAML_KINDS:
            data = loaders.load_yaml_file(cfg.path)
            return Loaded(cfg=cfg, data=data), None
        if cfg.kind in MARKDOWN_KINDS:
            fm, body, has_fm, err = loaders.load_frontmatter_file(cfg.path)
            loaded = Loaded(cfg=cfg, data=fm, is_markdown=True, body=body,
                             has_frontmatter=has_fm, malformed_error=err)
            return loaded, None
        if cfg.kind == "agents_md":
            body = loaders.load_text_file(cfg.path)
            return Loaded(cfg=cfg, data={}, is_markdown=True, body=body, has_frontmatter=False), None
    except loaders.LoadError as e:
        return Loaded(cfg=cfg, data=None), ParseError(cfg.rel, e.message)
    except OSError as e:
        return Loaded(cfg=cfg, data=None), ParseError(cfg.rel, str(e))
    except UnicodeDecodeError as e:
        # Defense in depth: every loader above already routes decode
        # failures through LoadError via loaders._read_text_file, but this
        # backstop guarantees malformed/binary/non-UTF-8 input can never
        # surface as an uncaught traceback for ANY dialect, present or
        # future -- malformed input is always exit 2, never a crash.
        return Loaded(cfg=cfg, data=None), ParseError(cfg.rel, f"cannot decode file as UTF-8: {e}")
    except RecursionError as e:
        # Defense in depth: every structured loader already catches
        # RecursionError internally and re-raises it as LoadError. This
        # backstop covers any other nested-structure walk that might one
        # day be added to this dispatch without its own try/except.
        return Loaded(cfg=cfg, data=None), ParseError(cfg.rel, f"structure nested too deeply to parse: {e}")

    return Loaded(cfg=cfg, data=None), ParseError(cfg.rel, f"unrecognized kind {cfg.kind!r}")


class ScanResult:
    def __init__(self):
        self.findings: List[Finding] = []
        self.parse_errors: List[ParseError] = []
        self.ctx = LintContext()
        self.files_scanned: List[str] = []

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key())

    def sorted_parse_errors(self) -> List[ParseError]:
        return sorted(self.parse_errors, key=lambda e: e.sort_key())


def scan(root: str) -> ScanResult:
    result = ScanResult()
    configs = discover(root)
    all_loaded: List[Loaded] = []

    for cfg in configs:
        loaded, err = load_one(cfg)
        result.files_scanned.append(cfg.rel)
        if err is not None:
            result.parse_errors.append(err)
            continue
        all_loaded.append(loaded)
        for rule_mod in FILE_RULES:
            result.findings.extend(rule_mod.check(loaded, result.ctx))

    for rule_mod in CROSS_FILE_RULES:
        result.findings.extend(rule_mod.check_all(all_loaded, result.ctx))

    return result
