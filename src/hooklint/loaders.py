"""JSON / TOML / YAML / markdown-frontmatter loaders.

Rules walk the returned dict/list structures directly and compute a JSON
Pointer as they go (via ``hooklint.pointer.json_pointer``); the loaders
themselves stay thin so ``resolve_pointer`` always agrees with what a rule
emitted.

Every loader here is BOM-tolerant (reads text as ``utf-8-sig``, which
strips a leading UTF-8 byte-order mark -- routine on Windows-authored
files -- and behaves exactly like plain ``utf-8`` otherwise) and turns
every way a file can fail to become data (invalid syntax, non-UTF-8/binary
bytes, or a structure nested deep enough to blow the interpreter's
recursion limit) into the same ``LoadError``, never an uncaught traceback.
"""
from __future__ import annotations

import json
import sys
from typing import Any, Dict, Optional, Tuple

import yaml

if sys.version_info >= (3, 11):
    import tomllib as _toml_reader
    _TOML_MODE = "rb"
else:  # pragma: no cover - exercised on py3.9/3.10 in CI, not locally
    import tomli as _toml_reader
    _TOML_MODE = "rb"


class LoadError(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def load_json_text(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise LoadError(f"invalid JSON: {e}") from e
    except RecursionError as e:
        raise LoadError(f"JSON is nested too deeply to parse: {e}") from e


def load_yaml_text(text: str) -> Any:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise LoadError(f"invalid YAML: {e}") from e
    except RecursionError as e:
        raise LoadError(f"YAML is nested too deeply to parse: {e}") from e
    return data


def load_toml_text(data: bytes) -> Any:
    try:
        text = data.decode("utf-8-sig")
        return _toml_reader.loads(text)
    except RecursionError as e:
        raise LoadError(f"TOML is nested too deeply to parse: {e}") from e
    except Exception as e:  # tomllib.TOMLDecodeError / tomli's equivalent / decode errors
        raise LoadError(f"invalid TOML: {e}") from e


def _read_text_file(path: str) -> str:
    """Read a config file as text.

    Uses ``utf-8-sig`` so a leading UTF-8 BOM is stripped transparently
    (an otherwise-valid file must not be reported malformed just because
    it carries one). A file that is not valid UTF-8 at all (binary, wrong
    encoding, ...) becomes a ``LoadError`` here rather than an uncaught
    ``UnicodeDecodeError`` from the caller.
    """
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            return f.read()
    except UnicodeDecodeError as e:
        raise LoadError(f"cannot decode file as UTF-8: {e}") from e


def load_json_file(path: str) -> Any:
    text = _read_text_file(path)
    return load_json_text(text)


def load_yaml_file(path: str) -> Any:
    text = _read_text_file(path)
    return load_yaml_text(text)


def load_toml_file(path: str) -> Any:
    with open(path, "rb") as f:
        data = f.read()
    return load_toml_text(data)


def load_text_file(path: str) -> str:
    """Generic BOM-tolerant text loader for dialects with no further
    structured parsing (e.g. ``AGENTS.md``, read as raw markdown body)."""
    return _read_text_file(path)


_FM_DELIM = "---"


def load_frontmatter_file(path: str) -> Tuple[Dict[str, Any], str, bool, Optional[str]]:
    """Parse a markdown file's YAML frontmatter.

    Returns (frontmatter_dict, body, has_frontmatter, error). By declared
    convention (see pointer.py), a JSON Pointer into a markdown file
    resolves against `frontmatter_dict`, not the raw text. If there is no
    frontmatter block at all, frontmatter_dict is {} and has_frontmatter is
    False (not itself an error -- callers decide if that matters for their
    rule). If the block exists but fails to parse as YAML, or does not
    parse to a mapping, frontmatter_dict is {} and error is set.
    """
    raw = _read_text_file(path)

    lines = raw.splitlines(keepends=True)
    if not lines or lines[0].strip() != _FM_DELIM:
        return {}, raw, False, None

    end_idx = None
    for i in range(1, len(lines)):
        if lines[i].strip() == _FM_DELIM:
            end_idx = i
            break
    if end_idx is None:
        return {}, raw, True, "unterminated frontmatter block (no closing '---')"

    fm_text = "".join(lines[1:end_idx])
    body = "".join(lines[end_idx + 1:])
    try:
        data = yaml.safe_load(fm_text)
    except yaml.YAMLError as e:
        return {}, body, True, f"malformed frontmatter YAML: {e}"
    except RecursionError as e:
        return {}, body, True, f"frontmatter is nested too deeply to parse: {e}"

    if data is None:
        return {}, body, True, None
    if not isinstance(data, dict):
        return {}, body, True, "frontmatter did not parse to a mapping"
    return data, body, True, None
