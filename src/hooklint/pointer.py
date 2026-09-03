"""RFC 6901 JSON Pointer helpers.

hooklint anchors every finding to a JSON Pointer that MUST resolve inside the
file it names. For markdown files (SKILL.md, command .md, Cursor .mdc) the
"document" a pointer resolves into is, by declared convention, the parsed
YAML frontmatter dict extracted from that file -- not the raw markdown text.
This convention is documented in README.md and exercised by
tests/test_pointer.py.
"""
from __future__ import annotations

from typing import Any, List, Sequence, Union

_Segment = Union[str, int]


def json_pointer(path: Sequence[_Segment]) -> str:
    """Build an RFC 6901 pointer string from a sequence of keys/indices."""
    if not path:
        return ""
    parts = []
    for seg in path:
        s = str(seg)
        s = s.replace("~", "~0").replace("/", "~1")
        parts.append(s)
    return "/" + "/".join(parts)


class PointerError(Exception):
    pass


def resolve_pointer(doc: Any, pointer: str) -> Any:
    """Resolve an RFC 6901 pointer against doc. Raises PointerError if it
    does not resolve -- used by tests to assert every emitted finding's
    pointer is real, not synthetic.
    """
    if pointer == "":
        return doc
    if not pointer.startswith("/"):
        raise PointerError(f"pointer must start with '/': {pointer!r}")
    node = doc
    for raw in pointer[1:].split("/"):
        tok = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict):
            if tok not in node:
                raise PointerError(f"key {tok!r} not in dict at {pointer!r}")
            node = node[tok]
        elif isinstance(node, list):
            if not tok.lstrip("-").isdigit():
                raise PointerError(f"index {tok!r} not an int at {pointer!r}")
            idx = int(tok)
            if idx < 0 or idx >= len(node):
                raise PointerError(f"index {idx} out of range at {pointer!r}")
            node = node[idx]
        else:
            raise PointerError(f"cannot descend into {type(node)} at {pointer!r}")
    return node
