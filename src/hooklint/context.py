from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from hooklint.discovery import ConfigFile


@dataclass
class Loaded:
    cfg: ConfigFile
    data: Any  # dict/list for json/toml/yaml; frontmatter dict for markdown
    is_markdown: bool = False
    body: Optional[str] = None
    has_frontmatter: bool = True
    malformed_error: Optional[str] = None


@dataclass
class LintContext:
    """Shared, mutable counters used for the honesty metric `unknown_rate`.

    checked: number of decidable check points a rule actually evaluated
             (e.g. one matcher, one permission entry, one mcp server).
    unknown: subset of `checked` where the rule could not decide because the
             construct fell outside a declared table, and reported `unknown`
             instead of guessing.
    """
    checked: int = 0
    unknown: int = 0

    def mark(self, is_unknown: bool = False) -> None:
        self.checked += 1
        if is_unknown:
            self.unknown += 1
