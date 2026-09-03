from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str  # "error" | "warning" | "info"
    file: str  # POSIX-style path, relative to the scan root
    json_pointer: str
    evidence: str
    message: str

    def to_dict(self) -> dict:
        return asdict(self)

    def sort_key(self):
        # Total order: (file, json_pointer, rule_id), then severity/evidence/
        # message as tiebreakers so output is byte-identical across processes
        # regardless of dict/set iteration order upstream.
        return (self.file, self.json_pointer, self.rule_id, self.severity, self.evidence, self.message)


@dataclass(frozen=True)
class ParseError:
    file: str
    error: str

    def to_dict(self) -> dict:
        return asdict(self)

    def sort_key(self):
        return (self.file, self.error)
