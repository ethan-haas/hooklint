from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from hooklint import __version__
from hooklint.engine import scan


def _human_report(result) -> str:
    lines: List[str] = []
    findings = result.sorted_findings()
    errors = result.sorted_parse_errors()
    total = result.ctx.checked
    unknown = result.ctx.unknown
    unknown_rate = (unknown / total) if total else 0.0

    if not findings and not errors:
        lines.append(f"hooklint: scanned {len(result.files_scanned)} file(s), 0 findings, "
                      f"unknown_rate={unknown_rate:.4f} ({unknown}/{total})")
        return "\n".join(lines)

    for e in errors:
        lines.append(f"ERROR  {e.file}  (unparseable: {e.error})")

    for f in findings:
        lines.append(f"{f.severity.upper():5s}  {f.file}  {f.json_pointer}  [{f.rule_id}]")
        lines.append(f"       {f.message}")
        lines.append(f"       evidence: {f.evidence}")

    total = result.ctx.checked
    unknown = result.ctx.unknown
    unknown_rate = (unknown / total) if total else 0.0
    lines.append("")
    lines.append(f"hooklint: scanned {len(result.files_scanned)} file(s), "
                  f"{len(findings)} finding(s), {len(errors)} parse error(s), "
                  f"unknown_rate={unknown_rate:.4f} ({unknown}/{total})")
    return "\n".join(lines)


def _json_report(result) -> str:
    findings = result.sorted_findings()
    errors = result.sorted_parse_errors()
    total = result.ctx.checked
    unknown = result.ctx.unknown
    payload = {
        "files_scanned": result.files_scanned,
        "findings": [f.to_dict() for f in findings],
        "parse_errors": [e.to_dict() for e in errors],
        "checked": total,
        "unknown": unknown,
        "unknown_rate": (unknown / total) if total else 0.0,
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hooklint",
                                      description="Offline, deterministic linter for agent hook/skill/MCP configs.")
    parser.add_argument("path", nargs="?", default=".",
                         help="root directory (or single file) to scan; defaults to cwd")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of human-readable text")
    parser.add_argument("--version", action="version", version=f"hooklint {__version__}")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 2

    import os
    if not os.path.exists(args.path):
        sys.stderr.write(f"hooklint: usage error: path does not exist: {args.path}\n")
        return 2

    try:
        result = scan(args.path)
    except OSError as e:
        sys.stderr.write(f"hooklint: usage error: {e}\n")
        return 2

    if args.json:
        sys.stdout.write(_json_report(result) + "\n")
    else:
        sys.stdout.write(_human_report(result) + "\n")

    if result.parse_errors:
        return 2
    if result.findings:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
