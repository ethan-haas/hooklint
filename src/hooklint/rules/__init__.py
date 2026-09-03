from hooklint.rules import (
    dead_matcher,
    unreachable_skill,
    shadowed_definition,
    unknown_key,
    unquoted_interpolation,
    fetch_pipe_interpreter,
    broad_permission,
    mcp_unstartable,
)

# Ordered by rule_id for stable iteration; engine also globally sorts
# findings so this order is cosmetic, not load-bearing.
FILE_RULES = [
    dead_matcher,
    unknown_key,
    unquoted_interpolation,
    fetch_pipe_interpreter,
    broad_permission,
    mcp_unstartable,
    unreachable_skill,
]

CROSS_FILE_RULES = [
    shadowed_definition,
]

__all__ = ["FILE_RULES", "CROSS_FILE_RULES"]
