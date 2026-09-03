import os

import pytest

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
PLANTED_ROOT = os.path.join(FIXTURES, "planted")
CLEAN_ROOT = os.path.join(FIXTURES, "clean")

PLANTED_RULE_IDS = [
    "dead_matcher",
    "unreachable_skill",
    "shadowed_definition",
    "unknown_key",
    "unquoted_interpolation",
    "fetch_pipe_interpreter",
    "broad_permission",
    "mcp_unstartable",
]


@pytest.fixture(scope="session")
def planted_root():
    return PLANTED_ROOT


@pytest.fixture(scope="session")
def clean_root():
    return CLEAN_ROOT
