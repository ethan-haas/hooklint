"""Acceptance gate 6: determinism across PROCESSES, at least 3 subprocesses
with differing PYTHONHASHSEED, byte-identical stdout. This must go through
a real subprocess boundary -- an in-process repeat cannot exercise dict/set
iteration-order sensitivity to PYTHONHASHSEED the way separate interpreter
starts can.
"""
import os
import subprocess
import sys

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _run_with_seed(seed: str) -> bytes:
    env = dict(os.environ)
    env["PYTHONHASHSEED"] = seed
    proc = subprocess.run(
        [sys.executable, "-m", "hooklint", "--json", FIXTURES],
        capture_output=True,
        env=env,
        check=False,
    )
    return proc.stdout


def test_determinism_across_three_processes_differing_hashseed():
    outputs = [_run_with_seed(seed) for seed in ("0", "1", "42")]
    assert len(outputs[0]) > 0, "scan produced no output at all"
    assert outputs[0] == outputs[1] == outputs[2], (
        "stdout differed across PYTHONHASHSEED values -- output depends on "
        "hash/iteration order somewhere"
    )
