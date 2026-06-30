"""Holistic adversarial gate: parity, exit-code matrix and fuzz across all 212 tools."""

from __future__ import annotations

import pytest
from ghidra_headless_mcp import cli_verify
from ghidra_headless_mcp.server import ALL_TOOL_SPECS


@pytest.mark.slow
def test_cli_verify_full_sweep_is_clean() -> None:
    report = cli_verify.run(paths=("json", "flag"))
    assert report["tool_count"] == len(ALL_TOOL_SPECS)
    assert report["mismatches"] == []
    assert report["missing_tools"] == []
    assert report["exit_code_violations"] == []
    assert report["fuzz_violations"] == []


def test_cli_verify_fuzz_inputs_never_crash() -> None:
    # A cheap prefix keeps this fast; run() always exercises the full fuzz-case matrix.
    report = cli_verify.run(prefix="health.")
    assert report["fuzz_violations"] == []
