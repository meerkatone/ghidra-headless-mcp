"""Drift guard: GHIDRA_CLI.md must document exactly the live tool registry."""

from __future__ import annotations

import re
from pathlib import Path

from ghidra_headless_mcp.server import ALL_TOOL_SPECS

_DOC = Path(__file__).resolve().parents[1] / "GHIDRA_CLI.md"


def test_doc_lists_exactly_every_tool() -> None:
    text = _DOC.read_text(encoding="utf-8")
    documented = set(re.findall(r"^#### `([^`]+)`", text, re.MULTILINE))
    expected = {spec["name"] for spec in ALL_TOOL_SPECS}
    assert documented == expected, {
        "missing_from_doc": sorted(expected - documented),
        "stale_in_doc": sorted(documented - expected),
    }


def test_doc_shows_call_invocation_per_tool() -> None:
    text = _DOC.read_text(encoding="utf-8")
    # every tool entry is followed by a fenced `ghidra_cli call <name>` signature
    assert text.count("ghidra_cli call ") >= len(ALL_TOOL_SPECS)
