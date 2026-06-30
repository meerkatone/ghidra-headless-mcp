"""Drift guard: the CLI must expose exactly the server's tool set (mirrors test_registry_consistency)."""

from __future__ import annotations

import pytest
from ghidra_headless_mcp.fake_ghidra import FakeGhidraBackend
from ghidra_headless_mcp.ghidra_cli import SPECS
from ghidra_headless_mcp.server import ALL_TOOL_SPECS, SimpleMcpServer
from tests.cli_harness import run_cli

_SPECS = {spec["name"]: spec for spec in ALL_TOOL_SPECS}
_NAMES = list(_SPECS)


def test_cli_specs_equal_server_handlers() -> None:
    server = SimpleMcpServer(FakeGhidraBackend())
    assert set(SPECS) == set(server._tool_handlers)


def test_list_matches_all_tool_specs() -> None:
    _, out, _ = run_cli(["list", "--names-only"])
    assert set(out.split()) == set(_NAMES)


@pytest.mark.parametrize("name", _NAMES)
def test_describe_every_tool(name: str) -> None:
    code, out, _ = run_cli(["describe", name])
    assert code == 0
    assert out["name"] == name
    assert set(out["properties"]) == set(_SPECS[name]["properties"])
    assert out["required"] == list(_SPECS[name]["required"])
