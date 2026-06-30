"""All-212 parity sweep: the CLI must produce exactly what the MCP server produces."""

from __future__ import annotations

import json

import pytest
from ghidra_headless_mcp.fuzz_support import create_tool_context, pre_actions, tool_arguments
from ghidra_headless_mcp.server import ALL_TOOL_SPECS
from tests.cli_harness import canon, flag_safe, flagify, run_cli
from tests.tool_harness import call_tool

_SPECS = {spec["name"]: spec for spec in ALL_TOOL_SPECS}
_NAMES = [spec["name"] for spec in ALL_TOOL_SPECS]


@pytest.mark.parametrize("name", _NAMES)
def test_cli_json_path_matches_direct_mcp(name: str) -> None:
    spec = _SPECS[name]

    ref_ctx = create_tool_context()
    pre_actions(ref_ctx.backend, name, ref_ctx.session_id)
    ref_args = tool_arguments(spec, ref_ctx.session_id, ref_ctx.task_id)
    reference = call_tool(ref_ctx.server, name, ref_args)
    assert reference["isError"] is False, (name, reference["structuredContent"])

    cli_ctx = create_tool_context()
    pre_actions(cli_ctx.backend, name, cli_ctx.session_id)
    cli_args = tool_arguments(spec, cli_ctx.session_id, cli_ctx.task_id)
    code, out, err = run_cli(["call", name, "--json", json.dumps(cli_args)], server=cli_ctx.server)

    assert code == 0, (name, err)
    assert canon(out) == canon(reference["structuredContent"]), name


@pytest.mark.parametrize("name", _NAMES)
def test_cli_flag_path_matches_json_path(name: str) -> None:
    spec = _SPECS[name]

    flag_ctx = create_tool_context()
    pre_actions(flag_ctx.backend, name, flag_ctx.session_id)
    flag_args = tool_arguments(spec, flag_ctx.session_id, flag_ctx.task_id)
    flags = flagify(flag_args)
    if flags is None or not flag_safe(spec, flag_args):
        pytest.skip("arguments are not faithfully representable as scalar --flags")
    flag_code, flag_out, flag_err = run_cli(["call", name, *flags], server=flag_ctx.server)

    json_ctx = create_tool_context()
    pre_actions(json_ctx.backend, name, json_ctx.session_id)
    json_args = tool_arguments(spec, json_ctx.session_id, json_ctx.task_id)
    json_code, json_out, _ = run_cli(
        ["call", name, "--json", json.dumps(json_args)], server=json_ctx.server
    )

    assert flag_code == json_code == 0, (name, flag_err)
    assert canon(flag_out) == canon(json_out), name
