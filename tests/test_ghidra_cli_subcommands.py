"""Tests for the list / describe / raw / batch subcommands (in-process)."""

from __future__ import annotations

import json

from ghidra_headless_mcp.fake_ghidra import FakeGhidraBackend
from ghidra_headless_mcp.server import ALL_TOOL_SPECS, SimpleMcpServer
from tests.cli_harness import canon, run_cli

_ALL_NAMES = {spec["name"] for spec in ALL_TOOL_SPECS}


def test_list_names_only_covers_all_tools() -> None:
    _, out, _ = run_cli(["list", "--names-only"])
    assert set(out.split()) == _ALL_NAMES


def test_list_prefix_filter() -> None:
    _, out, _ = run_cli(["list", "--prefix", "function.", "--names-only"])
    names = out.split()
    assert names and all(name.startswith("function.") for name in names)


def test_list_query_filter() -> None:
    code, out, _ = run_cli(["list", "--query", "decomp"])
    assert code == 0
    assert out["count"] >= 1
    assert all(
        "decomp" in t["name"].lower() or "decomp" in t["description"].lower() for t in out["tools"]
    )


def test_list_pagination() -> None:
    code, out, _ = run_cli(["list", "--limit", "5"])
    assert code == 0
    assert out["count"] == 5
    assert out["total"] == len(_ALL_NAMES)


def test_describe_shows_schema() -> None:
    code, out, _ = run_cli(["describe", "function.rename"])
    assert code == 0
    assert out["name"] == "function.rename"
    assert set(out["properties"]) == {"session_id", "function_start", "name"}
    assert out["required"] == ["session_id", "function_start", "name"]


def test_describe_server_only_tool_has_no_backend_method() -> None:
    code, out, _ = run_cli(["describe", "health.ping"])
    assert code == 0
    assert out["backend_method"] is None


def test_describe_includes_defaults() -> None:
    _, out, _ = run_cli(["describe", "program.open"])
    assert out["defaults"].get("read_only") is True


def test_raw_initialize() -> None:
    server = SimpleMcpServer(FakeGhidraBackend())
    code, out, _ = run_cli(["raw", "initialize"], server=server)
    assert code == 0
    assert out["serverInfo"]["name"] == "ghidra_headless_mcp"


def test_raw_tools_list_total() -> None:
    server = SimpleMcpServer(FakeGhidraBackend())
    code, out, _ = run_cli(["raw", "tools/list", "--params", "{}"], server=server)
    assert code == 0
    assert out["total"] == len(_ALL_NAMES)


def test_batch_stateful_sequence(tmp_path) -> None:
    server = SimpleMcpServer(FakeGhidraBackend())
    script = tmp_path / "batch.jsonl"
    script.write_text(
        '{"tool": "program.open", "arguments": {"path": "/x.bin", "read_only": false, '
        '"update_analysis": false}}\n'
        '{"tool": "function.list", "arguments": {"limit": 2}}\n',
        encoding="utf-8",
    )
    code, out, _ = run_cli(["batch", str(script)], server=server)
    records = [json.loads(line) for line in out.splitlines() if line.strip()]
    assert code == 0
    assert [r["tool"] for r in records] == ["program.open", "function.list"]
    opened_session = records[0]["structuredContent"]["session_id"]
    listed_session = records[1]["structuredContent"]["session_id"]
    assert listed_session == opened_session  # autosession threaded the opened session into line 2
    assert records[1]["structuredContent"]["count"] == 2


def test_batch_close_after_closes_opened_sessions(tmp_path) -> None:
    backend = FakeGhidraBackend()
    server = SimpleMcpServer(backend)
    script = tmp_path / "batch.jsonl"
    script.write_text(
        '{"tool": "program.open", "arguments": {"path": "/y.bin", "read_only": false, '
        '"update_analysis": false}}\n',
        encoding="utf-8",
    )
    code, _, _ = run_cli(["batch", "--close-after", str(script)], server=server)
    assert code == 0
    # the session opened during the batch was closed, leaving none behind
    listing = backend.session_list()
    assert listing["count"] == 0


def test_field_extraction() -> None:
    server = SimpleMcpServer(FakeGhidraBackend())
    code, out, _ = run_cli(["--field", "status", "call", "health.ping"], server=server)
    assert code == 0
    assert out.strip() == "ok"


def test_in_process_session_hint_on_stderr() -> None:
    server = SimpleMcpServer(FakeGhidraBackend())
    code, _, err = run_cli(
        [
            "call",
            "program.open",
            "--path",
            "/z.bin",
            "--read-only",
            "false",
            "--update-analysis",
            "false",
        ],
        server=server,
    )
    assert code == 0
    assert "ephemeral" in err


def test_canon_interns_volatile_ids() -> None:
    left = {"session_id": "abc", "count": 1, "items": [{"session_id": "abc"}]}
    right = {"session_id": "xyz", "count": 1, "items": [{"session_id": "xyz"}]}
    assert canon(left) == canon(right)


def test_canon_does_not_mask_real_differences() -> None:
    # Differing non-id content must remain unequal after canonicalization.
    assert canon({"session_id": "a", "count": 1}) != canon({"session_id": "b", "count": 2})
    # A non-volatile key that happens to hold an id-like value is left intact (not interned).
    assert canon({"name": "abc"}) != canon({"name": "xyz"})
