"""Subprocess tests for ghidra_cli (CI-safe, no sockets) -- mirrors test_cli_subprocess.py."""

from __future__ import annotations

import json

from ghidra_headless_mcp import __version__
from tests.cli_harness import run_cli_subprocess


def test_version() -> None:
    proc = run_cli_subprocess(["--version"])
    assert proc.returncode == 0
    assert __version__ in proc.stdout


def test_call_health_ping() -> None:
    proc = run_cli_subprocess(["--fake-backend", "call", "health.ping"])
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["status"] == "ok"


def test_list_names_only_count() -> None:
    proc = run_cli_subprocess(["list", "--names-only"])
    assert proc.returncode == 0
    assert len(proc.stdout.split()) == 212


def test_unknown_tool_exits_2() -> None:
    proc = run_cli_subprocess(["--fake-backend", "call", "no.such.tool"])
    assert proc.returncode == 2
    assert "unknown tool" in proc.stderr


def test_missing_required_exits_2() -> None:
    proc = run_cli_subprocess(["--fake-backend", "call", "function.list"])
    assert proc.returncode == 2
    assert "required" in proc.stderr


def test_malformed_json_exits_2() -> None:
    proc = run_cli_subprocess(["--fake-backend", "call", "health.ping", "--json", "{bad"])
    assert proc.returncode == 2


def test_tool_error_exits_1() -> None:
    proc = run_cli_subprocess(
        [
            "--fake-backend",
            "call",
            "function.rename",
            "--session-id",
            "does-not-exist",
            "--function_start",
            "0x1000",
            "--name",
            "renamed",
        ]
    )
    assert proc.returncode == 1
    payload = json.loads(proc.stdout)
    assert "error" in payload


def test_raw_shutdown_guarded_exits_2() -> None:
    proc = run_cli_subprocess(["--fake-backend", "raw", "shutdown"])
    assert proc.returncode == 2
    assert "shutdown" in proc.stderr


def test_empty_integer_value_is_clean_usage_error() -> None:
    proc = run_cli_subprocess(
        ["--fake-backend", "call", "function.list", "--session_id", "x", "--limit", ""]
    )
    assert proc.returncode == 2
    assert "Traceback" not in proc.stderr
    assert "integer" in proc.stderr


def test_raw_tool_error_exits_1() -> None:
    proc = run_cli_subprocess(
        [
            "--fake-backend",
            "raw",
            "tools/call",
            "--params",
            '{"name": "function.list", "arguments": {"session_id": "missing"}}',
        ]
    )
    assert proc.returncode == 1
    assert json.loads(proc.stdout)["isError"] is True
