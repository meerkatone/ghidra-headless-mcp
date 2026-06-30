"""Shared helpers for the ghidra_cli test suite (mirrors tests/tool_harness.py)."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

from ghidra_headless_mcp import ghidra_cli
from ghidra_headless_mcp.cli_verify import canon
from ghidra_headless_mcp.server import ALL_TOOL_SPECS, SimpleMcpServer

ROOT = Path(__file__).resolve().parents[1]

__all__ = [
    "ALL_TOOL_SPECS",
    "ROOT",
    "SimpleMcpServer",
    "canon",
    "flag_safe",
    "flagify",
    "pythonpath_env",
    "run_cli",
    "run_cli_subprocess",
]


def pythonpath_env() -> dict[str, str]:
    env = os.environ.copy()
    current = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(ROOT) if not current else f"{ROOT}{os.pathsep}{current}"
    return env


def run_cli_subprocess(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ghidra_headless_mcp.ghidra_cli", *args],
        capture_output=True,
        cwd=ROOT,
        env=pythonpath_env(),
        text=True,
        check=kwargs.pop("check", False),
        **kwargs,
    )


def run_cli(argv: list[str], *, server: SimpleMcpServer | None = None) -> tuple[int, Any, str]:
    """Invoke ghidra_cli.main; return (exit_code, parsed_stdout_or_text, stderr).

    stdout is parsed as JSON when possible (the default output is pretty JSON); otherwise the raw
    text is returned. ``SystemExit`` from argparse is caught and its code returned.
    """

    out = io.StringIO()
    err = io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            code = ghidra_cli.main(argv, server=server)
    except SystemExit as exc:  # argparse usage errors / --version
        code = int(exc.code) if isinstance(exc.code, int) else 2
    raw = out.getvalue()
    try:
        parsed: Any = json.loads(raw) if raw.strip() else None
    except json.JSONDecodeError:
        parsed = raw
    return code, parsed, err.getvalue()


_UNAMBIGUOUS_TYPES = {"boolean", "integer", "number", "string"}


def flagify(arguments: dict[str, Any]) -> list[str] | None:
    """Render a scalar arguments dict as ``--flag value`` tokens, or None if not scalar."""

    flags: list[str] = []
    for key, value in arguments.items():
        if isinstance(value, bool):
            flags += [f"--{key}", "true" if value else "false"]
        elif isinstance(value, (int, float, str)):
            flags += [f"--{key}", str(value)]
        else:
            return None
    return flags


def flag_safe(spec: dict[str, Any], arguments: dict[str, Any]) -> bool:
    """True when every generated arg round-trips identically through flag and --json paths.

    Untyped (``{}``) and address ``oneOf`` params are passed as strings via flags, so they only
    converge with the native-typed ``--json`` path when the value is already a string.
    """

    props = spec.get("properties", {})
    for key, value in arguments.items():
        if props.get(key, {}).get("type") in _UNAMBIGUOUS_TYPES:
            continue
        if isinstance(value, str):
            continue
        return False
    return True
