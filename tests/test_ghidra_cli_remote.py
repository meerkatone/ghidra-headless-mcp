"""Remote/TCP tests: persistent server-side sessions and managed-server lifecycle."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time

import pytest
from tests.cli_harness import ROOT, pythonpath_env, run_cli_subprocess


def _reserve_port() -> tuple[str, int]:
    try:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()
    except PermissionError as exc:
        pytest.skip(f"localhost sockets are unavailable in this environment: {exc}")


def _wait_ready(host: str, port: int, *, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError("tcp server did not become ready")


def _start_server(host: str, port: int) -> subprocess.Popen:
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "ghidra_headless_mcp",
            "--fake-backend",
            "--transport",
            "tcp",
            "--host",
            host,
            "--port",
            str(port),
        ],
        cwd=ROOT,
        env=pythonpath_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


@pytest.mark.socket
def test_remote_persistent_session_across_invocations() -> None:
    host, port = _reserve_port()
    proc = _start_server(host, port)
    target = f"{host}:{port}"
    try:
        _wait_ready(host, port)

        ping = run_cli_subprocess(["--connect", target, "call", "health.ping"])
        assert ping.returncode == 0
        assert json.loads(ping.stdout)["status"] == "ok"

        opened = run_cli_subprocess(
            [
                "--connect",
                target,
                "--field",
                "session_id",
                "call",
                "program.open",
                "--path",
                "/remote.bin",
                "--read-only",
                "false",
                "--update-analysis",
                "false",
            ]
        )
        assert opened.returncode == 0
        session_id = opened.stdout.strip()
        assert session_id

        # A separate CLI process reuses the server-side session -- proof of persistence.
        listed = run_cli_subprocess(
            [
                "--connect",
                target,
                "--field",
                "count",
                "call",
                "function.list",
                "--session-id",
                session_id,
                "--limit",
                "2",
            ]
        )
        assert listed.returncode == 0
        assert listed.stdout.strip() == "2"
    finally:
        proc.terminate()
        proc.wait(timeout=5)


@pytest.mark.socket
def test_remote_connection_refused_exits_2() -> None:
    host, port = _reserve_port()  # reserved but nothing is listening
    proc = run_cli_subprocess(["--connect", f"{host}:{port}", "call", "health.ping"])
    assert proc.returncode == 2
    assert "connect" in proc.stderr.lower()


@pytest.mark.socket
def test_managed_server_lifecycle(tmp_path) -> None:
    host, port = _reserve_port()
    env = pythonpath_env()
    env["GHIDRA_CLI_HOME"] = str(tmp_path / "state")

    def cli(args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "ghidra_headless_mcp.ghidra_cli", *args],
            capture_output=True,
            cwd=ROOT,
            env=env,
            text=True,
            check=False,
        )

    try:
        started = cli(["--fake-backend", "server", "start", "--host", host, "--port", str(port)])
        assert started.returncode == 0, started.stderr

        status = cli(["server", "status"])
        assert json.loads(status.stdout)["running"] is True

        # call auto-connects to the managed server (no explicit transport flag).
        ping = cli(["call", "health.ping"])
        assert ping.returncode == 0
        assert json.loads(ping.stdout)["status"] == "ok"
    finally:
        stopped = cli(["server", "stop"])
        assert stopped.returncode == 0
    assert json.loads(cli(["server", "status"]).stdout)["running"] is False
