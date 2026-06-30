"""Adversarial verification harness for :mod:`ghidra_headless_mcp.ghidra_cli`.

Modeled on :mod:`ghidra_headless_mcp.fuzzer`, this proves that the CLI can drive every tool and
produces results identical to the MCP server, with the documented exit-code contract, and that
malformed input never crashes. It is used by ``tests/test_ghidra_cli_adversarial.py`` and can be
run standalone::

    python -m ghidra_headless_mcp.cli_verify

It runs entirely against the deterministic fake backend, so it is CI-safe and needs no Ghidra.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from typing import Any

from . import ghidra_cli
from .fuzz_support import create_tool_context, pre_actions, tool_arguments
from .ghidra_cli import EXIT_OK, EXIT_TOOL_ERROR, EXIT_USAGE
from .server import ALL_TOOL_SPECS

#: Result keys that carry per-run-volatile identifiers; interned before comparison.
_VOLATILE_KEYS = {"session_id", "task_id", "transitioned_session_ids"}


def _canon(obj: Any, mapping: dict[str, str]) -> Any:
    """Return a copy with volatile id values interned to first-appearance tokens by key name."""

    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for key, value in sorted(obj.items()):
            if key in _VOLATILE_KEYS:
                out[key] = _intern_volatile(key, value, mapping)
            else:
                out[key] = _canon(value, mapping)
        return out
    if isinstance(obj, list):
        return [_canon(item, mapping) for item in obj]
    return obj


def _intern_volatile(key: str, value: Any, mapping: dict[str, str]) -> Any:
    if isinstance(value, str):
        token = mapping.get(value)
        if token is None:
            token = f"<{key}:{len(mapping)}>"
            mapping[value] = token
        return token
    if isinstance(value, list):
        return [_intern_volatile(key, item, mapping) for item in value]
    return value


def canon(obj: Any) -> Any:
    """Canonicalize a structuredContent payload so two independently-seeded runs compare equal."""

    return _canon(obj, {})


def _run_cli(argv: list[str], server: Any) -> tuple[int, str, str]:
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = ghidra_cli.main(argv, server=server)
    return code, out.getvalue(), err.getvalue()


def _direct(server: Any, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    return response["result"]


def _flagify(arguments: dict[str, Any]) -> list[str] | None:
    """Render a scalar arguments dict as ``--flag value`` tokens, or ``None`` if not scalar."""

    flags: list[str] = []
    for key, value in arguments.items():
        if isinstance(value, bool):
            flags += [f"--{key}", "true" if value else "false"]
        elif isinstance(value, (int, float, str)):
            flags += [f"--{key}", str(value)]
        else:
            return None
    return flags


def _expected_exit(reference: dict[str, Any]) -> int:
    return EXIT_TOOL_ERROR if reference.get("isError") else EXIT_OK


_UNAMBIGUOUS_TYPES = {"boolean", "integer", "number", "string"}


def _flag_safe(spec: dict[str, Any], arguments: dict[str, Any]) -> bool:
    """True when every arg round-trips identically through the flag and ``--json`` paths.

    Untyped (``{}``) and address ``oneOf`` parameters are intentionally passed as strings via
    flags, so they only converge with the native-typed ``--json`` path when the value is already
    a string. Such tools are skipped from the flag-vs-json convergence check by design.
    """

    props = spec.get("properties", {})
    for key, value in arguments.items():
        schema = props.get(key, {})
        if schema.get("type") in _UNAMBIGUOUS_TYPES:
            continue
        if isinstance(value, str):
            continue
        return False
    return True


def _verify_tool(spec: dict[str, Any], paths: tuple[str, ...]) -> dict[str, Any]:
    name = spec["name"]
    finding: dict[str, Any] = {"tool": name}

    ref_ctx = create_tool_context()
    pre_actions(ref_ctx.backend, name, ref_ctx.session_id)
    ref_args = tool_arguments(spec, ref_ctx.session_id, ref_ctx.task_id)
    reference = _direct(ref_ctx.server, name, ref_args)
    finding["reference_is_error"] = bool(reference.get("isError"))

    if "json" in paths:
        cli_ctx = create_tool_context()
        pre_actions(cli_ctx.backend, name, cli_ctx.session_id)
        cli_args = tool_arguments(spec, cli_ctx.session_id, cli_ctx.task_id)
        code, out, err = _run_cli(["call", name, "--json", json.dumps(cli_args)], cli_ctx.server)
        finding["json_exit"] = code
        finding["json_missing"] = code == EXIT_USAGE and "-32601" in err
        finding["json_exit_ok"] = code == _expected_exit(reference)
        cli_struct = json.loads(out) if out.strip() else {}
        finding["json_parity"] = canon(cli_struct) == canon(reference["structuredContent"])

    if "flag" in paths:
        flag_ctx = create_tool_context()
        pre_actions(flag_ctx.backend, name, flag_ctx.session_id)
        flag_args = tool_arguments(spec, flag_ctx.session_id, flag_ctx.task_id)
        flags = _flagify(flag_args)
        if flags is None or not _flag_safe(spec, flag_args):
            finding["flag_skipped"] = True
        else:
            code, out, _ = _run_cli(["call", name, *flags], flag_ctx.server)
            json_ctx = create_tool_context()
            pre_actions(json_ctx.backend, name, json_ctx.session_id)
            json_args = tool_arguments(spec, json_ctx.session_id, json_ctx.task_id)
            _, json_out, _ = _run_cli(
                ["call", name, "--json", json.dumps(json_args)], json_ctx.server
            )
            flag_struct = json.loads(out) if out.strip() else {}
            ref_struct = json.loads(json_out) if json_out.strip() else {}
            finding["flag_exit_ok"] = code == _expected_exit(reference)
            finding["flag_parity"] = canon(flag_struct) == canon(ref_struct)

    return finding


def _fuzz_cases() -> list[dict[str, Any]]:
    """Malformed invocations that must yield a clean exit code (never a traceback)."""

    return [
        {"argv": ["call", "no.such.tool"], "expect": EXIT_USAGE, "label": "unknown-tool"},
        {
            "argv": ["call", "health.ping", "--json", "{bad"],
            "expect": EXIT_USAGE,
            "label": "bad-json",
        },
        {"argv": ["call", "function.list"], "expect": EXIT_USAGE, "label": "missing-required"},
        {
            "argv": ["call", "function.list", "--session_id", "x", "--limit", "notint"],
            "expect": EXIT_USAGE,
            "label": "bad-int",
        },
        {
            "argv": ["call", "function.list", "--session_id", "x", "--limit", ""],
            "expect": EXIT_USAGE,
            "label": "empty-int",
        },
        {
            "argv": ["call", "program.open", "--bogus", "x"],
            "expect": EXIT_USAGE,
            "label": "unknown-flag",
        },
        {"argv": ["raw", "shutdown"], "expect": EXIT_USAGE, "label": "raw-shutdown-guard"},
        {"argv": ["raw", "no/such/method"], "expect": EXIT_USAGE, "label": "unknown-method"},
    ]


def _run_fuzz() -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []
    for case in _fuzz_cases():
        ctx = create_tool_context()
        try:
            code, _, _ = _run_cli(case["argv"], ctx.server)
        except Exception as exc:  # a traceback here is itself the failure being detected
            violations.append({"label": case["label"], "crash": f"{type(exc).__name__}: {exc}"})
            continue
        if code != case["expect"]:
            violations.append({"label": case["label"], "code": code, "expected": case["expect"]})
    return violations


def run(prefix: str | None = None, *, paths: tuple[str, ...] = ("json",)) -> dict[str, Any]:
    """Verify every tool (optionally filtered by ``prefix``) and return a structured report."""

    specs = [s for s in ALL_TOOL_SPECS if prefix is None or s["name"].startswith(prefix)]
    findings = [_verify_tool(spec, paths) for spec in specs]

    mismatches = [
        {"tool": f["tool"]}
        for f in findings
        if not f.get("json_parity", True) or not f.get("flag_parity", True)
    ]
    missing_tools = [f["tool"] for f in findings if f.get("json_missing")]
    exit_code_violations = [
        {"tool": f["tool"], "json_exit": f.get("json_exit")}
        for f in findings
        if not f.get("json_exit_ok", True) or not f.get("flag_exit_ok", True)
    ]
    return {
        "tool_count": len(findings),
        "mismatches": mismatches,
        "missing_tools": missing_tools,
        "exit_code_violations": exit_code_violations,
        "fuzz_violations": _run_fuzz(),
        "reference_errors": [f["tool"] for f in findings if f.get("reference_is_error")],
    }


def main() -> int:
    report = run(paths=("json", "flag"))
    summary = {key: report[key] for key in report if key != "reference_errors"}
    print(json.dumps(summary, indent=2, sort_keys=True))
    clean = (
        not report["mismatches"]
        and not report["missing_tools"]
        and not report["exit_code_violations"]
        and not report["fuzz_violations"]
    )
    return EXIT_OK if clean else 1


if __name__ == "__main__":
    raise SystemExit(main())
