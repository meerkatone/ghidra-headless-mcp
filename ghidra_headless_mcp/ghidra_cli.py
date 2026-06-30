"""Native command-line client for the Ghidra Headless MCP server.

``ghidra_cli`` lets agents and shells that do not speak the MCP protocol drive *all* of the
server's tools with plain commands::

    ghidra_cli call function.list --session-id <id> --limit 50

It is a thin layer over a ``dispatch(method, params) -> result`` abstraction with two backends:

* **In-process** (default): builds the backend and dispatches through
  :meth:`SimpleMcpServer.handle_request` -- the identical MCP code path, so results match the
  server exactly. State is ephemeral per invocation.
* **Remote** (``--connect host:port`` or a managed background server): a line-delimited
  JSON-RPC/TCP client to a long-lived server, so session state persists across invocations.

Tool names, parameters, types and required-ness are all derived from
:data:`ghidra_headless_mcp.server.ALL_TOOL_SPECS`, so the CLI never drifts from the server.
"""

from __future__ import annotations

import argparse
import difflib
import inspect
import json
import os
import signal
import socket
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

from ._version import __version__
from .backend import GhidraBackend
from .cli import add_backend_args, build_backend
from .server import ALL_TOOL_SPECS, SimpleMcpServer

#: Tool name -> spec, the single source of truth shared with the server.
SPECS: dict[str, dict[str, Any]] = {spec["name"]: spec for spec in ALL_TOOL_SPECS}

EXIT_OK = 0
EXIT_TOOL_ERROR = 1
EXIT_USAGE = 2

_DEFAULT_PROTOCOL = "2025-03-26"
_OPEN_TOOLS = {
    "program.open",
    "program.open_bytes",
    "project.program.open",
    "project.program.open_existing",
}
_PROTOCOL_ERROR_CODES = (-32700, -32600, -32601, -32602)

# Cache for a single stdin read shared across all ``-`` value sources in one invocation.
_STDIN_CACHE: dict[str, str] = {}


class CliUsageError(Exception):
    """A client-side usage error (bad flag, bad value, unknown tool, connection setup)."""


class RpcError(Exception):
    """A JSON-RPC ``error`` object returned by the server."""

    def __init__(self, code: Any, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


# --------------------------------------------------------------------------------------
# Value parsing / coercion
# --------------------------------------------------------------------------------------


def _parse_int(raw: str) -> int:
    """Parse an integer accepting ``0x``/``0o``/``0b`` prefixes, else base-10 (no octal trap)."""

    text = (raw or "").strip()
    sign = 1
    if text and text[0] in "+-":
        sign = -1 if text[0] == "-" else 1
        text = text[1:]
    if not text:
        raise CliUsageError(f"expected an integer, got {raw!r}")
    low = text.lower()
    if low.startswith("0x"):
        base = 16
    elif low.startswith("0o"):
        base = 8
    elif low.startswith("0b"):
        base = 2
    else:
        base = 10
    try:
        return sign * int(text, base)
    except ValueError as exc:
        raise CliUsageError(f"expected an integer, got {raw!r}") from exc


def _parse_float(raw: str) -> float:
    try:
        return float(raw)
    except (ValueError, TypeError) as exc:
        raise CliUsageError(f"expected a number, got {raw!r}") from exc


def _parse_bool(raw: str | None) -> bool:
    if raw is None:
        return True
    text = raw.strip().lower()
    if text in {"true", "1", "yes", "on"}:
        return True
    if text in {"false", "0", "no", "off"}:
        return False
    raise CliUsageError(f"invalid boolean {raw!r} (use true/false/yes/no/on/off/1/0)")


def _parse_json(raw: str, *, expect: str | None = None) -> Any:
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        raise CliUsageError(f"invalid JSON value: {raw!r}") from exc
    if expect == "object" and not isinstance(value, dict):
        raise CliUsageError(f"expected a JSON object, got {type(value).__name__}")
    if expect == "array" and not isinstance(value, list):
        raise CliUsageError(f"expected a JSON array, got {type(value).__name__}")
    return value


def _try_json_else_str(raw: str) -> Any:
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw


def coerce_value(raw: str, schema: dict[str, Any] | None) -> Any:
    """Coerce one string value to the JSON type described by a tool property schema.

    Address parameters (``oneOf[integer, string]``) and untyped (``{}``) parameters are passed
    through **as strings** so the backend applies its own interpretation -- in particular Ghidra
    parses a bare-digit address string as hex, so coercing it to a decimal int would silently
    point at the wrong location.
    """

    schema = schema or {}
    if "oneOf" in schema:
        return raw
    kind = schema.get("type")
    if kind == "boolean":
        return _parse_bool(raw)
    if kind == "integer":
        return _parse_int(raw)
    if kind == "number":
        return _parse_float(raw)
    if kind == "string":
        return raw
    if kind == "object":
        return _parse_json(raw, expect="object")
    if kind == "array":
        return _parse_json(raw, expect="array")
    return raw


def coerce_scalar(raw: str, item_type: str | None) -> Any:
    """Coerce a single array element by its declared ``items.type``."""

    if item_type == "integer":
        return _parse_int(raw)
    if item_type == "number":
        return _parse_float(raw)
    if item_type == "boolean":
        return _parse_bool(raw)
    if item_type == "string":
        return raw
    return _try_json_else_str(raw)


def _coerce_typed(typ: str, raw: str | None, has_value: bool) -> Any:
    """Coerce using an explicit ``--key:TYPE`` override."""

    if typ == "null":
        return None
    if typ == "bool":
        return _parse_bool(raw)
    if not has_value:
        raise CliUsageError(f"type ':{typ}' requires a value")
    if typ == "str":
        return raw
    if typ == "int":
        return _parse_int(raw)
    if typ == "float":
        return _parse_float(raw)
    if typ == "json":
        return _parse_json(raw)
    raise CliUsageError(f"unknown value type ':{typ}' (use str/int/float/bool/json/null)")


def _read_stdin_once() -> str:
    if "data" not in _STDIN_CACHE:
        _STDIN_CACHE["data"] = sys.stdin.read()
    return _STDIN_CACHE["data"]


def _apply_value_source(raw: str) -> str:
    """Resolve ``@file`` and ``-`` value sources (keeps large/secret values off argv)."""

    if raw == "-":
        return _read_stdin_once()
    if raw.startswith("@"):
        path = raw[1:]
        try:
            return Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise CliUsageError(f"cannot read value file {path!r}: {exc}") from exc
    return raw


# --------------------------------------------------------------------------------------
# Argument grammar for ``call``
# --------------------------------------------------------------------------------------


def _reject_unknown_flag(name: str, props: dict[str, Any]) -> None:
    matches = difflib.get_close_matches(name, list(props), n=3)
    hint = f" did you mean: {', '.join('--' + m for m in matches)}?" if matches else ""
    raise CliUsageError(f"unknown argument --{name}.{hint}")


def _assign_arg(
    result: dict[str, Any],
    name: str,
    typ: str | None,
    raw: str | None,
    has_value: bool,
    schema: dict[str, Any],
) -> None:
    if typ is not None:
        result[name] = _coerce_typed(typ, raw, has_value)
        return
    if schema.get("type") == "array":
        if not has_value:
            raise CliUsageError(f"--{name} requires a value")
        item_type = (schema.get("items") or {}).get("type")
        element = coerce_scalar(raw, item_type)
        existing = result.get(name)
        if isinstance(existing, list):
            existing.append(element)
        else:
            result[name] = [element]
        return
    if not has_value:
        if schema.get("type") == "boolean":
            result[name] = True
            return
        raise CliUsageError(f"--{name} requires a value")
    result[name] = coerce_value(raw, schema)


def parse_tool_rest(rest: list[str], spec: dict[str, Any]) -> dict[str, Any]:
    """Turn the trailing ``--flag value`` tokens of a ``call`` into a JSON arguments object.

    Supports ``--key value``, ``--key=value``, bare boolean ``--flag``, repeated flags (arrays),
    ``--key:TYPE`` overrides, ``@file``/``-`` value sources, and the ``--json``/``--json-stdin``
    escape hatches (whose object is the base; per-flag values override it).
    """

    props = spec.get("properties", {})
    base: dict[str, Any] = {}
    result: dict[str, Any] = {}
    index = 0
    count = len(rest)
    while index < count:
        token = rest[index]
        if token == "--":
            index += 1
            continue
        if not token.startswith("--"):
            raise CliUsageError(f"unexpected positional argument: {token!r} (use --name value)")
        left, eq, inline = token[2:].partition("=")
        name_part, colon, typ_part = left.partition(":")
        name = name_part.replace("-", "_")
        typ = typ_part if colon else None
        if name == "json_stdin":  # reads stdin, never consumes a following token
            base.update(_parse_json(_read_stdin_once(), expect="object"))
            index += 1
            continue
        if eq:
            raw: str | None = inline
            has_value = True
            index += 1
        elif index + 1 < count and not rest[index + 1].startswith("--"):
            raw = rest[index + 1]
            has_value = True
            index += 2
        else:
            raw = None
            has_value = False
            index += 1
        if has_value:
            raw = _apply_value_source(raw)
        if name == "json":
            if not has_value:
                raise CliUsageError("--json requires a JSON object value")
            base.update(_parse_json(raw, expect="object"))
            continue
        if name not in props:
            _reject_unknown_flag(name, props)
        _assign_arg(result, name, typ, raw, has_value, props[name])
    merged = dict(base)
    merged.update(result)
    return merged


def _inject_session(
    arguments: dict[str, Any], spec: dict[str, Any], session_id: str | None
) -> None:
    if session_id and "session_id" in spec.get("properties", {}) and "session_id" not in arguments:
        arguments["session_id"] = session_id


def _validate_required(spec: dict[str, Any], arguments: dict[str, Any]) -> None:
    missing = [key for key in spec.get("required", []) if key not in arguments]
    if missing:
        flags = ", ".join(f"--{key}" for key in missing)
        raise CliUsageError(f"missing required argument(s): {flags}")


def _unknown_tool(tool: str) -> None:
    matches = difflib.get_close_matches(tool, list(SPECS), n=3)
    hint = f" did you mean: {', '.join(matches)}?" if matches else ""
    raise CliUsageError(f"unknown tool: {tool!r}.{hint}")


# --------------------------------------------------------------------------------------
# Transports
# --------------------------------------------------------------------------------------


class InProcessTransport:
    """Dispatch against an in-process :class:`SimpleMcpServer` -- the exact MCP code path."""

    def __init__(self, server: SimpleMcpServer, *, owns_backend: bool = False) -> None:
        self._server = server
        self._owns_backend = owns_backend
        self._id = 0

    def dispatch(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self._id += 1
        response = self._server.handle_request(
            {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}
        )
        if response is None:
            return {}
        if "error" in response:
            err = response["error"]
            raise RpcError(err.get("code"), err.get("message", ""), err.get("data"))
        return response["result"]

    def close(self) -> None:
        if not self._owns_backend:
            return
        backend = getattr(self._server, "_backend", None)
        if backend is not None and hasattr(backend, "shutdown"):
            with suppress(Exception):
                backend.shutdown()


class RemoteTransport:
    """Line-delimited JSON-RPC/TCP client matching ``SimpleMcpServer.serve_tcp``."""

    def __init__(self, host: str, port: int, *, connect_timeout: float = 10.0) -> None:
        self._sock = socket.create_connection((host, port), timeout=connect_timeout)
        self._sock.settimeout(None)  # no read timeout: analysis/decompilation can be slow
        self._reader = self._sock.makefile("r", encoding="utf-8", newline="\n")
        self._writer = self._sock.makefile("w", encoding="utf-8", newline="\n")
        self._id = 0

    def dispatch(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self._id += 1
        request = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}
        self._writer.write(json.dumps(request) + "\n")
        self._writer.flush()
        line = self._reader.readline()  # buffered: reassembles responses larger than one packet
        if not line:
            raise ConnectionError("server closed the connection")
        response = json.loads(line)
        if "error" in response:
            err = response["error"]
            raise RpcError(err.get("code"), err.get("message", ""), err.get("data"))
        return response["result"]

    def close(self) -> None:
        for closeable in (self._reader, self._writer, self._sock):
            with suppress(Exception):
                closeable.close()


def _parse_hostport(target: str) -> tuple[str, int]:
    host, sep, port = target.rpartition(":")
    if not sep:
        raise CliUsageError(f"invalid connect target {target!r}; expected HOST:PORT")
    try:
        port_num = int(port)
    except ValueError as exc:
        raise CliUsageError(f"invalid port in {target!r}") from exc
    return host or "127.0.0.1", port_num


def _connect_remote(host: str, port: int, *, version_check: bool) -> RemoteTransport:
    try:
        transport = RemoteTransport(host, port)
    except OSError as exc:
        raise CliUsageError(f"could not connect to {host}:{port}: {exc}") from exc
    if version_check:
        with suppress(Exception):
            info = transport.dispatch("initialize", {"protocolVersion": _DEFAULT_PROTOCOL})
            remote_version = (info.get("serverInfo") or {}).get("version")
            if remote_version and remote_version != __version__:
                print(
                    f"warning: server version {remote_version} differs from client {__version__}",
                    file=sys.stderr,
                )
    return transport


def _build_inprocess(args: argparse.Namespace) -> InProcessTransport:
    try:
        backend = build_backend(args)
    except RuntimeError as exc:
        raise CliUsageError(str(exc)) from exc
    return InProcessTransport(SimpleMcpServer(backend), owns_backend=True)


def _make_transport(
    args: argparse.Namespace, *, server: SimpleMcpServer | None = None
) -> InProcessTransport | RemoteTransport:
    if server is not None:
        return InProcessTransport(server, owns_backend=False)
    if args.in_process or args.fake_backend or args.ghidra_install_dir:
        return _build_inprocess(args)
    target = args.connect or os.environ.get("GHIDRA_CLI_CONNECT")
    if not target:
        live = _read_live_state()
        if live:
            target = f"{live['host']}:{live['port']}"
    if target:
        host, port = _parse_hostport(target)
        return _connect_remote(host, port, version_check=True)
    return _build_inprocess(args)


# --------------------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------------------


def _print_json(obj: Any) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def _print_value(value: Any) -> None:
    if isinstance(value, (dict, list)):
        print(json.dumps(value, sort_keys=True))
    elif isinstance(value, bool):
        print("true" if value else "false")
    elif value is None:
        print("null")
    else:
        print(value)


def _extract_path(obj: Any, dotpath: str) -> Any:
    current = obj
    for part in dotpath.split("."):
        if isinstance(current, dict):
            if part not in current:
                raise CliUsageError(f"field path not found: {dotpath!r}")
            current = current[part]
        elif isinstance(current, list):
            try:
                idx = int(part)
            except ValueError as exc:
                raise CliUsageError(f"field path not found: {dotpath!r}") from exc
            if not 0 <= idx < len(current):
                raise CliUsageError(f"field index out of range: {dotpath!r}")
            current = current[idx]
        else:
            raise CliUsageError(f"field path not found: {dotpath!r}")
    return current


def _emit_call_result(result: dict[str, Any], args: argparse.Namespace) -> int:
    is_error = bool(result.get("isError"))
    structured = result.get("structuredContent", {})
    if args.raw:
        _print_json(result)
    elif args.quiet:
        content = result.get("content") or [{}]
        print(content[0].get("text", "") if content else "")
    elif args.field:
        _print_value(_extract_path(structured, args.field))
    else:
        _print_json(structured)
    return EXIT_TOOL_ERROR if is_error else EXIT_OK


def _rpc_exit_code(exc: RpcError) -> int:
    return EXIT_USAGE if exc.code in _PROTOCOL_ERROR_CODES else EXIT_TOOL_ERROR


def _handle_rpc_error(exc: RpcError) -> int:
    detail = f" :: {exc.data}" if exc.data not in (None, "") else ""
    hint = (
        " (tool/method not present on this server -- version skew?)" if exc.code == -32601 else ""
    )
    print(f"error[{exc.code}]: {exc.message}{detail}{hint}", file=sys.stderr)
    return _rpc_exit_code(exc)


# --------------------------------------------------------------------------------------
# Command handlers
# --------------------------------------------------------------------------------------


def _maybe_session_hint(args: argparse.Namespace, transport: Any, result: dict[str, Any]) -> None:
    if not isinstance(transport, InProcessTransport) or result.get("isError"):
        return
    structured = result.get("structuredContent") or {}
    if args.tool in _OPEN_TOOLS and structured.get("session_id"):
        print(
            "note: in-process sessions are ephemeral; use a managed/remote server "
            "(ghidra_cli server start / --connect) or 'batch' for multi-step work",
            file=sys.stderr,
        )


def _cmd_call(args: argparse.Namespace, transport: Any) -> int:
    spec = SPECS.get(args.tool)
    if spec is None:
        _unknown_tool(args.tool)
    arguments = parse_tool_rest(args.rest, spec)
    _inject_session(arguments, spec, args.session_id)
    _validate_required(spec, arguments)
    result = transport.dispatch("tools/call", {"name": args.tool, "arguments": arguments})
    _maybe_session_hint(args, transport, result)
    return _emit_call_result(result, args)


def _cmd_raw(args: argparse.Namespace, transport: Any) -> int:
    if args.method == "shutdown" and not args.yes:
        raise CliUsageError(
            "refusing to send 'shutdown' without --yes (it tears down a shared server)"
        )
    if args.params_stdin:
        params = _parse_json(_read_stdin_once(), expect="object")
    elif args.params:
        params = _parse_json(args.params, expect="object")
    else:
        params = {}
    result = transport.dispatch(args.method, params)
    _print_json(result)
    if isinstance(result, dict) and result.get("isError"):
        return EXIT_TOOL_ERROR
    return EXIT_OK


def _filter_specs(args: argparse.Namespace) -> tuple[list[dict[str, Any]], int]:
    tools = list(ALL_TOOL_SPECS)
    if args.prefix:
        tools = [tool for tool in tools if tool["name"].startswith(args.prefix)]
    if args.query:
        needle = args.query.lower()
        tools = [
            tool
            for tool in tools
            if needle in tool["name"].lower() or needle in tool["description"].lower()
        ]
    total = len(tools)
    if args.offset:
        tools = tools[args.offset :]
    if args.limit is not None:
        tools = tools[: args.limit]
    return tools, total


def _cmd_list(args: argparse.Namespace) -> int:
    tools, total = _filter_specs(args)
    if args.names_only:
        for tool in tools:
            print(tool["name"])
        return EXIT_OK
    _print_json(
        {
            "total": total,
            "offset": args.offset or 0,
            "count": len(tools),
            "tools": [{"name": t["name"], "description": t["description"]} for t in tools],
        }
    )
    return EXIT_OK


def _tool_defaults(spec: dict[str, Any]) -> dict[str, Any]:
    backend_method = spec.get("backend_method")
    if not backend_method:
        return {}
    try:
        signature = inspect.signature(getattr(GhidraBackend, backend_method))
    except (AttributeError, ValueError, TypeError):
        return {}
    defaults: dict[str, Any] = {}
    for name, param in signature.parameters.items():
        if name == "self" or param.default is inspect.Parameter.empty:
            continue
        try:
            json.dumps(param.default)
            defaults[name] = param.default
        except TypeError:
            defaults[name] = repr(param.default)
    return defaults


def _cmd_describe(args: argparse.Namespace) -> int:
    spec = SPECS.get(args.tool)
    if spec is None:
        _unknown_tool(args.tool)
    _print_json(
        {
            "name": spec["name"],
            "description": spec["description"],
            "backend_method": spec.get("backend_method"),
            "required": list(spec.get("required", [])),
            "properties": spec.get("properties", {}),
            "defaults": _tool_defaults(spec),
        }
    )
    return EXIT_OK


def _batch_request(line: str, line_no: int) -> tuple[str, dict[str, Any]]:
    request = json.loads(line)
    tool = request.get("tool") or request.get("name")
    if not tool:
        raise CliUsageError(f"batch line {line_no}: missing 'tool'")
    if tool not in SPECS:
        _unknown_tool(tool)
    arguments = dict(request.get("arguments") or request.get("args") or {})
    return tool, arguments


def _run_batch_lines(stream: Any, args: argparse.Namespace, transport: Any) -> int:
    worst = EXIT_OK
    last_session = args.session_id
    opened: list[str] = []
    for line_no, line in enumerate(stream, 1):
        stripped = line.strip()
        if not stripped:
            continue
        tool, arguments = _batch_request(stripped, line_no)
        if (
            not args.no_autosession
            and "session_id" in SPECS[tool].get("properties", {})
            and "session_id" not in arguments
            and last_session
        ):
            arguments["session_id"] = last_session
        try:
            result = transport.dispatch("tools/call", {"name": tool, "arguments": arguments})
        except RpcError as exc:
            worst = max(worst, _rpc_exit_code(exc))
            print(
                json.dumps(
                    {
                        "line": line_no,
                        "tool": tool,
                        "error": {"code": exc.code, "message": exc.message},
                    },
                    sort_keys=True,
                )
            )
            if not args.continue_on_error:
                break
            continue
        structured = result.get("structuredContent") or {}
        session_id = structured.get("session_id")
        if session_id and not args.no_autosession:
            last_session = session_id
            if tool in _OPEN_TOOLS and session_id not in opened:
                opened.append(session_id)
        is_error = bool(result.get("isError"))
        if is_error:
            worst = max(worst, EXIT_TOOL_ERROR)
        print(
            json.dumps(
                {
                    "line": line_no,
                    "tool": tool,
                    "isError": is_error,
                    "structuredContent": structured,
                },
                sort_keys=True,
            )
        )
        if is_error and not args.continue_on_error:
            break
    if args.close_after:
        for session_id in opened:
            with suppress(Exception):
                transport.dispatch(
                    "tools/call",
                    {"name": "program.close", "arguments": {"session_id": session_id}},
                )
    return worst


def _cmd_batch(args: argparse.Namespace, transport: Any) -> int:
    if args.file == "-":
        return _run_batch_lines(sys.stdin, args, transport)
    with open(args.file, encoding="utf-8") as stream:
        return _run_batch_lines(stream, args, transport)


# --------------------------------------------------------------------------------------
# Managed background server
# --------------------------------------------------------------------------------------


def _state_dir() -> Path:
    base = os.environ.get("GHIDRA_CLI_HOME")
    if base:
        return Path(base)
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime:
        return Path(runtime) / "ghidra_cli"
    return Path.home() / ".cache" / "ghidra_cli"


def _state_path() -> Path:
    return _state_dir() / "server.json"


def _read_state() -> dict[str, Any] | None:
    path = _state_path()
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _write_state(state: dict[str, Any]) -> None:
    directory = _state_dir()
    directory.mkdir(parents=True, exist_ok=True)
    _state_path().write_text(json.dumps(state, indent=2), encoding="utf-8")


def _clear_state() -> None:
    with suppress(OSError):
        _state_path().unlink()


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _port_open(host: str, port: int, *, timeout: float = 0.3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _server_alive(state: dict[str, Any] | None) -> bool:
    if not state:
        return False
    return _pid_alive(state.get("pid", -1)) and _port_open(state["host"], state["port"])


def _read_live_state() -> dict[str, Any] | None:
    state = _read_state()
    return state if _server_alive(state) else None


def _server_env() -> dict[str, str]:
    env = os.environ.copy()
    root = str(Path(__file__).resolve().parents[1])
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = root if not existing else f"{root}{os.pathsep}{existing}"
    return env


def _server_command(args: argparse.Namespace) -> list[str]:
    cmd = [
        sys.executable,
        "-m",
        "ghidra_headless_mcp",
        "--transport",
        "tcp",
        "--host",
        args.host,
        "--port",
        str(args.port),
    ]
    if args.fake_backend:
        cmd.append("--fake-backend")
    if args.ghidra_install_dir:
        cmd += ["--ghidra-install-dir", args.ghidra_install_dir]
    if not args.deterministic:
        cmd.append("--no-deterministic")
    return cmd


def _server_start(args: argparse.Namespace) -> int:
    state = _read_state()
    if _server_alive(state):
        print(
            f"managed server already running at {state['host']}:{state['port']} (pid {state['pid']})"
        )
        return EXIT_OK
    directory = _state_dir()
    directory.mkdir(parents=True, exist_ok=True)
    log_handle = open(directory / "server.log", "ab")  # noqa: SIM115 (lives for the child process)
    proc = subprocess.Popen(
        _server_command(args),
        stdout=log_handle,
        stderr=log_handle,
        start_new_session=True,
        env=_server_env(),
    )
    deadline = time.time() + 20.0
    while time.time() < deadline:
        if proc.poll() is not None:
            raise CliUsageError(
                f"server exited early (rc={proc.returncode}); see {directory / 'server.log'}"
            )
        if _port_open(args.host, args.port):
            break
        time.sleep(0.1)
    else:
        proc.terminate()
        raise CliUsageError("server did not become ready in time")
    version = None
    with suppress(Exception):
        transport = RemoteTransport(args.host, args.port)
        info = transport.dispatch("initialize", {"protocolVersion": _DEFAULT_PROTOCOL})
        version = (info.get("serverInfo") or {}).get("version")
        transport.close()
    _write_state(
        {
            "pid": proc.pid,
            "host": args.host,
            "port": args.port,
            "version": version,
            "backend": "fake" if args.fake_backend else "real",
        }
    )
    print(f"managed server started at {args.host}:{args.port} (pid {proc.pid})")
    return EXIT_OK


def _server_stop(_args: argparse.Namespace) -> int:
    state = _read_state()
    if not state:
        print("no managed server recorded")
        return EXIT_OK
    pid = state.get("pid", -1)
    if _server_alive(state):
        with suppress(Exception):
            transport = RemoteTransport(state["host"], state["port"])
            transport.dispatch("shutdown", {})
            transport.close()
        deadline = time.time() + 5.0
        while time.time() < deadline and _pid_alive(pid):
            time.sleep(0.1)
        if _pid_alive(pid):
            with suppress(ProcessLookupError, PermissionError):
                os.kill(pid, signal.SIGTERM)
    _clear_state()
    print(f"managed server stopped (pid {pid})")
    return EXIT_OK


def _server_status(_args: argparse.Namespace) -> int:
    state = _read_state()
    if not state:
        _print_json({"running": False})
        return EXIT_OK
    if not _server_alive(state):
        _clear_state()
        _print_json({"running": False, "stale": True, **state})
        return EXIT_OK
    _print_json({"running": True, **state})
    return EXIT_OK


def _cmd_server(args: argparse.Namespace) -> int:
    if args.action == "start":
        return _server_start(args)
    if args.action == "stop":
        return _server_stop(args)
    if args.action == "status":
        return _server_status(args)
    if args.action == "restart":
        _server_stop(args)
        return _server_start(args)
    raise CliUsageError(f"unknown server action: {args.action}")


# --------------------------------------------------------------------------------------
# Argument parser and entry point
# --------------------------------------------------------------------------------------


def _add_suppressed_backend_args(parser: argparse.ArgumentParser) -> None:
    """Backend flags on the ``server`` subparser that default to the top-level values."""

    parser.add_argument("--fake-backend", action="store_true", default=argparse.SUPPRESS)
    parser.add_argument("--ghidra-install-dir", default=argparse.SUPPRESS)
    parser.add_argument(
        "--deterministic", action=argparse.BooleanOptionalAction, default=argparse.SUPPRESS
    )


def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ghidra_cli",
        description="Native command-line client for the Ghidra Headless MCP server.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--connect",
        metavar="HOST:PORT",
        help="Connect to a running TCP MCP server (persistent sessions).",
    )
    parser.add_argument(
        "--in-process",
        action="store_true",
        help="Force an in-process backend even if a managed server is live.",
    )
    add_backend_args(parser)
    parser.add_argument(
        "--session-id",
        default=os.environ.get("GHIDRA_CLI_SESSION"),
        help="Default session_id for tools that take one (env: GHIDRA_CLI_SESSION).",
    )
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--raw", action="store_true", help="Print the full tool-result envelope.")
    output.add_argument("--quiet", action="store_true", help="Print only the summary text line.")
    output.add_argument(
        "--field", metavar="DOTPATH", help="Print one value from structuredContent."
    )

    sub = parser.add_subparsers(dest="verb", required=True)

    call_parser = sub.add_parser("call", help="Invoke one tool.")
    call_parser.add_argument("tool")
    call_parser.add_argument("rest", nargs=argparse.REMAINDER)

    for verb in ("list", "tools"):
        list_parser = sub.add_parser(verb, help="List available tools.")
        list_parser.add_argument("--prefix")
        list_parser.add_argument("--query")
        list_parser.add_argument("--offset", type=int, default=0)
        list_parser.add_argument("--limit", type=int)
        list_parser.add_argument("--names-only", action="store_true")

    describe_parser = sub.add_parser("describe", help="Show a tool's description and parameters.")
    describe_parser.add_argument("tool")

    raw_parser = sub.add_parser(
        "raw", help="Send an arbitrary JSON-RPC method (bypasses coercion)."
    )
    raw_parser.add_argument("method")
    raw_group = raw_parser.add_mutually_exclusive_group()
    raw_group.add_argument("--params", help="Params as a JSON object.")
    raw_group.add_argument(
        "--params-stdin", action="store_true", help="Read params JSON from stdin."
    )
    raw_parser.add_argument(
        "--yes", action="store_true", help="Confirm dangerous methods (shutdown)."
    )

    batch_parser = sub.add_parser(
        "batch", help="Run a JSONL sequence of tool calls on one transport."
    )
    batch_parser.add_argument("file", nargs="?", default="-")
    batch_parser.add_argument("--continue-on-error", action="store_true")
    batch_parser.add_argument("--no-autosession", action="store_true")
    batch_parser.add_argument("--close-after", action="store_true")

    server_parser = sub.add_parser("server", help="Manage a background TCP MCP server.")
    server_parser.add_argument("action", choices=["start", "stop", "status", "restart"])
    server_parser.add_argument("--host", default="127.0.0.1")
    server_parser.add_argument("--port", type=int, default=8765)
    _add_suppressed_backend_args(server_parser)

    return parser


_TRANSPORT_VERBS = {"call": _cmd_call, "raw": _cmd_raw, "batch": _cmd_batch}


def _run(args: argparse.Namespace, server: SimpleMcpServer | None) -> int:
    if args.verb in ("list", "tools"):
        return _cmd_list(args)
    if args.verb == "describe":
        return _cmd_describe(args)
    if args.verb == "server":
        return _cmd_server(args)
    handler = _TRANSPORT_VERBS[args.verb]
    transport = _make_transport(args, server=server)
    try:
        return handler(args, transport)
    finally:
        transport.close()


def main(argv: list[str] | None = None, *, server: SimpleMcpServer | None = None) -> int:
    """Entry point. ``server`` injects a pre-built :class:`SimpleMcpServer` (used by tests)."""

    _STDIN_CACHE.clear()
    args = build_cli_parser().parse_args(argv)
    try:
        return _run(args, server)
    except CliUsageError as exc:
        print(f"usage error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except RpcError as exc:
        return _handle_rpc_error(exc)
    except json.JSONDecodeError as exc:
        print(f"usage error: invalid JSON: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except ConnectionError as exc:
        print(f"connection error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
