# ghidra_cli Command Reference

Agent-facing reference for `ghidra_cli`, the native command-line client for the Ghidra Headless
MCP server. It exposes **all 212 MCP tools** through one binary so an agent that does not speak
the MCP protocol can call every capability with a plain command. The client dispatches through the
same code path as the MCP server, so a CLI call and the equivalent MCP `tools/call` return identical
results.

> This file is generated from the live tool registry (`ALL_TOOL_SPECS` + `GhidraBackend`
> signatures). The runtime equivalents are always authoritative: `ghidra_cli list` enumerates every
> tool and `ghidra_cli describe <tool>` prints a tool's full schema, parameters, types, and defaults.

## Contents

1. [Invocation](#invocation)
2. [Transports and session state](#transports-and-session-state)
3. [Global options](#global-options)
4. [Verbs](#verbs)
5. [Argument syntax and coercion](#argument-syntax-and-coercion)
6. [Output and exit codes](#output-and-exit-codes)
7. [Security](#security)
8. [Tool reference](#tool-reference) — all 212 tools

## Invocation

Installed console script (after `pip install .`):

```bash
ghidra_cli <verb> ...        # or the kebab-case alias: ghidra-cli
```

Straight from a checkout, no install:

```bash
cd /path/to/ghidra-headless-mcp
PYTHONPATH=. python3 -m ghidra_headless_mcp.ghidra_cli <verb> ...
```

All examples below use the `ghidra_cli` name.

## Transports and session state

Tools are stateful: most take a `session_id` returned by `program.open`, and that session lives in
the backend that served it. The client picks a transport per invocation:

- **In-process** — builds a backend inside the CLI process and dispatches directly. State is
  **ephemeral**: a `session_id` returned by one command is gone in the next process. Good for
  stateless calls, CI, and self-contained `batch` runs. Selected by `--fake-backend`,
  `--ghidra-install-dir`, or `--in-process`.
- **Remote / managed** — a JSON-RPC/TCP client to a long-lived server, so **session state persists**
  across invocations. This is the right mode for multi-step reverse engineering and the only
  practical mode for the real backend (slow JVM startup). Selected by `--connect HOST:PORT`, the
  `GHIDRA_CLI_CONNECT` env var, or an auto-detected managed server (`ghidra_cli server start`).

**Transport precedence:** `--fake-backend` / `--ghidra-install-dir` / `--in-process` →
`--connect` → `$GHIDRA_CLI_CONNECT` → a live managed server → in-process real backend
(needs `$GHIDRA_INSTALL_DIR`). `ghidra_cli list` and `ghidra_cli describe` answer locally and need
no transport.

Typical real workflow:

```bash
ghidra_cli --ghidra-install-dir /opt/ghidra server start    # start once
SID=$(ghidra_cli --field session_id call program.open --path /bin/ls)
ghidra_cli call function.list --session_id "$SID" --limit 50  # auto-connects to the managed server
ghidra_cli server stop
```

Set `export GHIDRA_CLI_SESSION="$SID"` to make `--session_id` implicit for every call.

## Global options

These appear **before** the verb:

| Option | Meaning |
| --- | --- |
| `--connect HOST:PORT` | Use a running TCP server (persistent sessions). |
| `--fake-backend` | In-process fake backend (no Ghidra; for tests/demos). |
| `--ghidra-install-dir DIR` | In-process real backend (else `$GHIDRA_INSTALL_DIR`). |
| `--in-process` | Force in-process even if a managed server is live. |
| `--[no-]deterministic` | Deterministic startup (default on). |
| `--session-id ID` | Default `session_id` (else `$GHIDRA_CLI_SESSION`). |
| `--raw` | Print the full result envelope (`content` + `structuredContent` + `isError`). |
| `--quiet` | Print only the summary text line. |
| `--field DOTPATH` | Print one value from `structuredContent` (e.g. `session_id`, `items.0.name`). |
| `--version` | Print version and exit. |

## Verbs

### `call <tool> [--param value ...]`
Invoke one tool. Parameters are derived from the tool's schema (see [Tool reference](#tool-reference)).
```bash
ghidra_cli call function.list --session_id <id> --limit 20
```

### `list` (alias `tools`)
List available tools. `--prefix P`, `--query Q` (name/description substring), `--offset N`,
`--limit N`, `--names-only`. Answers locally; no transport needed.
```bash
ghidra_cli list --query decomp
ghidra_cli list --names-only | wc -l    # 212
```

### `describe <tool>`
Show a tool's description plus every parameter with type, required-ness, and default.
```bash
ghidra_cli describe function.signature.set
```

### `raw <method> [--params JSON | --params-stdin] [--yes]`
Send an arbitrary JSON-RPC method (`initialize`, `tools/list`, `tools/call`, `ping`, `shutdown`).
Bypasses all argument coercion. `shutdown` requires `--yes`.
```bash
ghidra_cli raw tools/list --params '{"prefix": "decomp."}'
```

### `batch [FILE|-] [--continue-on-error] [--no-autosession] [--close-after]`
Run a JSONL stream of `{"tool": ..., "arguments": {...}}` against one transport, in order. The most
recent `session_id` seen in output is auto-threaded into later lines, so a multi-step sequence runs
against one backend without a server. One result object is printed per line; default is fail-fast.
```bash
printf '%s\n' \
  '{"tool":"program.open","arguments":{"path":"/bin/ls"}}' \
  '{"tool":"function.list","arguments":{"limit":5}}' | ghidra_cli --fake-backend batch -
```

### `server start|stop|status|restart [--host H] [--port P]`
Manage a long-lived background TCP server (records pid/host/port in a state file). Once running,
`call`/`batch`/`raw` auto-connect to it. Backend selection uses the global `--fake-backend` /
`--ghidra-install-dir` flags.
```bash
ghidra_cli --fake-backend server start --port 8765
ghidra_cli server status
ghidra_cli server stop
```

## Argument syntax and coercion

Each tool parameter maps to a `--flag`. Dashes and underscores are interchangeable (`--read-only`
== `--read_only`). Values are coerced from the parameter's schema type:

| Type | How to pass | Notes |
| --- | --- | --- |
| `string` | `--name main` | verbatim |
| `int` | `--limit 50`, `--limit 0x20` | accepts `0x`/`0o`/`0b`, else decimal; negatives ok |
| `bool` | `--read_only false` or bare `--read_only` | true/false/yes/no/on/off/1/0 |
| `number` | `--threshold 1.5` | |
| `address` | `--function_start 0x401000` | **passed as a string**; Ghidra reads a bare-digit address as hex. For a decimal int use `--function_start:int 4198400`. |
| `array<...>` | `--values 1 --values 2` | repeat the flag; or `--values:json '[1,2]'` |
| `object` | `--kwargs:json '{"k":1}'` | JSON only |
| `any` | `--value 5` | passed as a string by default; the backend coerces |

Extra forms:

- **Full-args escape:** `--json '{...}'` (or `--json-stdin`) sets the entire arguments object; any
  individual `--flag` overrides keys on top of it.
- **Typed overrides:** `--key:TYPE value` with `TYPE` in `str|int|float|bool|json|null`.
  `--key:null` sets JSON `null` (e.g. `variable.comment.set --comment:null` clears a comment).
- **Value sources:** `--code @script.py` reads a file; `--code -` reads stdin. Keeps large or secret
  values out of `argv`, process listings, and shell history.
- Values that begin with `--` must use the `=` form: `--query=--literal`.

## Output and exit codes

stdout carries the payload only (diagnostics go to stderr). By default the tool's
`structuredContent` is printed as pretty JSON; use `--raw`, `--quiet`, or `--field DOTPATH` to
change that.

| Exit code | Meaning |
| --- | --- |
| `0` | success |
| `1` | the tool ran but reported an error (`isError`) |
| `2` | usage/client error (unknown tool, bad flag/value, malformed `--json`) or connection/transport failure |

## Security

All tools are available with no extra flag — including `ghidra.eval`, `ghidra.call`, and
`ghidra.script`, which execute arbitrary Python/Java/scripts inside the Ghidra runtime. The
TCP/managed server binds `127.0.0.1` only and has **no authentication**: anyone with localhost
access can run arbitrary code through it. Prefer `@file`/stdin value sources for code and secrets so
they never appear in `argv`. `raw shutdown` against a shared server requires `--yes`.

## Tool reference

Every tool below is callable as `ghidra_cli call <tool> ...`. Required parameters have no brackets;
optional ones are shown in `[...]` with their default where one exists. `address` parameters take
either `0x`-prefixed or bare-hex strings (Ghidra parsing). Run `ghidra_cli describe <tool>` for the
authoritative live schema.


### health — liveness

#### `health.ping`
Confirm that the server is reachable and responding.

```
ghidra_cli call health.ping
```


### mcp — protocol help

#### `mcp.response_format`
Explain how MCP tool responses split full structured data and human-readable summary text.

```
ghidra_cli call mcp.response_format
```


### ghidra — scripting and runtime bridge

#### `ghidra.call`
Invoke Ghidra or Java APIs directly through a generic bridge.

```
ghidra_cli call ghidra.call --target <string> [--args <array<any>=null>] [--kwargs <object=null>] [--session_id <string=null>]
```

#### `ghidra.eval`
Evaluate Python code inside the live Ghidra runtime context.

```
ghidra_cli call ghidra.eval --code <string> [--session_id <string=null>]
```

#### `ghidra.info`
Return runtime information about Ghidra, PyGhidra, and the server environment.

```
ghidra_cli call ghidra.info
```

#### `ghidra.script`
Run a Ghidra script against an open program session.

```
ghidra_cli call ghidra.script --path <string> [--session_id <string=null>] [--script_args <array<string>=null>]
```


### analysis — auto-analysis and options

#### `analysis.analyzers.list`
List boolean analyzers available for the current program and show whether each one is enabled.

```
ghidra_cli call analysis.analyzers.list --session_id <string> [--offset <int=0>] [--limit <int=100>] [--query <string=null>]
```

#### `analysis.analyzers.set`
Enable or disable a specific boolean analyzer for the current program.

```
ghidra_cli call analysis.analyzers.set --session_id <string> --name <string> --enabled <bool>
```

#### `analysis.clear_cache`
Clear cached decompiler state for the current session so later requests rebuild it cleanly.

```
ghidra_cli call analysis.clear_cache --session_id <string>
```

#### `analysis.options.get`
Return the current value of a specific analysis option.

```
ghidra_cli call analysis.options.get --session_id <string> --name <string>
```

#### `analysis.options.list`
List available analysis options together with their current values.

```
ghidra_cli call analysis.options.list --session_id <string> [--offset <int=0>] [--limit <int=100>] [--query <string=null>]
```

#### `analysis.options.set`
Update the value of an analysis option for the current session.

```
ghidra_cli call analysis.options.set --session_id <string> --name <string> --value <any>
```

#### `analysis.status`
Return the current auto-analysis status for the session.

```
ghidra_cli call analysis.status --session_id <string>
```

#### `analysis.update`
Start auto-analysis in the background and return immediately.

```
ghidra_cli call analysis.update --session_id <string>
```

#### `analysis.update_and_wait`
Run auto-analysis and wait until it completes.

```
ghidra_cli call analysis.update_and_wait --session_id <string>
```


### task — asynchronous tasks

#### `task.analysis_update`
Start auto-analysis as a tracked background task and return a task ID.

```
ghidra_cli call task.analysis_update --session_id <string>
```

#### `task.cancel`
Request cancellation for a running or queued asynchronous task.

```
ghidra_cli call task.cancel --task_id <string>
```

#### `task.result`
Return the terminal result or error payload for a completed task.

```
ghidra_cli call task.result --task_id <string>
```

#### `task.status`
Return status, timing, and cancellation details for an asynchronous task.

```
ghidra_cli call task.status --task_id <string>
```


### program — program/session lifecycle

#### `program.close`
Close an open program session and release its associated resources.

```
ghidra_cli call program.close --session_id <string>
```

#### `program.export_binary`
Export the program to disk as either the original-file format or raw bytes.

```
ghidra_cli call program.export_binary --session_id <string> --path <string> [--format <string=original_file>]
```

#### `program.image_base.set`
Change the program image base and optionally commit the rebasing operation.

```
ghidra_cli call program.image_base.set --session_id <string> --image_base <address> [--commit <bool=true>]
```

#### `program.list_open`
List all program sessions currently held open by the server.

```
ghidra_cli call program.list_open
```

#### `program.mode.get`
Return whether a session is currently read-only or read-write.

```
ghidra_cli call program.mode.get --session_id <string>
```

#### `program.mode.set`
Switch a session between read-only and read-write mode.

```
ghidra_cli call program.mode.set --session_id <string> [--read_only <bool=null>] [--deterministic <bool=null>]
```

#### `program.open`
Open a binary file for analysis and return a new session.

```
ghidra_cli call program.open --path <string> [--update_analysis <bool=true>] [--read_only <bool=true>] [--project_location <string=null>] [--project_name <string=null>] [--program_name <string=null>] [--language <string=null>] [--compiler <string=null>] [--loader <string=null>]
```

#### `program.open_bytes`
Open a binary from base64-encoded bytes and return a new session.

```
ghidra_cli call program.open_bytes --data_base64 <string> [--filename <string=session.bin>] [--update_analysis <bool=true>] [--read_only <bool=true>] [--project_location <string=null>] [--project_name <string=null>] [--program_name <string=null>] [--language <string=null>] [--compiler <string=null>] [--loader <string=null>]
```

#### `program.report`
Return a compact program report with counts plus sample functions, strings, imports, and memory blocks.

```
ghidra_cli call program.report --session_id <string>
```

#### `program.save`
Save the current program state back into the project.

```
ghidra_cli call program.save --session_id <string>
```

#### `program.save_as`
Save the current program under a new project path or name.

```
ghidra_cli call program.save_as --session_id <string> --program_name <string> [--folder_path <string=/>] [--overwrite <bool=true>]
```

#### `program.summary`
Return core program metadata such as architecture, memory layout, and entry point.

```
ghidra_cli call program.summary --session_id <string>
```


### project — project navigation

#### `project.export`
Export the current Ghidra project artifacts to a destination directory.

```
ghidra_cli call project.export --session_id <string> --destination <string>
```

#### `project.file.info`
Return metadata and state flags for a specific project file.

```
ghidra_cli call project.file.info --session_id <string> --path <string>
```

#### `project.files.list`
List project files with folder, content-type, query, and pagination filters.

```
ghidra_cli call project.files.list --session_id <string> [--folder_path <string=/>] [--recursive <bool=false>] [--content_type <string=null>] [--query <string=null>] [--offset <int=0>] [--limit <int=100>]
```

#### `project.folders.list`
List project folders, optionally walking the tree recursively.

```
ghidra_cli call project.folders.list --session_id <string> [--folder_path <string=/>] [--recursive <bool=false>]
```

#### `project.program.open`
Open a program already stored in the current project and return a new session.

```
ghidra_cli call project.program.open --session_id <string> --path <string> [--read_only <bool=null>] [--update_analysis <bool=false>]
```

#### `project.program.open_existing`
Open a program from a named existing Ghidra project and return a new session.

```
ghidra_cli call project.program.open_existing --project_location <string> --project_name <string> [--program_path <string=null>] [--folder_path <string=/>] [--program_name <string=null>] [--read_only <bool=true>] [--update_analysis <bool=false>]
```

#### `project.search.programs`
Search program files in the project by name or path.

```
ghidra_cli call project.search.programs --session_id <string> [--query <string=null>] [--content_type <string=null>] [--offset <int=0>] [--limit <int=100>]
```


### transaction — undo/redo grouping

#### `transaction.begin`
Begin an explicit undo transaction for grouped changes.

```
ghidra_cli call transaction.begin --session_id <string> [--description <string=MCP Transaction>]
```

#### `transaction.commit`
Commit the active transaction so its changes become undoable.

```
ghidra_cli call transaction.commit --session_id <string>
```

#### `transaction.redo`
Reapply the most recently undone change.

```
ghidra_cli call transaction.redo --session_id <string>
```

#### `transaction.revert`
Roll back the active transaction without committing it.

```
ghidra_cli call transaction.revert --session_id <string>
```

#### `transaction.status`
Return undo, redo, and active-transaction status for the session.

```
ghidra_cli call transaction.status --session_id <string>
```

#### `transaction.undo`
Undo the most recently committed change.

```
ghidra_cli call transaction.undo --session_id <string>
```


### memory — memory blocks and bytes

#### `memory.block.create`
Create a memory block with permissions, initialization, and an optional comment.

```
ghidra_cli call memory.block.create --session_id <string> --name <string> --address <address> --length <int> [--initialized <bool=true>] [--fill <int=0>] [--read <bool=true>] [--write <bool=false>] [--execute <bool=false>] [--comment <string=null>]
```

#### `memory.block.remove`
Remove an existing memory block from the program.

```
ghidra_cli call memory.block.remove --session_id <string> [--name <string=null>] [--address <address=null>]
```

#### `memory.blocks.list`
List memory blocks together with addresses, permissions, and sizes.

```
ghidra_cli call memory.blocks.list --session_id <string>
```

#### `memory.read`
Read raw bytes directly from program memory.

```
ghidra_cli call memory.read --session_id <string> --address <address> --length <int>
```

#### `memory.write`
Write raw bytes directly into program memory.

```
ghidra_cli call memory.write --session_id <string> --address <address> [--data_base64 <string=null>] [--data_hex <string=null>]
```


### listing — code units, data, disassembly

#### `listing.clear`
Clear listing content over a range, including optional symbols, comments, references, functions, or context.

```
ghidra_cli call listing.clear --session_id <string> --start <address> [--end <address=null>] [--length <int=null>] [--clear_context <bool=false>] [--clear_symbols <bool=false>] [--clear_comments <bool=false>] [--clear_properties <bool=false>] [--clear_functions <bool=false>] [--clear_registers <bool=false>] [--clear_equates <bool=false>] [--clear_user_references <bool=false>] [--clear_analysis_references <bool=false>] [--clear_import_references <bool=false>] [--clear_default_references <bool=false>] [--clear_bookmarks <bool=false>]
```

#### `listing.code_unit.after`
Return the nearest code unit that follows a given address.

```
ghidra_cli call listing.code_unit.after --session_id <string> --address <address>
```

#### `listing.code_unit.at`
Return the code unit that starts exactly at a given address.

```
ghidra_cli call listing.code_unit.at --session_id <string> --address <address>
```

#### `listing.code_unit.before`
Return the nearest code unit that precedes a given address.

```
ghidra_cli call listing.code_unit.before --session_id <string> --address <address>
```

#### `listing.code_unit.containing`
Return the code unit that contains a given address.

```
ghidra_cli call listing.code_unit.containing --session_id <string> --address <address>
```

#### `listing.code_units.list`
List code units in a range with pagination and direction controls.

```
ghidra_cli call listing.code_units.list --session_id <string> [--start <address=null>] [--end <address=null>] [--offset <int=0>] [--limit <int=100>] [--forward <bool=true>]
```

#### `listing.data.at`
Return the defined data item at a specific address.

```
ghidra_cli call listing.data.at --session_id <string> --address <address>
```

#### `listing.data.clear`
Clear one or more data definitions starting at an address.

```
ghidra_cli call listing.data.clear --session_id <string> --address <address> [--length <int=1>]
```

#### `listing.data.create`
Create a data definition of a chosen type at an address.

```
ghidra_cli call listing.data.create --session_id <string> --address <address> --data_type <string> [--length <int=null>] [--clear_existing <bool=true>]
```

#### `listing.data.list`
List defined data items in the program with range and pagination controls.

```
ghidra_cli call listing.data.list --session_id <string> [--offset <int=0>] [--limit <int=100>]
```

#### `listing.disassemble.function`
Disassemble all instructions that belong to a function body.

```
ghidra_cli call listing.disassemble.function --session_id <string> --address <address> [--limit <int=500>]
```

#### `listing.disassemble.range`
Disassemble instructions across a selected address range.

```
ghidra_cli call listing.disassemble.range --session_id <string> --start <address> --length <int> [--limit <int=200>]
```

#### `listing.disassemble.seed`
Start disassembly from a seed address and follow discovered flows.

```
ghidra_cli call listing.disassemble.seed --session_id <string> --address <address> [--limit <int=128>] [--clear_existing <bool=false>]
```


### context — processor context registers

#### `context.get`
Return processor context register values at a specific address.

```
ghidra_cli call context.get --session_id <string> --register <string> --address <address> [--signed <bool=false>]
```

#### `context.ranges`
List address ranges where a processor context register value applies.

```
ghidra_cli call context.ranges --session_id <string> --register <string> [--start <address=null>] [--end <address=null>]
```

#### `context.set`
Set processor context register values across an address range.

```
ghidra_cli call context.set --session_id <string> --register <string> --start <address> [--end <address=null>] [--length <int=null>] [--value <address=null>] [--clear <bool=false>]
```


### patch — assemble / nop / branch

#### `patch.assemble`
Assemble instruction text at an address and write the resulting bytes.

```
ghidra_cli call patch.assemble --session_id <string> --address <address> --assembly <string>
```

#### `patch.branch_invert`
Invert a conditional branch instruction in place.

```
ghidra_cli call patch.branch_invert --session_id <string> --address <address>
```

#### `patch.nop`
Replace instructions in a range with NOP bytes.

```
ghidra_cli call patch.nop --session_id <string> --address <address> [--count <int=1>]
```


### symbol — symbols and labels

#### `symbol.by_name`
Look up a symbol by name and return its details.

```
ghidra_cli call symbol.by_name --session_id <string> --name <string> [--exact <bool=false>] [--limit <int=20>] [--include_dynamic <bool=true>]
```

#### `symbol.create`
Create a new symbol or label at an address.

```
ghidra_cli call symbol.create --session_id <string> --address <address> --name <string> [--make_primary <bool=true>]
```

#### `symbol.delete`
Delete a symbol at an address, optionally by name.

```
ghidra_cli call symbol.delete --session_id <string> --address <address> [--name <string=null>]
```

#### `symbol.list`
List symbols with filtering and pagination support.

```
ghidra_cli call symbol.list --session_id <string> [--offset <int=0>] [--limit <int=100>] [--include_dynamic <bool=false>] [--query <string=null>]
```

#### `symbol.namespace.move`
Move a symbol into a different namespace.

```
ghidra_cli call symbol.namespace.move --session_id <string> --address <address> --namespace <string> [--name <string=null>]
```

#### `symbol.primary.set`
Mark a selected symbol as the primary symbol at its address.

```
ghidra_cli call symbol.primary.set --session_id <string> --address <address> [--name <string=null>]
```

#### `symbol.rename`
Rename an existing symbol.

```
ghidra_cli call symbol.rename --session_id <string> --address <address> --new_name <string> [--old_name <string=null>]
```


### namespace — namespaces

#### `namespace.create`
Create a namespace under an optional parent namespace.

```
ghidra_cli call namespace.create --session_id <string> --name <string> [--parent <string=null>]
```


### class — class namespaces

#### `class.create`
Create a class namespace for recovered methods or fields.

```
ghidra_cli call class.create --session_id <string> --name <string> [--parent <string=null>]
```


### external — libraries, imports, exports, externals

#### `external.entrypoint.add`
Add an address to the program's external entry point set.

```
ghidra_cli call external.entrypoint.add --session_id <string> --address <address>
```

#### `external.entrypoint.list`
List addresses currently marked as external entry points.

```
ghidra_cli call external.entrypoint.list --session_id <string>
```

#### `external.entrypoint.remove`
Remove an address from the external entry point set.

```
ghidra_cli call external.entrypoint.remove --session_id <string> --address <address>
```

#### `external.exports.list`
List symbols exported by the program.

```
ghidra_cli call external.exports.list --session_id <string> [--offset <int=0>] [--limit <int=100>]
```

#### `external.function.create`
Create an external function symbol under an external location.

```
ghidra_cli call external.function.create --session_id <string> --library_name <string> --name <string> [--external_address <address=null>]
```

#### `external.imports.list`
List symbols imported by the program.

```
ghidra_cli call external.imports.list --session_id <string> [--offset <int=0>] [--limit <int=100>]
```

#### `external.library.create`
Create a new external library record.

```
ghidra_cli call external.library.create --session_id <string> --name <string>
```

#### `external.library.list`
List external libraries known to the program.

```
ghidra_cli call external.library.list --session_id <string>
```

#### `external.library.set_path`
Set or update the filesystem path associated with an external library.

```
ghidra_cli call external.library.set_path --session_id <string> --name <string> --path <string> [--user_defined <bool=true>]
```

#### `external.location.create`
Create an external location for a symbol within a library.

```
ghidra_cli call external.location.create --session_id <string> --library_name <string> [--label <string=null>] [--external_address <address=null>]
```

#### `external.location.get`
Return details for a specific external location.

```
ghidra_cli call external.location.get --session_id <string> [--address <address=null>] [--name <string=null>]
```


### reference — cross-references

#### `reference.association.remove`
Remove the symbol association attached to a specific reference.

```
ghidra_cli call reference.association.remove --session_id <string> --from_address <address> --to_address <address> [--operand_index <int=0>]
```

#### `reference.association.set`
Associate a specific reference with a symbol.

```
ghidra_cli call reference.association.set --session_id <string> --from_address <address> --to_address <address> [--operand_index <int=0>] --symbol_address <address> [--symbol_name <string=null>]
```

#### `reference.clear_from`
Remove references originating from one address or an address range.

```
ghidra_cli call reference.clear_from --session_id <string> --from_address <address> [--end_address <address=null>]
```

#### `reference.clear_to`
Remove all references that target a specific address.

```
ghidra_cli call reference.clear_to --session_id <string> --to_address <address>
```

#### `reference.create.external`
Create a reference from an address to an external location.

```
ghidra_cli call reference.create.external --session_id <string> --from_address <address> --library_name <string> [--label <string=null>] [--external_address <address=null>] [--reference_type <string=DATA>] [--operand_index <int=0>] [--source_type <string=USER_DEFINED>]
```

#### `reference.create.memory`
Create a memory reference between two program addresses.

```
ghidra_cli call reference.create.memory --session_id <string> --from_address <address> --to_address <address> [--reference_type <string=DATA>] [--operand_index <int=0>] [--source_type <string=USER_DEFINED>]
```

#### `reference.create.register`
Create a reference from an address to a register.

```
ghidra_cli call reference.create.register --session_id <string> --from_address <address> --register <string> [--reference_type <string=DATA>] [--operand_index <int=0>] [--source_type <string=USER_DEFINED>]
```

#### `reference.create.stack`
Create a reference from an address to a stack location.

```
ghidra_cli call reference.create.stack --session_id <string> --from_address <address> --stack_offset <int> [--reference_type <string=DATA>] [--operand_index <int=0>] [--source_type <string=USER_DEFINED>]
```

#### `reference.delete`
Delete a specific reference selected by source, destination, and operand.

```
ghidra_cli call reference.delete --session_id <string> --from_address <address> [--to_address <address=null>] [--operand_index <int=null>]
```

#### `reference.from`
List cross-references that originate from an address.

```
ghidra_cli call reference.from --session_id <string> [--address <address=null>] [--start <address=null>] [--end <address=null>] [--limit <int=100>]
```

#### `reference.primary.set`
Mark a specific reference as the primary one for its operand.

```
ghidra_cli call reference.primary.set --session_id <string> --from_address <address> --to_address <address> [--operand_index <int=0>]
```

#### `reference.to`
List cross-references that target an address.

```
ghidra_cli call reference.to --session_id <string> [--address <address=null>] [--start <address=null>] [--end <address=null>] [--limit <int=100>]
```


### equate — operand equates

#### `equate.clear_range`
Remove equate references across an address range and delete empty equates.

```
ghidra_cli call equate.clear_range --session_id <string> --start <address> [--end <address=null>] [--length <int=null>]
```

#### `equate.create`
Create an equate and attach it to an operand at an address.

```
ghidra_cli call equate.create --session_id <string> --address <address> --name <string> --value <address> [--operand_index <int=0>]
```

#### `equate.delete`
Delete an equate entirely, or remove one of its references before deletion.

```
ghidra_cli call equate.delete --session_id <string> --name <string> [--address <address=null>] [--operand_index <int=null>]
```

#### `equate.list`
List equates together with values and attached references.

```
ghidra_cli call equate.list --session_id <string> [--name <string=null>] [--address <address=null>] [--operand_index <int=null>] [--offset <int=0>] [--limit <int=100>]
```


### comment — comments

#### `comment.get`
Return one comment type from a specific address.

```
ghidra_cli call comment.get --session_id <string> [--address <address=null>] [--comment_type <string=eol>] [--function_start <address=null>] [--scope <string=listing>]
```

#### `comment.get_all`
Return all available comment types at an address, with optional function comments.

```
ghidra_cli call comment.get_all --session_id <string> --address <address> [--include_function <bool=true>]
```

#### `comment.list`
List comments matching range, type, text, and pagination filters.

```
ghidra_cli call comment.list --session_id <string> [--start <address=null>] [--end <address=null>] [--comment_type <string=null>] [--query <string=null>] [--case_sensitive <bool=false>] [--offset <int=0>] [--limit <int=100>]
```

#### `comment.set`
Set or clear a comment of a selected type at an address.

```
ghidra_cli call comment.set --session_id <string> --comment <string> [--address <address=null>] [--comment_type <string=eol>] [--function_start <address=null>] [--scope <string=listing>]
```


### bookmark — bookmarks

#### `bookmark.add`
Add a bookmark at an address with a type, category, and comment.

```
ghidra_cli call bookmark.add --session_id <string> --address <address> --category <string> --comment <string> [--bookmark_type <string=NOTE>]
```

#### `bookmark.clear`
Remove bookmarks in an address range, optionally filtered by bookmark type.

```
ghidra_cli call bookmark.clear --session_id <string> --start <address> [--end <address=null>] [--length <int=null>] [--bookmark_type <string=null>]
```

#### `bookmark.list`
List bookmarks, optionally scoped to an address or bookmark type.

```
ghidra_cli call bookmark.list --session_id <string> [--address <address=null>] [--bookmark_type <string=null>] [--offset <int=0>] [--limit <int=100>]
```

#### `bookmark.remove`
Remove bookmarks at an address, optionally filtered by type or category.

```
ghidra_cli call bookmark.remove --session_id <string> --address <address> [--bookmark_type <string=null>] [--category <string=null>]
```


### tag — function tags

#### `tag.add`
Create or reuse a function tag and attach it to a function.

```
ghidra_cli call tag.add --session_id <string> --function_start <address> --name <string> [--comment <string=>]
```

#### `tag.list`
List tags for one function or across the whole program.

```
ghidra_cli call tag.list --session_id <string> [--function_start <address=null>]
```

#### `tag.remove`
Remove a function tag from a function.

```
ghidra_cli call tag.remove --session_id <string> --function_start <address> --name <string>
```

#### `tag.stats`
Summarize function tags and the number of functions using each one.

```
ghidra_cli call tag.stats --session_id <string>
```


### metadata — persistent metadata

#### `metadata.query`
Read metadata entries stored by this server, optionally filtered by key or prefix.

```
ghidra_cli call metadata.query --session_id <string> [--key <string=null>] [--prefix <string=null>] [--offset <int=0>] [--limit <int=100>]
```

#### `metadata.store`
Store a JSON-serializable metadata value under a program-scoped key.

```
ghidra_cli call metadata.store --session_id <string> --key <string> --value <any>
```


### source — source files and source maps

#### `source.file.add`
Register a source file record with the program's source file manager.

```
ghidra_cli call source.file.add --session_id <string> --path <string> [--id_type <string=null>] [--identifier_hex <string=null>]
```

#### `source.file.list`
List all source files currently registered with the program.

```
ghidra_cli call source.file.list --session_id <string>
```

#### `source.file.remove`
Remove a source file record by path.

```
ghidra_cli call source.file.remove --session_id <string> --path <string>
```

#### `source.map.add`
Add a source mapping entry from a source line to an address range.

```
ghidra_cli call source.map.add --session_id <string> --path <string> --line_number <int> --base_address <address> --length <int>
```

#### `source.map.list`
List source mapping entries by address, source file, or line filters.

```
ghidra_cli call source.map.list --session_id <string> [--address <address=null>] [--path <string=null>] [--min_line <int=null>] [--max_line <int=null>]
```

#### `source.map.remove`
Remove a specific source mapping entry by file, line, and base address.

```
ghidra_cli call source.map.remove --session_id <string> --path <string> --line_number <int> --base_address <address>
```


### relocation — relocations

#### `relocation.add`
Add a relocation entry at an address with type, status, values, and symbol metadata.

```
ghidra_cli call relocation.add --session_id <string> --address <address> [--status <string=APPLIED>] [--type <int=0>] [--values <array<int>=null>] [--byte_length <int=0>] [--symbol_name <string=null>]
```

#### `relocation.list`
List relocation entries, optionally limited to an address range.

```
ghidra_cli call relocation.list --session_id <string> [--start <address=null>] [--end <address=null>]
```


### function — functions and signatures

#### `function.at`
Return the function that starts at, or contains, a specific address.

```
ghidra_cli call function.at --session_id <string> --address <address>
```

#### `function.batch.run`
Run one supported action across a filtered batch of functions.

```
ghidra_cli call function.batch.run --session_id <string> --action <string> [--query <string=null>] [--offset <int=0>] [--limit <int=50>] [--timeout_secs <int=30>]
```

#### `function.body.set`
Replace the body range of an existing function.

```
ghidra_cli call function.body.set --session_id <string> --function_start <address> --start <address> [--end <address=null>] [--length <int=null>]
```

#### `function.by_name`
Look up a function by name and return its details.

```
ghidra_cli call function.by_name --session_id <string> --name <string> [--exact <bool=false>] [--limit <int=20>]
```

#### `function.callees`
List the functions called by a specific function.

```
ghidra_cli call function.callees --session_id <string> --function_start <address>
```

#### `function.callers`
List the functions that call a specific function.

```
ghidra_cli call function.callers --session_id <string> --function_start <address>
```

#### `function.calling_convention.set`
Set the calling convention used by a function.

```
ghidra_cli call function.calling_convention.set --session_id <string> --function_start <address> --name <string>
```

#### `function.calling_conventions.list`
List calling conventions available in the current program.

```
ghidra_cli call function.calling_conventions.list --session_id <string>
```

#### `function.create`
Create a new function at a given address.

```
ghidra_cli call function.create --session_id <string> --address <address> [--name <string=null>]
```

#### `function.delete`
Delete a function at a given address.

```
ghidra_cli call function.delete --session_id <string> --function_start <address>
```

#### `function.flags.set`
Update function flags such as varargs, inline, noreturn, or custom storage.

```
ghidra_cli call function.flags.set --session_id <string> --function_start <address> [--varargs <bool=null>] [--inline <bool=null>] [--noreturn <bool=null>] [--custom_storage <bool=null>]
```

#### `function.list`
List functions in the program with filtering and pagination support.

```
ghidra_cli call function.list --session_id <string> [--offset <int=0>] [--limit <int=100>] [--query <string=null>]
```

#### `function.rename`
Rename an existing function.

```
ghidra_cli call function.rename --session_id <string> --function_start <address> --name <string>
```

#### `function.report`
Return a richer function report with signature, variables, call graph edges, xrefs, and decompilation output.

```
ghidra_cli call function.report --session_id <string> --function_start <address>
```

#### `function.return_type.set`
Set the return type of a function.

```
ghidra_cli call function.return_type.set --session_id <string> --function_start <address> --data_type <string>
```

#### `function.signature.get`
Return the full signature of a function.

```
ghidra_cli call function.signature.get --session_id <string> --function_start <address>
```

#### `function.signature.set`
Apply a full C-style signature declaration to a function.

```
ghidra_cli call function.signature.set --session_id <string> --function_start <address> --signature <string>
```

#### `function.thunk.set`
Mark a function as a thunk to another function.

```
ghidra_cli call function.thunk.set --session_id <string> --function_start <address> --thunk_target <address>
```

#### `function.variables`
List parameters and local variables for a function.

```
ghidra_cli call function.variables --session_id <string> --function_start <address>
```


### parameter — function parameters

#### `parameter.add`
Add a new parameter to a function with a chosen type and storage.

```
ghidra_cli call parameter.add --session_id <string> --function_start <address> --name <string> --data_type <string> [--ordinal <int=null>] [--stack_offset <int=null>] [--register <string=null>]
```

#### `parameter.move`
Reorder a parameter to a new ordinal within the signature.

```
ghidra_cli call parameter.move --session_id <string> --function_start <address> --ordinal <int> --new_ordinal <int>
```

#### `parameter.remove`
Remove a parameter from a function by ordinal or name.

```
ghidra_cli call parameter.remove --session_id <string> --function_start <address> [--ordinal <int=null>] [--name <string=null>]
```

#### `parameter.replace`
Replace an existing parameter definition by ordinal or name.

```
ghidra_cli call parameter.replace --session_id <string> --function_start <address> [--ordinal <int=null>] [--name <string=null>] [--new_name <string=null>] [--data_type <string=null>] [--stack_offset <int=null>] [--register <string=null>]
```


### variable — local variables

#### `variable.comment.set`
Set or clear the comment attached to a local variable or parameter.

```
ghidra_cli call variable.comment.set --session_id <string> --function_start <address> --name <string> --comment <string> [--ordinal <int=null>] [--storage <string=null>]
```

#### `variable.local.create`
Create a local variable with explicit type, storage, and optional comment.

```
ghidra_cli call variable.local.create --session_id <string> --function_start <address> --name <string> --data_type <string> [--first_use_offset <int=0>] [--stack_offset <int=null>] [--register <string=null>] [--storage_address <address=null>] [--comment <string=null>]
```

#### `variable.local.remove`
Remove a local variable from a function.

```
ghidra_cli call variable.local.remove --session_id <string> --function_start <address> --name <string> [--storage <string=null>]
```

#### `variable.rename`
Rename a local variable or parameter.

```
ghidra_cli call variable.rename --session_id <string> --function_start <address> --name <string> --new_name <string> [--ordinal <int=null>] [--storage <string=null>]
```

#### `variable.retype`
Change the data type of a local variable or parameter.

```
ghidra_cli call variable.retype --session_id <string> --function_start <address> --name <string> --data_type <string> [--ordinal <int=null>] [--storage <string=null>]
```


### stackframe — stack-frame variables

#### `stackframe.variable.clear`
Clear a stack-frame variable at a specific stack offset.

```
ghidra_cli call stackframe.variable.clear --session_id <string> --function_start <address> --stack_offset <int>
```

#### `stackframe.variable.create`
Create a stack-frame variable at a specific stack offset.

```
ghidra_cli call stackframe.variable.create --session_id <string> --function_start <address> --name <string> --stack_offset <int> --data_type <string>
```

#### `stackframe.variables`
List stack-frame variables for a function.

```
ghidra_cli call stackframe.variables --session_id <string> --function_start <address>
```


### type — data types and type libraries

#### `type.apply_at`
Apply a data type at an address in the listing.

```
ghidra_cli call type.apply_at --session_id <string> --address <address> --data_type <string> [--length <int=null>] [--clear_existing <bool=true>]
```

#### `type.archives.list`
List the current program archive plus attached source archives.

```
ghidra_cli call type.archives.list --session_id <string>
```

#### `type.category.create`
Create a new data type category path.

```
ghidra_cli call type.category.create --session_id <string> --path <string>
```

#### `type.category.list`
List data type categories under a path, optionally recursively.

```
ghidra_cli call type.category.list --session_id <string> [--path <string=/>] [--recursive <bool=false>]
```

#### `type.define_c`
Define a new data type from a C declaration.

```
ghidra_cli call type.define_c --session_id <string> --declaration <string> [--name <string=null>] [--category <string=/>]
```

#### `type.delete`
Delete a data type by name or full path.

```
ghidra_cli call type.delete --session_id <string> [--path <string=null>] [--name <string=null>]
```

#### `type.get`
Return details for a data type by name or full path.

```
ghidra_cli call type.get --session_id <string> [--path <string=null>] [--name <string=null>]
```

#### `type.get_by_id`
Look up a data type by internal ID, universal ID, or source archive ID.

```
ghidra_cli call type.get_by_id --session_id <string> [--data_type_id <int=null>] [--universal_id <int=null>] [--source_archive_id <int=null>]
```

#### `type.list`
List data types with filtering and pagination support.

```
ghidra_cli call type.list --session_id <string> [--offset <int=0>] [--limit <int=100>] [--query <string=null>]
```

#### `type.parse_c`
Parse a C declaration and return the resulting type without necessarily committing it.

```
ghidra_cli call type.parse_c --session_id <string> --declaration <string> [--name <string=null>] [--category <string=/>]
```

#### `type.rename`
Rename an existing data type.

```
ghidra_cli call type.rename --session_id <string> [--path <string=null>] [--name <string=null>] --new_name <string>
```

#### `type.source_archives.list`
List source archives referenced by the current data type manager.

```
ghidra_cli call type.source_archives.list --session_id <string>
```


### layout — struct/union/enum reconstruction

#### `layout.enum.create`
Create an enum data type in a chosen category.

```
ghidra_cli call layout.enum.create --session_id <string> --name <string> [--category <string=/>] [--size <int=4>]
```

#### `layout.enum.member.add`
Add a named value to an enum data type.

```
ghidra_cli call layout.enum.member.add --session_id <string> [--enum_path <string=null>] [--enum_name <string=null>] --name <string> --value <address> [--comment <string=null>]
```

#### `layout.enum.member.remove`
Remove a named member from an enum data type.

```
ghidra_cli call layout.enum.member.remove --session_id <string> [--enum_path <string=null>] [--enum_name <string=null>] --name <string>
```

#### `layout.inspect.components`
Inspect the component layout of a composite data type.

```
ghidra_cli call layout.inspect.components --session_id <string> [--path <string=null>] [--name <string=null>]
```

#### `layout.struct.bitfield.add`
Insert a bitfield into a structure at a byte and bit offset.

```
ghidra_cli call layout.struct.bitfield.add --session_id <string> [--struct_path <string=null>] [--struct_name <string=null>] --byte_offset <int> --byte_width <int> --bit_offset <int> --data_type <string> --bit_size <int> [--field_name <string=null>] [--comment <string=null>]
```

#### `layout.struct.create`
Create a structure data type in a chosen category.

```
ghidra_cli call layout.struct.create --session_id <string> --name <string> [--category <string=/>] [--length <int=0>]
```

#### `layout.struct.field.add`
Add a field to a structure at a specific offset or append position.

```
ghidra_cli call layout.struct.field.add --session_id <string> [--struct_path <string=null>] [--struct_name <string=null>] [--field_name <string=null>] --data_type <string> [--offset <int=null>] [--length <int=null>] [--comment <string=null>]
```

#### `layout.struct.field.clear`
Clear a field from a structure by offset, ordinal, or field name.

```
ghidra_cli call layout.struct.field.clear --session_id <string> [--struct_path <string=null>] [--struct_name <string=null>] --offset <int>
```

#### `layout.struct.field.comment.set`
Set or clear the comment on a structure field.

```
ghidra_cli call layout.struct.field.comment.set --session_id <string> [--struct_path <string=null>] [--struct_name <string=null>] [--offset <int=null>] [--ordinal <int=null>] [--field_name <string=null>] --comment <string>
```

#### `layout.struct.field.rename`
Rename a structure field.

```
ghidra_cli call layout.struct.field.rename --session_id <string> [--struct_path <string=null>] [--struct_name <string=null>] [--old_name <string=null>] --new_name <string> [--offset <int=null>] [--ordinal <int=null>]
```

#### `layout.struct.field.replace`
Replace an existing structure field with a new type, size, name, or comment.

```
ghidra_cli call layout.struct.field.replace --session_id <string> [--struct_path <string=null>] [--struct_name <string=null>] --offset <int> --data_type <string> [--length <int=null>] [--field_name <string=null>] [--comment <string=null>]
```

#### `layout.struct.fill_from_decompiler`
Build or extend a structure from decompiler-observed usage of a variable.

```
ghidra_cli call layout.struct.fill_from_decompiler --session_id <string> --function_start <address> --name <string> [--ordinal <int=null>] [--storage <string=null>] [--create_new_structure <bool=true>] [--create_class_if_needed <bool=false>] [--timeout_secs <int=30>]
```

#### `layout.struct.get`
Return a structure definition together with its components.

```
ghidra_cli call layout.struct.get --session_id <string> [--struct_path <string=null>] [--struct_name <string=null>]
```

#### `layout.struct.resize`
Resize a structure to a specific total length.

```
ghidra_cli call layout.struct.resize --session_id <string> [--struct_path <string=null>] [--struct_name <string=null>] --length <int>
```

#### `layout.union.create`
Create a union data type in a chosen category.

```
ghidra_cli call layout.union.create --session_id <string> --name <string> [--category <string=/>]
```

#### `layout.union.member.add`
Add a member to a union data type.

```
ghidra_cli call layout.union.member.add --session_id <string> [--union_path <string=null>] [--union_name <string=null>] [--field_name <string=null>] --data_type <string> [--length <int=null>] [--comment <string=null>]
```

#### `layout.union.member.remove`
Remove a member from a union data type.

```
ghidra_cli call layout.union.member.remove --session_id <string> [--union_path <string=null>] [--union_name <string=null>] [--ordinal <int=null>] [--field_name <string=null>]
```


### decomp — decompiler and high-level symbols

#### `decomp.ast`
Decompile a function and return the Clang markup tree for the result.

```
ghidra_cli call decomp.ast --session_id <string> --function_start <address> [--timeout_secs <int=30>]
```

#### `decomp.function`
Decompile a function and return recovered C source code.

```
ghidra_cli call decomp.function --session_id <string> --function_start <address> [--timeout_secs <int=30>]
```

#### `decomp.global.rename`
Rename a global symbol selected through decompiler high-symbol information.

```
ghidra_cli call decomp.global.rename --session_id <string> --function_start <address> --name <string> --new_name <string> [--storage <string=null>] [--timeout_secs <int=30>]
```

#### `decomp.global.retype`
Retype a global symbol selected through decompiler high-symbol information.

```
ghidra_cli call decomp.global.retype --session_id <string> --function_start <address> --name <string> --data_type <string> [--storage <string=null>] [--timeout_secs <int=30>]
```

#### `decomp.high_function.summary`
Summarize the high-function view, including local symbols, globals, blocks, and jump tables.

```
ghidra_cli call decomp.high_function.summary --session_id <string> --function_start <address> [--timeout_secs <int=30>]
```

#### `decomp.override.get`
Return the decompiler call override, if any, for a specific callsite.

```
ghidra_cli call decomp.override.get --session_id <string> --function_start <address> --callsite <address>
```

#### `decomp.override.set`
Set or replace the decompiler call override signature for a specific callsite.

```
ghidra_cli call decomp.override.set --session_id <string> --function_start <address> --callsite <address> --signature <string>
```

#### `decomp.tokens`
Decompile a function and return tokenized Clang markup for the output.

```
ghidra_cli call decomp.tokens --session_id <string> --function_start <address> [--timeout_secs <int=30>]
```

#### `decomp.trace_type.backward`
Trace type propagation backward from a selected decompiler symbol.

```
ghidra_cli call decomp.trace_type.backward --session_id <string> --function_start <address> --name <string> [--ordinal <int=null>] [--storage <string=null>] [--timeout_secs <int=30>]
```

#### `decomp.trace_type.forward`
Trace type propagation forward from a selected decompiler symbol.

```
ghidra_cli call decomp.trace_type.forward --session_id <string> --function_start <address> --name <string> [--ordinal <int=null>] [--storage <string=null>] [--timeout_secs <int=30>]
```

#### `decomp.writeback.locals`
Commit decompiler-recovered local names back into the program database.

```
ghidra_cli call decomp.writeback.locals --session_id <string> --function_start <address> [--timeout_secs <int=30>]
```

#### `decomp.writeback.params`
Commit decompiler-recovered parameter information back into the program database.

```
ghidra_cli call decomp.writeback.params --session_id <string> --function_start <address> [--use_data_types <bool=true>] [--commit_return <bool=false>] [--timeout_secs <int=30>]
```


### pcode — p-code inspection

#### `pcode.block`
Return per-instruction p-code for the basic block containing an address.

```
ghidra_cli call pcode.block --session_id <string> --address <address>
```

#### `pcode.function`
Return per-instruction p-code for a function.

```
ghidra_cli call pcode.function --session_id <string> --function_start <address> [--limit <int=200>]
```

#### `pcode.op.at`
Return the p-code ops generated by the instruction at an address.

```
ghidra_cli call pcode.op.at --session_id <string> --address <address>
```

#### `pcode.varnode_uses`
Find p-code reads and writes that match a selected varnode.

```
ghidra_cli call pcode.varnode_uses --session_id <string> --function_start <address> [--varnode <string=null>] [--address <address=null>] [--space <string=null>] [--size <int=null>] [--timeout_secs <int=30>]
```


### search — search and resolve

#### `search.bytes`
Search program memory for an exact byte pattern.

```
ghidra_cli call search.bytes --session_id <string> [--pattern_base64 <string=null>] [--pattern_hex <string=null>] [--start <address=null>] [--end <address=null>] [--limit <int=100>]
```

#### `search.constants`
Search instructions for scalar constant operands that match a value.

```
ghidra_cli call search.constants --session_id <string> --value <address> [--start <address=null>] [--end <address=null>] [--limit <int=100>]
```

#### `search.defined_strings`
List defined strings discovered in the program.

```
ghidra_cli call search.defined_strings --session_id <string> [--offset <int=0>] [--limit <int=100>] [--query <string=null>]
```

#### `search.instructions`
Search instructions by mnemonic or rendered instruction text.

```
ghidra_cli call search.instructions --session_id <string> --query <string> [--case_sensitive <bool=false>] [--function_start <address=null>] [--start <address=null>] [--end <address=null>] [--limit <int=100>]
```

#### `search.pcode`
Search p-code operations by mnemonic or rendered op text.

```
ghidra_cli call search.pcode --session_id <string> --query <string> [--case_sensitive <bool=false>] [--function_start <address=null>] [--start <address=null>] [--end <address=null>] [--limit <int=100>]
```

#### `search.resolve`
Resolve a symbol name or expression into an address.

```
ghidra_cli call search.resolve --session_id <string> --query <address>
```

#### `search.text`
Search for text across defined strings and raw memory matches.

```
ghidra_cli call search.text --session_id <string> --text <string> [--case_sensitive <bool=false>] [--defined_strings_only <bool=false>] [--encoding <string=utf-8>] [--start <address=null>] [--end <address=null>] [--limit <int=100>]
```


### graph — CFG and call-graph extraction

#### `graph.basic_blocks`
List the basic blocks that make up a function.

```
ghidra_cli call graph.basic_blocks --session_id <string> --function_start <address>
```

#### `graph.call_paths`
Find call graph paths between two functions up to a chosen depth.

```
ghidra_cli call graph.call_paths --session_id <string> --source_function <address> --target_function <address> [--max_depth <int=4>] [--limit <int=10>]
```

#### `graph.cfg.edges`
List control-flow edges between the basic blocks of a function.

```
ghidra_cli call graph.cfg.edges --session_id <string> --function_start <address>
```
