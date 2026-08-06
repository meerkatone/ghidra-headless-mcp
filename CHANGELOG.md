# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project uses Semantic Versioning.

## [Unreleased]

### Added
- `ghidra_cli` native command-line client exposing every MCP tool to agents and shells that do not speak the MCP protocol, with in-process and remote/managed-server transports, schema-driven argument coercion, a `batch` runner with session auto-threading, and a `cli_verify` parity/exit-code/fuzz harness.
- GitHub Actions release gates for linting, packaging, fake-backend coverage, and live Ghidra coverage.
- Contributor-facing development and release documentation.
- Shared package version wiring across the CLI and MCP initialize response.

### Changed
- Pytest now distinguishes `live`, `slow`, and `socket` coverage so CI can run the right gates for each environment.
- Ruff policy now targets real defects while allowing the intentional large dispatcher-style modules and scenario-style tests.
- `ghidra.eval`, `ghidra.call`, and `ghidra.script` reject raw access to read-only sessions unless `write=true`, which explicitly transitions the target session to writable.

### Fixed
- Concurrent auto-analysis on the same session is rejected with a clear error instead of corrupting Ghidra's transaction stack.
- Category paths accept a leading-`/`-less form in `type.category.create`, `type.define_c`, `struct.create`, `enum.create`, `union.create`, and type lookups (path + name).
- `type.define_c`/`type.parse_c` now parse full `typedef struct { ... }` and other composite declarations via the C parser; `type.parse_c` is non-mutating and works on read-only sessions.
- `relocation.add` validates the status enum and reports the supported values instead of a raw `AttributeError`.
- `source.file.add` resolves relative paths to absolute instead of failing with Ghidra's `IllegalArgumentException`.
- Decompiler high-symbol lookups match storage case-insensitively and report candidate symbols when nothing matches.
- C declarations with function-pointer members use the full parser, defined types honor their requested category, and non-mutating parsing no longer rolls back an active caller transaction.
- Cancelled queued analysis tasks release the per-session analysis guard so later analysis can run.
