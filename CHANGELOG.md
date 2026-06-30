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
