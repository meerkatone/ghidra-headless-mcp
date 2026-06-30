"""Unit tests for ghidra_cli argument coercion and the tool-argument scanner."""

from __future__ import annotations

import pytest
from ghidra_headless_mcp.fuzz_support import TOOL_SPECS_BY_NAME
from ghidra_headless_mcp.ghidra_cli import (
    CliUsageError,
    coerce_value,
    parse_tool_rest,
)

_ADDRESS = {"oneOf": [{"type": "integer"}, {"type": "string"}]}


@pytest.mark.parametrize(
    ("raw", "schema", "expected"),
    [
        ("true", {"type": "boolean"}, True),
        ("False", {"type": "boolean"}, False),
        ("1", {"type": "boolean"}, True),
        ("0", {"type": "boolean"}, False),
        ("yes", {"type": "boolean"}, True),
        ("off", {"type": "boolean"}, False),
        ("42", {"type": "integer"}, 42),
        ("0x10", {"type": "integer"}, 16),
        ("0o17", {"type": "integer"}, 15),
        ("0b101", {"type": "integer"}, 5),
        ("-1", {"type": "integer"}, -1),
        ("010", {"type": "integer"}, 10),  # decimal, not octal 8
        ("08", {"type": "integer"}, 8),  # would crash with int(v, 0)
        ("1.5", {"type": "number"}, 1.5),
        ("text", {"type": "string"}, "text"),
        (
            "401000",
            _ADDRESS,
            "401000",
        ),  # B1: address stays a string (Ghidra reads bare digits as hex)
        ("0x401000", _ADDRESS, "0x401000"),
        ("main", _ADDRESS, "main"),
        ("123", {}, "123"),  # untyped {} passes through as string
        ('{"k": 1}', {"type": "object"}, {"k": 1}),
        ("[1, 2]", {"type": "array", "items": {"type": "integer"}}, [1, 2]),
    ],
)
def test_coerce_value(raw: str, schema: dict, expected: object) -> None:
    assert coerce_value(raw, schema) == expected


@pytest.mark.parametrize(
    ("raw", "schema"),
    [
        ("maybe", {"type": "boolean"}),
        ("2", {"type": "boolean"}),
        ("notint", {"type": "integer"}),
        ("0x", {"type": "integer"}),
        ("", {"type": "integer"}),  # empty string must not crash with IndexError
        ("   ", {"type": "integer"}),
        ("+", {"type": "integer"}),
        ("-", {"type": "integer"}),
        ("nan-but-not", {"type": "number"}),
        ("{bad", {"type": "object"}),
    ],
)
def test_coerce_value_rejects(raw: str, schema: dict) -> None:
    with pytest.raises(CliUsageError):
        coerce_value(raw, schema)


def test_parse_tool_rest_typed_suffixes() -> None:
    spec = TOOL_SPECS_BY_NAME["metadata.store"]
    assert parse_tool_rest(["--key", "k", "--value", "123"], spec)["value"] == "123"
    assert parse_tool_rest(["--key", "k", "--value:json", "123"], spec)["value"] == 123
    assert parse_tool_rest(["--key", "k", "--value:int", "0x10"], spec)["value"] == 16


def test_parse_tool_rest_null_token() -> None:
    spec = TOOL_SPECS_BY_NAME["variable.comment.set"]
    assert parse_tool_rest(["--comment:null"], spec)["comment"] is None


def test_parse_tool_rest_json_base_with_flag_override() -> None:
    spec = TOOL_SPECS_BY_NAME["program.open"]
    args = parse_tool_rest(
        ["--json", '{"path": "/a", "read_only": true}', "--read-only", "false"], spec
    )
    assert args == {"path": "/a", "read_only": False}


def test_parse_tool_rest_repeated_array_flags() -> None:
    spec = TOOL_SPECS_BY_NAME["relocation.add"]
    assert parse_tool_rest(["--values", "1", "--values", "2"], spec)["values"] == [1, 2]


def test_parse_tool_rest_inline_equals_and_dashes() -> None:
    spec = TOOL_SPECS_BY_NAME["program.open"]
    assert parse_tool_rest(["--read-only=false"], spec) == {"read_only": False}
    assert parse_tool_rest(["--read_only", "true"], spec) == {"read_only": True}


def test_parse_tool_rest_unknown_flag_rejected() -> None:
    spec = TOOL_SPECS_BY_NAME["program.open"]
    with pytest.raises(CliUsageError, match="unknown argument"):
        parse_tool_rest(["--bogus", "x"], spec)


def test_parse_tool_rest_bare_boolean() -> None:
    spec = TOOL_SPECS_BY_NAME["program.open"]
    assert parse_tool_rest(["--read-only"], spec) == {"read_only": True}


def test_parse_tool_rest_value_starting_with_dashes_via_equals() -> None:
    spec = TOOL_SPECS_BY_NAME["search.text"]
    assert parse_tool_rest(["--text=--weird"], spec) == {"text": "--weird"}


def test_parse_tool_rest_empty_typed_int_rejected() -> None:
    spec = TOOL_SPECS_BY_NAME["metadata.store"]
    with pytest.raises(CliUsageError, match="integer"):
        parse_tool_rest(["--key", "k", "--value:int="], spec)
