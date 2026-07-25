"""Unit tests for _find_byte_matches that do not require a real Ghidra.

These guard the two regressions that made search_bytes silently return count 0:
  1. the findBytes byteString must be \\xNN-escaped (not space-separated hex);
  2. a genuine backend failure must raise, not be swallowed into an empty list.

The fake backend (fake_ghidra.py) reimplements byte search and never exercises
_find_byte_matches, so these call the real method directly with stubs.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from ghidra_headless_mcp.backend import GhidraBackend, GhidraBackendError


class _Record:
    def __init__(self, flat_api: object) -> None:
        self.flat_api = flat_api


def _make_self(flat_api: object) -> SimpleNamespace:
    memory = object()
    return SimpleNamespace(
        _get_program=lambda _session_id: SimpleNamespace(getMemory=lambda: memory),
        _get_record=lambda _session_id: _Record(flat_api),
    )


def test_find_byte_matches_uses_escaped_hex_pattern() -> None:
    captured: dict[str, object] = {}

    def find_bytes(search_base, pattern, limit, alignment):  # noqa: ANN001, ANN202
        captured["pattern"] = pattern
        captured["limit"] = limit
        captured["alignment"] = alignment
        return ["0x1000"]

    stub_self = _make_self(SimpleNamespace(findBytes=find_bytes))
    result = GhidraBackend._find_byte_matches(
        stub_self, "session", b"\xde\xad\xbe\xef", 100
    )

    assert result == ["0x1000"]
    assert captured["pattern"] == "\\xde\\xad\\xbe\\xef"
    assert captured["limit"] == 100
    assert captured["alignment"] == 1


def test_find_byte_matches_returns_empty_on_none() -> None:
    stub_self = _make_self(SimpleNamespace(findBytes=lambda *_: None))
    assert GhidraBackend._find_byte_matches(stub_self, "session", b"\x00", 10) == []


def test_find_byte_matches_short_circuits_on_nonpositive_limit() -> None:
    def find_bytes(*_):  # noqa: ANN002, ANN202
        raise AssertionError("findBytes should not be called when limit <= 0")

    stub_self = _make_self(SimpleNamespace(findBytes=find_bytes))
    assert GhidraBackend._find_byte_matches(stub_self, "session", b"\x00", 0) == []


def test_find_byte_matches_surfaces_backend_errors() -> None:
    def find_bytes(*_):  # noqa: ANN002, ANN202
        raise RuntimeError("no matching overload")

    stub_self = _make_self(SimpleNamespace(findBytes=find_bytes))
    with pytest.raises(GhidraBackendError, match="byte search failed"):
        GhidraBackend._find_byte_matches(stub_self, "session", b"\x00", 10)
