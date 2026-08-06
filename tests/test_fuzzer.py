from __future__ import annotations

import pytest
from ghidra_headless_mcp import fuzz_support, fuzzer
from ghidra_headless_mcp.fuzz_support import (
    ToolContext,
    create_tool_context,
    resolve_sample_binary_path,
)
from ghidra_headless_mcp.fuzzer import run
from ghidra_headless_mcp.server import ALL_TOOL_SPECS


class _ScriptedTaskBackend:
    def __init__(self, statuses: list[str]) -> None:
        self.statuses = iter(statuses)
        self.last_status = statuses[-1]
        self.status_calls: list[str] = []
        self.cancel_calls: list[str] = []

    def task_status(self, task_id: str) -> dict[str, object]:
        self.status_calls.append(task_id)
        self.last_status = next(self.statuses, self.last_status)
        return {"task_id": task_id, "status": self.last_status}

    def task_cancel(self, task_id: str) -> dict[str, object]:
        self.cancel_calls.append(task_id)
        return {"task_id": task_id, "status": "cancelling"}


def _live_context(backend: object, task_id: str | None = None) -> ToolContext:
    return ToolContext(
        backend=backend,
        server=None,
        session_id="session-1",
        task_id=task_id,
        mode="live",
        live_case=object(),
    )


def test_fuzzer_covers_all_tools_with_required_and_optional_cases() -> None:
    result = run(rounds=2, seed=0)

    assert result["sample_path"] == resolve_sample_binary_path()
    assert result["tool_count"] == len(ALL_TOOL_SPECS)
    assert result["case_count"] == len(ALL_TOOL_SPECS) * 2
    assert result["missing_tools"] == []
    assert result["error_count"] == 0


def test_fuzzer_prefix_mode_exercises_deeper_round_variants() -> None:
    result = run(prefix="function.", rounds=3, seed=1)

    assert result["tool_count"] > 0
    assert result["case_count"] == result["tool_count"] * 3
    assert result["error_count"] == 0
    assert all(item["name"].startswith("function.") for item in result["results"])

    round_two = [
        item
        for item in result["results"]
        if item["name"] == "function.return_type.set" and item["round"] == 2
    ]
    assert round_two
    assert round_two[0]["arguments"]["data_type"] == "/long"


def test_fuzzer_seed_context_opens_repo_ls_sample() -> None:
    ctx = create_tool_context()

    assert ctx.backend._sessions[ctx.session_id].filename == resolve_sample_binary_path()


def test_live_task_waiter_polls_until_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = _ScriptedTaskBackend(["queued", "running", "completed"])
    monkeypatch.setattr(fuzzer.time, "sleep", lambda _seconds: None)

    status = fuzzer._wait_for_live_task_terminal(_live_context(backend), "task-1")

    assert status["status"] == "completed"
    assert backend.status_calls == ["task-1", "task-1", "task-1"]


def test_live_task_waiter_timeout_includes_last_status() -> None:
    backend = _ScriptedTaskBackend(["running"])

    with pytest.raises(
        RuntimeError,
        match=r"task task-1 .* within 0 seconds \(last_status=running\)",
    ):
        fuzzer._wait_for_live_task_terminal(
            _live_context(backend),
            "task-1",
            timeout_secs=0,
        )


def test_task_result_preparation_waits_for_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Backend(_ScriptedTaskBackend):
        def task_analysis_update(self, session_id: str) -> dict[str, str]:
            assert session_id == "session-1"
            return {"task_id": "task-1"}

    backend = _Backend(["completed"])
    waited: list[str] = []
    monkeypatch.setattr(
        fuzzer,
        "_wait_for_live_task_terminal",
        lambda _ctx, task_id: waited.append(task_id),
    )

    ctx = _live_context(backend)
    fuzzer._prepare_context(ctx, "task.result")

    assert ctx.task_id == "task-1"
    assert waited == ["task-1"]


def test_task_analysis_update_does_not_require_a_seed_task() -> None:
    assert fuzz_support._tool_requires_task_id("task.analysis_update") is False
    assert fuzz_support._tool_requires_task_id("task.status") is True


def test_task_status_cleanup_cancels_and_drains(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = _ScriptedTaskBackend(["running"])
    waited: list[str] = []
    monkeypatch.setattr(
        fuzzer,
        "_wait_for_live_task_terminal",
        lambda _ctx, task_id: waited.append(task_id),
    )

    fuzzer._cleanup_live_task_case(_live_context(backend, "task-1"), "task.status")

    assert backend.cancel_calls == ["task-1"]
    assert waited == ["task-1"]


def test_task_cancel_cleanup_ensures_cancellation_and_drains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _ScriptedTaskBackend(["cancelling"])
    waited: list[str] = []
    monkeypatch.setattr(
        fuzzer,
        "_wait_for_live_task_terminal",
        lambda _ctx, task_id: waited.append(task_id),
    )

    fuzzer._cleanup_live_task_case(_live_context(backend, "task-1"), "task.cancel")

    assert backend.cancel_calls == ["task-1"]
    assert waited == ["task-1"]


@pytest.mark.parametrize("tool_name", ["analysis.update", "task.analysis_update"])
def test_async_analysis_results_are_drained(
    monkeypatch: pytest.MonkeyPatch,
    tool_name: str,
) -> None:
    waited: list[str] = []
    monkeypatch.setattr(
        fuzzer,
        "_wait_for_live_task_terminal",
        lambda _ctx, task_id: waited.append(task_id),
    )

    fuzzer._stabilize_live_result(
        _live_context(_ScriptedTaskBackend(["completed"])),
        tool_name,
        {"structuredContent": {"task_id": "task-1"}},
    )

    assert waited == ["task-1"]


@pytest.mark.live
@pytest.mark.slow
def test_live_fuzzer_covers_all_tools_on_repo_ls_sample() -> None:
    pytest.importorskip("pyghidra")

    result = run(rounds=1, seed=0, backend_mode="live", fail_fast=True)

    assert result["backend_mode"] == "live"
    assert result["sample_path"] == resolve_sample_binary_path()
    assert result["tool_count"] == len(ALL_TOOL_SPECS)
    assert result["case_count"] == len(ALL_TOOL_SPECS)
    assert result["missing_tools"] == []
    assert result["error_count"] == 0


@pytest.mark.live
@pytest.mark.slow
def test_live_fuzzer_exercises_deeper_function_mutations() -> None:
    pytest.importorskip("pyghidra")

    result = run(prefix="function.", rounds=2, seed=1, backend_mode="live", fail_fast=True)

    assert result["backend_mode"] == "live"
    assert result["tool_count"] > 0
    assert result["case_count"] == result["tool_count"] * 2
    assert result["error_count"] == 0


@pytest.mark.live
@pytest.mark.slow
def test_live_fuzzer_regression_prefixes_remain_clean() -> None:
    pytest.importorskip("pyghidra")

    for prefix in ("analysis.", "patch.", "graph.", "reference.", "function.", "type.", "layout."):
        result = run(prefix=prefix, rounds=1, seed=0, backend_mode="live", fail_fast=True)

        assert result["backend_mode"] == "live"
        assert result["tool_count"] > 0
        assert result["error_count"] == 0
