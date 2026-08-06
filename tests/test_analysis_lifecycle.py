from __future__ import annotations

from threading import Barrier, Event
from types import SimpleNamespace

import pytest
from ghidra_headless_mcp.backend import GhidraBackend, GhidraBackendError, SessionRecord


def _backend_with_session() -> tuple[GhidraBackend, SessionRecord]:
    pyghidra = SimpleNamespace(
        task_monitor=lambda _timeout: SimpleNamespace(cancel=lambda: None),
    )
    backend = GhidraBackend(pyghidra)
    record = SessionRecord(
        session_id="session",
        project=None,
        program=object(),
        flat_api=object(),
        program_name="program",
        program_path="/program",
        project_location="/tmp",
        project_name="project",
        read_only=False,
    )
    backend._sessions[record.session_id] = record
    return backend, record


def test_cancelled_queued_analysis_releases_session_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    backend, record = _backend_with_session()
    release = Event()
    started = Barrier(5)

    def block_worker() -> None:
        started.wait()
        release.wait()

    blockers = [backend._executor.submit(block_worker) for _ in range(4)]
    started.wait(timeout=5)
    monkeypatch.setattr(backend, "_analyze_program", lambda _program, _monitor: "complete")

    try:
        queued = backend.task_analysis_update(record.session_id)
        cancelled = backend.task_cancel(queued["task_id"])

        assert cancelled["status"] == "cancelled"
        assert backend.analysis_status(record.session_id)["status"] == "cancelled"

        release.set()
        for blocker in blockers:
            blocker.result(timeout=5)

        retry = backend.task_analysis_update(record.session_id)
        result = backend._get_task(retry["task_id"]).future.result(timeout=5)
        assert result["status"] == "completed"
        assert backend.analysis_status(record.session_id)["status"] == "completed"
    finally:
        release.set()
        backend._executor.shutdown(wait=True, cancel_futures=True)


def test_analysis_submission_failure_is_terminal() -> None:
    backend, record = _backend_with_session()
    backend._executor.shutdown(wait=True, cancel_futures=True)

    with pytest.raises(GhidraBackendError, match="failed to submit analysis task"):
        backend.task_analysis_update(record.session_id)

    status = backend.analysis_status(record.session_id)
    assert status["status"] == "failed"
    assert status["last_analysis_completed_at"] is not None


def test_synchronous_analysis_monitor_failure_is_terminal() -> None:
    backend, record = _backend_with_session()

    def fail_monitor(_timeout: int) -> None:
        raise RuntimeError("monitor unavailable")

    backend._pyghidra.task_monitor = fail_monitor
    try:
        with pytest.raises(GhidraBackendError, match="failed to create analysis monitor"):
            backend.analysis_update_and_wait(record.session_id)

        status = backend.analysis_status(record.session_id)
        assert status["status"] == "failed"
        assert status["last_analysis_error"] == "monitor unavailable"
    finally:
        backend._executor.shutdown(wait=True, cancel_futures=True)
