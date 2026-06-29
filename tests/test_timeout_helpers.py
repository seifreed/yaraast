"""Timeout helper regression tests."""

from __future__ import annotations

import threading
import time

import pytest

from yaraast.performance import timeout_helpers


def test_run_with_timeout_rejects_non_positive_values() -> None:
    with pytest.raises(ValueError, match="file_timeout must be greater than 0"):
        timeout_helpers.run_with_timeout("bad timeout", 0.0, lambda: 1)


def test_run_with_timeout_falls_back_to_thread_in_worker_threads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Worker threads must not use signal-based timeouts."""

    def _alarm_unsupported(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("signal-based timeout used in worker thread")

    monkeypatch.setattr(
        timeout_helpers,
        "_run_with_alarm_timeout",
        _alarm_unsupported,
    )

    timed_out: threading.Event = threading.Event()

    def _slow_work() -> bool:
        timed_out.set()
        time.sleep(0.05)
        return False

    result: object = None
    error: BaseException | None = None

    def _run_in_worker() -> None:
        nonlocal result, error
        try:
            result = timeout_helpers.run_with_timeout(
                "worker timeout",
                0.001,
                _slow_work,
            )
        except Exception as exc:
            error = exc

    worker = threading.Thread(target=_run_in_worker, name="performance-timeout-test")
    worker.start()
    worker.join(timeout=1)
    assert not worker.is_alive()

    assert timed_out.is_set()
    assert result is None
    assert isinstance(error, TimeoutError)
    assert "timed out after" in str(error)


def test_run_with_timeout_does_not_block_worker_after_thread_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Thread-based timeout path must return promptly and unblock callers."""

    def _alarm_unsupported(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("signal-based timeout used in worker thread")

    monkeypatch.setattr(
        timeout_helpers,
        "_run_with_alarm_timeout",
        _alarm_unsupported,
    )

    seen: dict[str, bool] = {"called": False}

    def _never_finish() -> bool:
        seen["called"] = True
        time.sleep(1.5)
        return True

    result: object = None
    error: BaseException | None = None

    def _run_in_worker() -> None:
        nonlocal result, error
        try:
            result = timeout_helpers.run_with_timeout(
                "worker timeout",
                0.001,
                _never_finish,
            )
        except Exception as exc:
            error = exc

    worker = threading.Thread(target=_run_in_worker, name="performance-timeout-watchdog")
    start = time.perf_counter()
    worker.start()
    worker.join(timeout=0.4)

    assert not worker.is_alive()
    elapsed = time.perf_counter() - start
    assert elapsed < 0.8
    assert seen["called"]
    assert result is None
    assert isinstance(error, TimeoutError)
    assert "timed out after 0.001" in str(error)
