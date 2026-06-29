"""Shared timeout helpers for file-oriented performance operations."""

from __future__ import annotations

from collections.abc import Callable
import threading
from typing import Any, TypeVar

from yaraast.shared.numeric_validation import validate_positive_number_setting

T = TypeVar("T")


def _validate_timeout(name: str, timeout: float | None) -> None:
    if timeout is not None:
        validate_positive_number_setting(timeout, name)


def _run_with_alarm_timeout[T](
    signal_module: Any,
    operation: str,
    timeout: float,
    fn: Callable[[], T],
) -> T:
    """Run a callback with SIGALRM timeout protection."""

    def _alarm_handler(_signum: int, _frame: object) -> None:
        raise TimeoutError(f"{operation} timed out after {timeout:g} seconds")

    previous_handler = signal_module.getsignal(signal_module.SIGALRM)
    previous_timer = signal_module.getitimer(signal_module.ITIMER_REAL)
    signal_module.signal(signal_module.SIGALRM, _alarm_handler)
    signal_module.setitimer(signal_module.ITIMER_REAL, timeout)
    try:
        return fn()
    finally:
        signal_module.setitimer(signal_module.ITIMER_REAL, previous_timer[0], previous_timer[1])
        signal_module.signal(signal_module.SIGALRM, previous_handler)


def run_with_timeout[T](operation: str, timeout: float | None, fn: Callable[[], T]) -> T:
    """Run a callback with an optional timeout."""
    _validate_timeout("file_timeout", timeout)
    if timeout is None:
        return fn()

    if threading.current_thread() is not threading.main_thread():
        return _run_with_thread_timeout(operation, timeout, fn)

    signal_module = _signal_module()
    if signal_module is not None and hasattr(signal_module, "SIGALRM"):
        return _run_with_alarm_timeout(signal_module, operation, timeout, fn)

    return _run_with_thread_timeout(operation, timeout, fn)


def _signal_module() -> Any:
    """Resolve the optional signal module in a context manager style."""
    try:
        import signal as signal_module

        return signal_module
    except ImportError:
        return None


def _run_with_thread_timeout[T](operation: str, timeout: float, fn: Callable[[], T]) -> T:
    """Fallback timeout implementation when SIGALRM is unavailable."""
    result_cell: list[T] = []
    error_cell: list[BaseException] = []
    done = threading.Event()

    def _run_task() -> None:
        try:
            result_cell.append(fn())
        except Exception as exc:
            error_cell.append(exc)
        finally:
            done.set()

    thread = threading.Thread(target=_run_task, name="yaraast-timeout-worker", daemon=True)
    thread.start()
    if not done.wait(timeout):
        msg = f"{operation} timed out after {timeout:g} seconds"
        raise TimeoutError(msg)

    if error_cell:
        error = error_cell[0]
        if isinstance(error, TimeoutError):
            raise error
        raise error
    return result_cell[0]
