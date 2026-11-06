"""Decorator for safe LSP operation handling."""

from __future__ import annotations

from collections.abc import Callable
import functools
import logging
from typing import Any, TypeVar, cast, overload

from yaraast.logging_config import safe_traceback_frames

logger = logging.getLogger(__name__)
F = TypeVar("F", bound=Callable[..., Any])


@overload
def lsp_safe_handler(func: F) -> F: ...


@overload
def lsp_safe_handler(*, default: Any) -> Callable[[F], F]: ...


def lsp_safe_handler(func: F | None = None, *, default: Any = None) -> F | Callable[[F], F]:
    """Wrap LSP handler to catch exceptions and return a default value.

    LSP handlers use broad ``except Exception`` intentionally: the language
    server must remain responsive even when individual operations fail on
    malformed input.  Narrowing to domain exceptions would risk crashing
    the server on unexpected edge cases.

    Can be used as:
        @lsp_safe_handler          # returns None on error
        @lsp_safe_handler(default=[])  # returns [] on error
    """

    def fresh_default() -> Any:
        if isinstance(default, (dict, list, set)):
            return default.copy()
        return default

    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return fn(*args, **kwargs)
            except Exception as exc:
                logger.error(
                    "LSP handler failed",
                    extra={
                        "event_name": "lsp.handler.failed",
                        "operation": fn.__qualname__,
                        "error_type": type(exc).__name__,
                        "stack_trace": safe_traceback_frames(exc.__traceback__),
                    },
                )
                return fresh_default()

        return cast(F, wrapper)

    if func is not None:
        return decorator(func)
    return decorator
