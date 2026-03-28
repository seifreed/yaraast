"""Decorator for safe LSP operation handling."""

from __future__ import annotations

from collections.abc import Callable
import functools
import logging
from typing import Any, overload

logger = logging.getLogger(__name__)


@overload
def lsp_safe_handler[F: Callable[..., Any]](func: F) -> F: ...


@overload
def lsp_safe_handler[F: Callable[..., Any]](*, default: Any) -> Callable[[F], F]: ...


def lsp_safe_handler[F: Callable[..., Any]](
    func: F | None = None, *, default: Any = None
) -> F | Callable[[F], F]:
    """Wrap LSP handler to catch exceptions and return a default value.

    LSP handlers use broad ``except Exception`` intentionally: the language
    server must remain responsive even when individual operations fail on
    malformed input.  Narrowing to domain exceptions would risk crashing
    the server on unexpected edge cases.

    Can be used as:
        @lsp_safe_handler          # returns None on error
        @lsp_safe_handler(default=[])  # returns [] on error
    """

    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return fn(*args, **kwargs)
            except Exception:
                logger.debug(
                    "Operation failed in %s.%s",
                    fn.__module__,
                    fn.__qualname__,
                    exc_info=True,
                )
                return default

        return wrapper  # type: ignore[return-value]

    if func is not None:
        return decorator(func)
    return decorator
