"""Decorator for safe LSP operation handling."""

from __future__ import annotations

import functools
import logging
from collections.abc import Callable
from typing import Any, TypeVar

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


def lsp_safe_handler(func: F) -> F:
    """Wrap LSP handler to catch exceptions and return None.

    Replaces the repeated try/except pattern across LSP modules:
        try:
            ...
        except Exception:
            logger.debug("Operation failed in %s", __name__, exc_info=True)
            return None
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except Exception:
            logger.debug(
                "Operation failed in %s.%s",
                func.__module__,
                func.__qualname__,
                exc_info=True,
            )
            return None

    return wrapper  # type: ignore[return-value]
