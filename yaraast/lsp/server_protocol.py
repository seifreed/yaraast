"""Structural protocol for LSP feature registration."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol


class FeatureRegistrationServer(Protocol):
    """Minimum server surface needed while registering LSP features."""

    semantic_tokens_provider: Any
    workspace_symbols_provider: Any

    def feature(
        self, name: str, *options: Any
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Return a decorator that registers an LSP handler."""
        ...

    def show_message_log(self, message: str) -> None:
        """Log a message through the language server."""
        ...
