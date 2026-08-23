"""Structural protocol for LSP feature registration."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

from lsprotocol.types import LogMessageParams, PublishDiagnosticsParams


class FeatureRegistrationServer(Protocol):
    """Minimum server surface needed while registering LSP features."""

    semantic_tokens_provider: Any
    workspace_symbols_provider: Any

    def feature(
        self, name: str, *options: Any
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Return a decorator that registers an LSP handler."""
        ...

    def window_log_message(self, params: LogMessageParams) -> None:
        """Log a message through the language server."""
        ...

    def text_document_publish_diagnostics(self, params: PublishDiagnosticsParams) -> None:
        """Publish diagnostics through the language server."""
        ...
