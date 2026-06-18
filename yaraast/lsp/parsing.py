"""Unified parsing helpers for LSP providers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from yaraast.errors import ParseError
from yaraast.lexer.lexer_errors import LexerError
from yaraast.lsp.runtime import get_document_context

if TYPE_CHECKING:
    from yaraast.lsp.runtime import LspRuntime


def parse_for_lsp(text: str, uri: str | None = None, runtime: LspRuntime | None = None) -> Any:
    """Parse through the same LSP pipeline used by runtime documents."""
    document = get_document_context(runtime, uri, text)
    ast = document.ast()
    if ast is not None:
        return ast
    error = document.parse_error()
    if error is not None:
        if isinstance(error, LexerError):
            raise ParseError(str(error)) from error
        raise error
    raise ParseError("Unable to parse document")
