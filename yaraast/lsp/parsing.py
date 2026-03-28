"""Unified parsing helpers for LSP providers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from yaraast.errors import ParseError
from yaraast.lsp.document_context import DocumentContext

if TYPE_CHECKING:
    from yaraast.lsp.runtime import LspRuntime


def parse_for_lsp(text: str, uri: str | None = None, runtime: LspRuntime | None = None) -> Any:
    """Parse through the same LSP pipeline used by runtime documents."""
    if runtime is not None and uri:
        document = runtime.ensure_document(uri, text)
    else:
        document = DocumentContext(uri or "file://local.yar", text)
    ast = document.ast()
    if ast is not None:
        return ast
    error = document.parse_error()
    if error is not None:
        raise error
    raise ParseError("Unable to parse document")
