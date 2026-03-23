"""Document symbols provider for YARA Language Server."""

from __future__ import annotations

import logging
import time

from lsprotocol.types import DocumentSymbol, Range

from yaraast.lsp.runtime import DocumentContext, LspRuntime
from yaraast.lsp.symbol_tree_builder import build_document_symbols
from yaraast.lsp.symbol_tree_builder import find_closing_brace as _find_closing_brace_impl
from yaraast.lsp.symbol_tree_builder import find_line_containing as _find_line_containing_impl
from yaraast.lsp.symbol_tree_builder import make_range as _make_range_impl

logger = logging.getLogger(__name__)


class SymbolsProvider:
    """Provides document symbols (outline view)."""

    def __init__(self, runtime: LspRuntime | None = None) -> None:
        self.runtime = runtime

    def get_symbols(self, text: str, uri: str | None = None) -> list[DocumentSymbol]:
        """
        Get document symbols for the given YARA file.

        Args:
            text: The YARA source code

        Returns:
            List of document symbols
        """
        started = time.perf_counter()

        try:
            if self.runtime and uri:
                doc = self.runtime.ensure_document(uri, text)
            else:
                doc = DocumentContext(uri or "", text)
            cached = doc.get_cached("lsp:document_symbols")
            if cached is not None:
                return cached
            ast = doc.ast()
            if ast is None:
                return []
            lines = text.split("\n")
            symbols = build_document_symbols(doc, lines)

        except Exception:
            logger.debug("Operation failed in %s", __name__, exc_info=True)
            # If parsing fails, return empty symbols
            symbols = []

        doc.set_cached("lsp:document_symbols", symbols)
        if self.runtime is not None:
            self.runtime.record_latency(
                "document_symbols", (time.perf_counter() - started) * 1000.0
            )
        return symbols

    def _find_line_containing(
        self,
        lines: list[str],
        text: str,
        start: int = 0,
    ) -> int:
        """Find the line number containing the given text."""
        return _find_line_containing_impl(lines, text, start)

    def _find_closing_brace(self, lines: list[str], start: int) -> int:
        """Find the closing brace for a rule."""
        return _find_closing_brace_impl(lines, start)

    def _make_range(self, start_line: int, start_char: int, end_line: int, end_char: int) -> Range:
        """Create an LSP Range."""
        return _make_range_impl(start_line, start_char, end_line, end_char)
