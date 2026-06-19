"""Document symbols provider for YARA Language Server."""

from __future__ import annotations

import logging
import time

from lsprotocol.types import DocumentSymbol

from yaraast.lsp.runtime import LspRuntime, get_document_context
from yaraast.lsp.symbol_tree_builder import (
    build_document_symbols,
)

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
        if not isinstance(text, str):
            msg = "Symbols text must be a string"
            raise TypeError(msg)
        if uri is not None and not isinstance(uri, str):
            msg = "Symbols URI must be a string or None"
            raise TypeError(msg)

        started = time.perf_counter()
        doc = None
        symbols: list[DocumentSymbol]
        symbol_build_succeeded = False

        try:
            doc = get_document_context(self.runtime, uri, text, fallback_uri=uri or "")
            cached = doc.get_cached("lsp:document_symbols")
            if cached is not None:
                return list(cached)
            lines = text.split("\n")
            symbols = build_document_symbols(doc, lines)
            symbol_build_succeeded = True

        except Exception:
            logger.debug("Operation failed in %s", __name__, exc_info=True)
            # If parsing fails, return empty symbols
            symbols = []

        if doc is not None and symbol_build_succeeded:
            doc.set_cached("lsp:document_symbols", list(symbols))
        if self.runtime is not None:
            self.runtime.record_latency(
                "document_symbols", (time.perf_counter() - started) * 1000.0
            )
        return list(symbols)
