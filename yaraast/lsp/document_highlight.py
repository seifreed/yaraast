"""Document highlight provider for YARAAST LSP."""

from __future__ import annotations

from lsprotocol.types import DocumentHighlight, DocumentHighlightKind, Position

from yaraast.lsp.document_context import DocumentContext
from yaraast.lsp.document_highlight_helpers import (
    highlight_identifier as helper_highlight_identifier,
)
from yaraast.lsp.document_highlight_helpers import (
    highlight_string_identifier as helper_highlight_string_identifier,
)
from yaraast.lsp.document_highlight_helpers import simple_highlight as helper_simple_highlight
from yaraast.lsp.document_types import ReferenceRecord
from yaraast.lsp.utils import get_word_at_position


class DocumentHighlightProvider:
    """Provide document highlighting for symbols."""

    def get_highlights(self, text: str, position: Position) -> list[DocumentHighlight]:
        """Get all highlights for symbol at position."""
        word, word_range = get_word_at_position(text, position)
        if not word:
            return []

        # Check if it's a string identifier
        if word.startswith("$"):
            return self._highlight_string_identifier(text, word)

        # Check if it's a rule name or other identifier
        return self._highlight_identifier(text, word)

    def _highlight_string_identifier(self, text: str, identifier: str) -> list[DocumentHighlight]:
        """Highlight all occurrences of a string identifier."""
        records = self._get_string_reference_records(text, identifier)
        if records:
            return self._highlights_from_records(records)
        return helper_highlight_string_identifier(text, identifier)

    def _highlight_identifier(self, text: str, identifier: str) -> list[DocumentHighlight]:
        """Highlight all occurrences of a regular identifier."""
        records = self._get_rule_reference_records(text, identifier)
        if records:
            return self._highlights_from_records(records)
        return helper_highlight_identifier(text, identifier)

    def _simple_highlight(self, text: str, word: str) -> list[DocumentHighlight]:
        """Simple text-based highlighting fallback."""
        return helper_simple_highlight(text, word)

    def _get_string_reference_records(self, text: str, identifier: str) -> list[ReferenceRecord]:
        ctx = DocumentContext("file:///document-highlight.yar", text)
        if ctx.ast() is None:
            return []
        return ctx.find_string_reference_records(identifier, include_declaration=True)

    def _get_rule_reference_records(self, text: str, identifier: str) -> list[ReferenceRecord]:
        ctx = DocumentContext("file:///document-highlight.yar", text)
        if ctx.ast() is None:
            return []
        return ctx.rule_reference_records(identifier, include_declaration=True)

    def _highlights_from_records(self, records: list[ReferenceRecord]) -> list[DocumentHighlight]:
        highlights: list[DocumentHighlight] = []
        for record in records:
            kind = (
                DocumentHighlightKind.Write
                if record.role == "declaration"
                else DocumentHighlightKind.Read
            )
            highlights.append(DocumentHighlight(range=record.location.range, kind=kind))
        return highlights
