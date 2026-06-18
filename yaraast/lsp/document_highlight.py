"""Document highlight provider for YARAAST LSP."""

from __future__ import annotations

from lsprotocol.types import DocumentHighlight, DocumentHighlightKind, Position

from yaraast.lsp.document_context import DocumentContext
from yaraast.lsp.document_highlight_helpers import (
    highlight_identifier,
    highlight_string_identifier,
    simple_highlight,
)
from yaraast.lsp.document_types import ReferenceRecord
from yaraast.lsp.utils import get_word_at_position


class DocumentHighlightProvider:
    """Provide document highlighting for symbols."""

    def get_highlights(self, text: str, position: Position) -> list[DocumentHighlight]:
        """Get all highlights for symbol at position."""
        if not isinstance(text, str):
            msg = "Document highlight text must be a string"
            raise TypeError(msg)
        if not isinstance(position, Position):
            msg = "position must be an LSP Position"
            raise TypeError(msg)

        word, _word_range = get_word_at_position(text, position)
        if not word:
            return []

        ctx = DocumentContext("file:///document-highlight.yar", text)
        resolved = ctx.resolve_symbol(position)
        if resolved is not None:
            if resolved.kind == "string":
                rule_scope = ctx.rule_name_at_position(resolved.range.start)
                return self._highlight_string_identifier(
                    text, resolved.normalized_name, rule_scope=rule_scope
                )
            if resolved.kind == "rule":
                return self._highlight_identifier(text, resolved.normalized_name)
            if self._is_local_shadow(resolved.kind, resolved.normalized_name, word, ctx):
                return [
                    DocumentHighlight(
                        range=resolved.range,
                        kind=DocumentHighlightKind.Text,
                    )
                ]

        # Check if it's a string identifier
        if word.startswith(("$", "#", "@", "!")):
            if not word.startswith("$"):
                word = f"${word[1:]}"
            return self._highlight_string_identifier(text, word)

        # Check if it's a rule name or other identifier
        return self._highlight_identifier(text, word)

    def _highlight_string_identifier(
        self, text: str, identifier: str, *, rule_scope: str | None = None
    ) -> list[DocumentHighlight]:
        """Highlight all occurrences of a string identifier."""
        records = self._get_string_reference_records(text, identifier, rule_scope=rule_scope)
        if records:
            return self._highlights_from_records(records)
        return highlight_string_identifier(text, identifier)

    def _highlight_identifier(self, text: str, identifier: str) -> list[DocumentHighlight]:
        """Highlight all occurrences of a regular identifier."""
        records = self._get_rule_reference_records(text, identifier)
        if records:
            return self._highlights_from_records(records)
        return highlight_identifier(text, identifier)

    def _simple_highlight(self, text: str, word: str) -> list[DocumentHighlight]:
        """Simple text-based highlighting fallback."""
        return simple_highlight(text, word)

    def _is_local_shadow(
        self,
        kind: str,
        normalized_name: str,
        word: str,
        ctx: DocumentContext,
    ) -> bool:
        if kind != "identifier":
            return False
        if word.startswith(("$", "#", "@", "!")):
            return ctx.find_string_definition(normalized_name) is not None
        return ctx.find_rule_definition(normalized_name) is not None

    def _get_string_reference_records(
        self, text: str, identifier: str, *, rule_scope: str | None = None
    ) -> list[ReferenceRecord]:
        ctx = DocumentContext("file:///document-highlight.yar", text)
        return ctx.find_string_reference_records(
            identifier, include_declaration=True, rule_scope=rule_scope
        )

    def _get_rule_reference_records(self, text: str, identifier: str) -> list[ReferenceRecord]:
        ctx = DocumentContext("file:///document-highlight.yar", text)
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
