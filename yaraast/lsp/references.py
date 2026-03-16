"""References provider for YARA Language Server."""

from __future__ import annotations

from lsprotocol.types import Location, Position

from yaraast.lsp.runtime import DocumentContext, LspRuntime, ReferenceRecord


class ReferencesProvider:
    """Provides find-all-references functionality."""

    def __init__(self, runtime: LspRuntime | None = None) -> None:
        self.runtime = runtime

    def get_references(
        self,
        text: str,
        position: Position,
        uri: str,
        include_declaration: bool = True,
    ) -> list[Location]:
        """
        Find all references to the symbol at the given position.

        Args:
            text: The YARA source code
            position: The cursor position
            uri: The document URI
            include_declaration: Whether to include the declaration

        Returns:
            List of locations where the symbol is referenced
        """
        return [
            record.location
            for record in self.get_reference_records(text, position, uri, include_declaration)
        ]

    def get_reference_records(
        self,
        text: str,
        position: Position,
        uri: str,
        include_declaration: bool = True,
    ) -> list[ReferenceRecord]:
        """Find typed references for the symbol at the given position."""
        doc = (
            self.runtime.ensure_document(uri, text)
            if self.runtime and uri
            else DocumentContext(uri, text)
        )
        resolved = (
            self.runtime.resolve_symbol(uri, text, position)
            if self.runtime and uri
            else doc.resolve_symbol(position)
        )

        if resolved is not None:
            if resolved.kind == "string":
                return doc.find_string_reference_records(
                    resolved.normalized_name,
                    include_declaration=include_declaration,
                )
            if resolved.kind == "rule":
                if self.runtime:
                    return self.runtime.find_rule_reference_records(
                        resolved.normalized_name,
                        include_declaration=include_declaration,
                        current_uri=uri,
                    )
                return doc.rule_reference_records(
                    resolved.normalized_name,
                    include_declaration=include_declaration,
                )

        return []
