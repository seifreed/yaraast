"""Definition provider for YARA Language Server."""

from __future__ import annotations

from lsprotocol.types import Location, Position, Range

from yaraast.lsp.runtime import DocumentContext, LspRuntime, path_to_uri, uri_to_path


class DefinitionProvider:
    """Provides go-to-definition functionality."""

    def __init__(self, runtime: LspRuntime | None = None) -> None:
        self.runtime = runtime

    def get_definition(
        self,
        text: str,
        position: Position,
        uri: str,
    ) -> Location | list[Location] | None:
        """
        Get definition location for the symbol at the given position.

        Args:
            text: The YARA source code
            position: The cursor position
            uri: The document URI

        Returns:
            Location of the definition or None
        """
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
                return doc.find_string_definition(resolved.normalized_name)
            if resolved.kind == "rule":
                if self.runtime:
                    return self.runtime.find_rule_definition(resolved.normalized_name, uri)
                return doc.find_rule_definition(resolved.normalized_name)
            if resolved.kind == "include":
                include_location = self._find_include_definition(uri, resolved.normalized_name)
                if include_location is not None:
                    return include_location
            return None
        return None

    def _find_string_definition(
        self,
        text: str,
        identifier: str,
        uri: str,
    ) -> Location | None:
        """Find the definition of a string identifier."""
        return DocumentContext(uri, text).find_string_definition(identifier)

    def _find_rule_definition(self, text: str, rule_name: str, uri: str) -> Location | None:
        """Find the definition of a rule."""
        return DocumentContext(uri, text).find_rule_definition(rule_name)

    def _find_include_definition(self, uri: str, include_path: str) -> Location | None:
        """Find the target file of an include."""
        doc_path = uri_to_path(uri)
        if doc_path is None:
            return None
        include_file = (doc_path.parent / include_path).resolve()
        if not include_file.exists():
            return None
        return Location(
            uri=path_to_uri(include_file),
            range=Range(
                start=Position(line=0, character=0),
                end=Position(line=0, character=0),
            ),
        )
