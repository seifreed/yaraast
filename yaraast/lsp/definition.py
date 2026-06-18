"""Definition provider for YARA Language Server."""

from __future__ import annotations

from lsprotocol.types import Location, Position, Range

from yaraast.lsp.runtime import DocumentContext, LspRuntime, path_to_uri, uri_to_path
from yaraast.lsp.utils import path_exists


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
        if not isinstance(text, str):
            msg = "Definition text must be a string"
            raise TypeError(msg)
        if not isinstance(position, Position):
            msg = "position must be an LSP Position"
            raise TypeError(msg)

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
                rule_scope = doc.rule_name_at_position(resolved.range.start)
                return doc.find_string_definition(resolved.normalized_name, rule_scope=rule_scope)
            if resolved.kind == "rule":
                if self.runtime:
                    return self.runtime.find_rule_definition(resolved.normalized_name, uri)
                return doc.find_rule_definition(resolved.normalized_name)
            if resolved.kind == "include":
                include_location = self._find_include_definition(
                    uri,
                    resolved.normalized_name,
                )
                if include_location is not None:
                    return include_location
            return None
        return None

    def _find_include_definition(self, uri: str, include_path: str) -> Location | None:
        """Find the target file of an include."""
        target_uri = None
        if self.runtime is not None:
            target_uri = self.runtime.resolve_include_target_uri(uri, include_path)
        if target_uri is None:
            doc_path = uri_to_path(uri)
            if doc_path is None:
                return None
            try:
                include_file = (doc_path.parent / include_path).resolve()
            except OSError:
                return None
            if not path_exists(include_file):
                return None
            target_uri = path_to_uri(include_file)
        return Location(
            uri=target_uri,
            range=Range(
                start=Position(line=0, character=0),
                end=Position(line=0, character=0),
            ),
        )
