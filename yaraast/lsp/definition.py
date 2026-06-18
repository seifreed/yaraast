"""Definition provider for YARA Language Server."""

from __future__ import annotations

from lsprotocol.types import Location, Position, Range

from yaraast.lsp.runtime import LspRuntime, get_document_context


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

        doc = get_document_context(self.runtime, uri, text, fallback_uri=uri or "")
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
                target_uri = (
                    self.runtime.resolve_include_target_uri(uri, resolved.normalized_name)
                    if self.runtime is not None
                    else doc.get_include_target_uri(resolved.normalized_name)
                )
                if target_uri is None:
                    return None
                return Location(
                    uri=target_uri,
                    range=Range(
                        start=Position(line=0, character=0),
                        end=Position(line=0, character=0),
                    ),
                )
            return None
        return None
