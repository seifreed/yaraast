"""Rename provider for YARA Language Server."""

from __future__ import annotations

from lsprotocol.types import Position, Range, WorkspaceEdit

from yaraast.lsp.runtime import DocumentContext, LspRuntime


class RenameProvider:
    """Provides rename functionality."""

    def __init__(self, runtime: LspRuntime | None = None) -> None:
        self.runtime = runtime

    def prepare_rename(self, text: str, position: Position, uri: str | None = None) -> Range | None:
        """
        Prepare for rename operation.

        Args:
            text: The YARA source code
            position: The cursor position

        Returns:
            Range of the symbol to rename or None if not renameable
        """
        resolved = (
            self.runtime.resolve_symbol(uri, text, position)
            if self.runtime and uri
            else DocumentContext(uri or "file://local.yar", text).resolve_symbol(position)
        )
        if resolved is not None and resolved.kind in {"string", "rule"}:
            return resolved.range
        return None

    def rename(
        self,
        text: str,
        position: Position,
        new_name: str,
        uri: str,
    ) -> WorkspaceEdit | None:
        """
        Perform rename operation.

        Args:
            text: The YARA source code
            position: The position of the symbol to rename
            new_name: The new name
            uri: The document URI

        Returns:
            WorkspaceEdit with all the changes
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
        if resolved is None:
            return None

        # Handle string identifier renaming
        if resolved.kind == "string":
            base_identifier = resolved.normalized_name
            edits = doc.build_string_rename_edits(base_identifier, new_name)
            if edits:
                return WorkspaceEdit(changes={uri: edits})
            return None

        # Handle rule name renaming
        if resolved.kind == "rule":
            if self.runtime:
                changes = self.runtime.rename_rule(resolved.normalized_name, new_name)
                if changes:
                    return WorkspaceEdit(changes=changes)
            edits = doc.rename_rule_edits(resolved.normalized_name, new_name)
            if edits:
                return WorkspaceEdit(changes={uri: edits})

        return None

    def _is_rule_name(self, text: str, position: Position) -> bool:
        """Check if position is at a rule name."""
        lines = text.split("\n")
        if position.line >= len(lines):
            return False

        line = lines[position.line]
        return "rule" in line and "{" not in line
