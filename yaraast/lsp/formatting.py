"""Formatting provider for YARA Language Server."""

from __future__ import annotations

from typing import TYPE_CHECKING

from lsprotocol.types import Position, Range, TextEdit

from yaraast.codegen.generator import CodeGenerator
from yaraast.parser.parser import Parser

if TYPE_CHECKING:
    pass


class FormattingProvider:
    """Provides code formatting functionality."""

    def format_document(self, text: str) -> list[TextEdit]:
        """
        Format the entire document.

        Args:
            text: The YARA source code

        Returns:
            List of text edits to apply
        """
        try:
            # Parse the document
            parser = Parser(text)
            ast = parser.parse()

            # Generate formatted code
            generator = CodeGenerator()
            formatted_text = generator.generate(ast)

            # Calculate the range for the entire document
            lines = text.split("\n")
            doc_range = Range(
                start=Position(line=0, character=0),
                end=Position(line=len(lines), character=0),
            )

            # Return a single edit that replaces the entire document
            return [TextEdit(range=doc_range, new_text=formatted_text)]

        except Exception:
            # If formatting fails, return no edits
            return []

    def format_range(
        self,
        text: str,
        start: Position,
        end: Position,
    ) -> list[TextEdit]:
        """
        Format a specific range in the document.

        Args:
            text: The YARA source code
            start: Start position of the range
            end: End position of the range

        Returns:
            List of text edits to apply
        """
        # For now, format the entire document
        # A more sophisticated implementation would only format the selected range
        return self.format_document(text)
