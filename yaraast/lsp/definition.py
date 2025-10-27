"""Definition provider for YARA Language Server."""

from __future__ import annotations

from typing import TYPE_CHECKING

from lsprotocol.types import Location, Position, Range

from yaraast.lsp.utils import get_word_at_position
from yaraast.parser.parser import Parser

if TYPE_CHECKING:
    pass


class DefinitionProvider:
    """Provides go-to-definition functionality."""

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
        word, _ = get_word_at_position(text, position)

        if not word:
            return None

        # Handle string identifiers
        if (
            word.startswith("$")
            or word.startswith("#")
            or word.startswith("@")
            or word.startswith("!")
        ):
            # Normalize to base identifier
            base_identifier = word.lstrip("#@!")
            if not base_identifier.startswith("$"):
                base_identifier = f"${base_identifier}"

            return self._find_string_definition(text, base_identifier, uri)

        # Handle rule references
        return self._find_rule_definition(text, word, uri)

    def _find_string_definition(
        self,
        text: str,
        identifier: str,
        uri: str,
    ) -> Location | None:
        """Find the definition of a string identifier."""
        try:
            parser = Parser(text)
            ast = parser.parse()

            lines = text.split("\n")
            for rule in ast.rules:
                for string_def in rule.strings:
                    if string_def.identifier == identifier:
                        # Find the line where this string is defined
                        for line_num, line in enumerate(lines):
                            if identifier in line and "=" in line:
                                col = line.index(identifier)
                                return Location(
                                    uri=uri,
                                    range=Range(
                                        start=Position(line=line_num, character=col),
                                        end=Position(
                                            line=line_num,
                                            character=col + len(identifier),
                                        ),
                                    ),
                                )

        except Exception:
            pass

        return None

    def _find_rule_definition(self, text: str, rule_name: str, uri: str) -> Location | None:
        """Find the definition of a rule."""
        try:
            parser = Parser(text)
            ast = parser.parse()

            lines = text.split("\n")
            for rule in ast.rules:
                if rule.name == rule_name:
                    # Find the line where this rule is defined
                    for line_num, line in enumerate(lines):
                        if "rule" in line and rule_name in line:
                            col = line.index(rule_name)
                            return Location(
                                uri=uri,
                                range=Range(
                                    start=Position(line=line_num, character=col),
                                    end=Position(line=line_num, character=col + len(rule_name)),
                                ),
                            )

        except Exception:
            pass

        return None
