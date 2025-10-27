"""References provider for YARA Language Server."""

from __future__ import annotations

from typing import TYPE_CHECKING

from lsprotocol.types import Location, Position, Range

from yaraast.lsp.utils import get_word_at_position

if TYPE_CHECKING:
    pass


class ReferencesProvider:
    """Provides find-all-references functionality."""

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
        word, _ = get_word_at_position(text, position)

        if not word:
            return []

        locations = []
        lines = text.split("\n")

        # Normalize string identifiers
        if (
            word.startswith("$")
            or word.startswith("#")
            or word.startswith("@")
            or word.startswith("!")
        ):
            base_identifier = word.lstrip("#@!")
            if not base_identifier.startswith("$"):
                base_identifier = f"${base_identifier}"

            # Find all occurrences of this identifier and its variants
            for line_num, line in enumerate(lines):
                # Check for all variants: $id, #id, @id, !id
                for variant in [
                    base_identifier,
                    f"#{base_identifier[1:]}",
                    f"@{base_identifier[1:]}",
                    f"!{base_identifier[1:]}",
                ]:
                    col = 0
                    while True:
                        col = line.find(variant, col)
                        if col == -1:
                            break

                        # Check if it's a whole word (not part of another identifier)
                        if (col == 0 or not line[col - 1].isalnum()) and (
                            col + len(variant) >= len(line)
                            or not line[col + len(variant)].isalnum()
                        ):
                            locations.append(
                                Location(
                                    uri=uri,
                                    range=Range(
                                        start=Position(line=line_num, character=col),
                                        end=Position(
                                            line=line_num,
                                            character=col + len(variant),
                                        ),
                                    ),
                                )
                            )
                        col += len(variant)

        else:
            # Find all occurrences of the word
            for line_num, line in enumerate(lines):
                col = 0
                while True:
                    col = line.find(word, col)
                    if col == -1:
                        break

                    # Check if it's a whole word
                    if (col == 0 or not line[col - 1].isalnum()) and (
                        col + len(word) >= len(line) or not line[col + len(word)].isalnum()
                    ):
                        locations.append(
                            Location(
                                uri=uri,
                                range=Range(
                                    start=Position(line=line_num, character=col),
                                    end=Position(line=line_num, character=col + len(word)),
                                ),
                            )
                        )
                    col += len(word)

        return locations
