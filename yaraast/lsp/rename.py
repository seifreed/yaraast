"""Rename provider for YARA Language Server."""

from __future__ import annotations

from typing import TYPE_CHECKING

from lsprotocol.types import Position, Range, TextEdit, WorkspaceEdit

from yaraast.lsp.utils import get_word_at_position

if TYPE_CHECKING:
    pass


class RenameProvider:
    """Provides rename functionality."""

    def prepare_rename(self, text: str, position: Position) -> Range | None:
        """
        Prepare for rename operation.

        Args:
            text: The YARA source code
            position: The cursor position

        Returns:
            Range of the symbol to rename or None if not renameable
        """
        word, word_range = get_word_at_position(text, position)

        if not word:
            return None

        # Only allow renaming of string identifiers and rule names
        if word.startswith("$") or self._is_rule_name(text, position):
            return word_range

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
        word, _ = get_word_at_position(text, position)

        if not word:
            return None

        edits = []
        lines = text.split("\n")

        # Handle string identifier renaming
        if word.startswith("$"):
            base_identifier = word
            # Ensure new_name has $ prefix
            if not new_name.startswith("$"):
                new_name = f"${new_name}"

            # Find all occurrences of this identifier and its variants
            for line_num, line in enumerate(lines):
                # Check for all variants: $id, #id, @id, !id
                base_name = base_identifier[1:]  # Remove $
                for variant, new_variant in [
                    (base_identifier, new_name),
                    (f"#{base_name}", f"#{new_name[1:]}"),
                    (f"@{base_name}", f"@{new_name[1:]}"),
                    (f"!{base_name}", f"!{new_name[1:]}"),
                ]:
                    col = 0
                    while True:
                        col = line.find(variant, col)
                        if col == -1:
                            break

                        # Check if it's a whole word
                        if (col == 0 or not line[col - 1].isalnum()) and (
                            col + len(variant) >= len(line)
                            or not line[col + len(variant)].isalnum()
                        ):
                            edits.append(
                                TextEdit(
                                    range=Range(
                                        start=Position(line=line_num, character=col),
                                        end=Position(
                                            line=line_num,
                                            character=col + len(variant),
                                        ),
                                    ),
                                    new_text=new_variant,
                                )
                            )
                        col += len(variant)

        # Handle rule name renaming
        elif self._is_rule_name(text, position):
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
                        edits.append(
                            TextEdit(
                                range=Range(
                                    start=Position(line=line_num, character=col),
                                    end=Position(line=line_num, character=col + len(word)),
                                ),
                                new_text=new_name,
                            )
                        )
                    col += len(word)

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
