"""Selection range provider for YARA Language Server."""

from __future__ import annotations

from lsprotocol.types import Position, Range, SelectionRange

from yaraast.lsp.runtime import LspRuntime
from yaraast.lsp.selection_range_helpers import (
    build_selection_parent,
    find_enclosing_rule_range,
    find_enclosing_section_range,
    line_range,
)
from yaraast.lsp.utils import get_word_at_position


class SelectionRangeProvider:
    """Provide progressively larger selections."""

    def __init__(self, runtime: LspRuntime | None = None) -> None:
        self.runtime = runtime

    def get_selection_ranges(
        self,
        text: str,
        positions: list[Position],
        uri: str | None = None,
    ) -> list[SelectionRange]:
        if not isinstance(text, str):
            msg = "Selection range text must be a string"
            raise TypeError(msg)
        if not isinstance(positions, list):
            msg = "positions must be a list of LSP Position values"
            raise TypeError(msg)
        if any(not isinstance(position, Position) for position in positions):
            msg = "positions must be a list of LSP Position values"
            raise TypeError(msg)

        lines = text.split("\n")
        doc = self.runtime.ensure_document(uri, text) if self.runtime and uri else None

        result: list[SelectionRange] = []
        for position in positions:
            if position.line >= len(lines):
                continue

            word, word_range = get_word_at_position(text, position)
            current_line_range = line_range(lines, position.line)

            parent: SelectionRange | None = SelectionRange(range=current_line_range, parent=None)
            if doc is not None:
                parent = build_selection_parent(
                    doc.text,
                    position,
                    current_line_range,
                    self._find_enclosing_rule_range,
                    self._find_enclosing_section_range,
                )

            if word:
                result.append(SelectionRange(range=word_range, parent=parent))
            elif parent is not None:
                result.append(parent)
        return result

    def _find_enclosing_rule_range(self, text: str, position: Position) -> Range | None:
        return find_enclosing_rule_range(text, position)

    def _find_enclosing_section_range(self, text: str, position: Position) -> Range | None:
        return find_enclosing_section_range(text, position)
