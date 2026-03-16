"""Selection range provider for YARA Language Server."""

from __future__ import annotations

from lsprotocol.types import Position, Range, SelectionRange

from yaraast.lsp.runtime import LspRuntime
from yaraast.lsp.selection_range_helpers import (
    build_selection_parent as helper_build_selection_parent,
)
from yaraast.lsp.selection_range_helpers import (
    find_enclosing_rule_range as helper_find_enclosing_rule_range,
)
from yaraast.lsp.selection_range_helpers import (
    find_enclosing_section_range as helper_find_enclosing_section_range,
)
from yaraast.lsp.selection_range_helpers import line_range as helper_line_range
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
        lines = text.split("\n")
        doc = self.runtime.get_document(uri) if self.runtime and uri else None

        result: list[SelectionRange] = []
        for position in positions:
            if position.line >= len(lines):
                continue

            word, word_range = get_word_at_position(text, position)
            line_range = helper_line_range(lines, position.line)

            parent: SelectionRange | None = SelectionRange(range=line_range, parent=None)
            if doc is not None:
                parent = helper_build_selection_parent(
                    doc.text,
                    position,
                    line_range,
                    self._find_enclosing_rule_range,
                    self._find_enclosing_section_range,
                )

            if word:
                result.append(SelectionRange(range=word_range, parent=parent))
            else:
                result.append(parent)
        return result

    def _find_enclosing_rule_range(self, text: str, position: Position) -> Range | None:
        return helper_find_enclosing_rule_range(text, position)

    def _find_enclosing_section_range(self, text: str, position: Position) -> Range | None:
        return helper_find_enclosing_section_range(text, position)
