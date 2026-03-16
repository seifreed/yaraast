"""Range helpers for LSP document symbols."""

from __future__ import annotations

from typing import Any

from lsprotocol.types import Position, Range

from yaraast.ast.base import Location
from yaraast.lsp.structure import find_quoted_value_range, make_range


def node_range(node: Any, source_text: str) -> Range | None:
    location = getattr(node, "location", None)
    if location is None:
        return None
    return location_to_symbol_range(location, source_text)


def node_value_range(node: Any, source_text: str, value: str) -> Range | None:
    base_range = node_range(node, source_text)
    if base_range is None:
        return None
    return narrow_range_to_value(source_text, base_range, value) or base_range


def quoted_value_range_from_node_line(lines: list[str], node: Any, value: str) -> Range | None:
    location = getattr(node, "location", None)
    if location is None:
        return None
    return find_quoted_value_range(lines, location.line - 1, value)


def narrow_range_to_value(source_text: str, base_range: Range, value: str) -> Range | None:
    lines = source_text.split("\n")
    start_line = base_range.start.line
    end_line = min(base_range.end.line, len(lines) - 1)
    for line_num in range(start_line, end_line + 1):
        line = lines[line_num]
        start_char = base_range.start.character if line_num == start_line else 0
        end_char = base_range.end.character if line_num == end_line else len(line)
        segment = line[start_char:end_char]
        offset = segment.find(value)
        if offset >= 0:
            return make_range(line_num, start_char + offset, start_char + offset + len(value))
        quoted = segment.find(f'"{value}"')
        if quoted >= 0:
            return make_range(
                line_num, start_char + quoted + 1, start_char + quoted + 1 + len(value)
            )
    return None


def location_to_symbol_range(location: Location, source_text: str) -> Range:
    start_line = location.line - 1
    start_character = max(0, location.column - 1)
    if location.end_line is not None and location.end_column is not None:
        return Range(
            start=Position(line=start_line, character=start_character),
            end=Position(
                line=location.end_line - 1,
                character=max(start_character + 1, location.end_column - 1),
            ),
        )
    lines = source_text.split("\n")
    line_text = lines[start_line] if 0 <= start_line < len(lines) else ""
    return Range(
        start=Position(line=start_line, character=start_character),
        end=Position(line=start_line, character=min(len(line_text), start_character + 1)),
    )
