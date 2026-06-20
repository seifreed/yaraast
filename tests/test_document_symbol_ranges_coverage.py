"""Coverage for LSP document symbol range computation helpers."""

from __future__ import annotations

from lsprotocol.types import Position, Range

from yaraast.ast.base import Location
from yaraast.lsp.document_symbol_ranges import (
    location_to_symbol_range,
    narrow_range_to_value,
    node_value_range,
)

TEXT = 'rule alpha {\n    author = "value_here"\n}'


def test_location_to_symbol_range_multi_column_same_line() -> None:
    result = location_to_symbol_range(Location(line=2, column=5, end_line=2, end_column=11), TEXT)
    assert result.start.character == 4
    assert result.end.character == 10


def test_location_to_symbol_range_without_end_falls_back_to_single_line() -> None:
    result = location_to_symbol_range(Location(line=2, column=5), TEXT)
    assert result.start.line == 1
    assert result.end.line == 1


def test_narrow_range_to_value_plain_and_quoted() -> None:
    base = Range(start=Position(line=1, character=0), end=Position(line=1, character=30))
    assert narrow_range_to_value(TEXT, base, "author") is not None
    assert narrow_range_to_value(TEXT, base, "value_here") is not None
    assert narrow_range_to_value(TEXT, base, "absent") is None


def test_node_value_range_uses_location() -> None:
    class _Node:
        location = Location(line=2, column=5, end_line=2, end_column=30)

    assert node_value_range(_Node(), TEXT, "author") is not None
    assert node_value_range(object(), TEXT, "author") is None
