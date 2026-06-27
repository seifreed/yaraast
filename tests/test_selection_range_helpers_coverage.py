"""Coverage for LSP selection-range hierarchy helpers."""

from __future__ import annotations

from typing import Any

from lsprotocol.types import Position

from yaraast.lsp import selection_range_helpers as helpers

RULE_TEXT = (
    "rule alpha {\n"
    "    meta:\n"
    '        author = "x"\n'
    "    strings:\n"
    '        $a = "y"\n'
    "    condition:\n"
    "        $a\n"
    "}\n"
)


def _chain_depth(selection: Any) -> int:
    depth = 0
    node = selection
    while node is not None:
        depth += 1
        node = node.parent
    return depth


def test_selection_parent_inside_section_is_three_levels() -> None:
    lines = RULE_TEXT.split("\n")
    selection = helpers.build_selection_parent(
        RULE_TEXT,
        Position(line=2, character=8),
        helpers.line_range(lines, 2),
        helpers.find_enclosing_rule_range,
        helpers.find_enclosing_section_range,
    )
    # line -> section -> rule
    assert _chain_depth(selection) == 3


def test_selection_parent_on_rule_line_is_two_levels() -> None:
    lines = RULE_TEXT.split("\n")
    selection = helpers.build_selection_parent(
        RULE_TEXT,
        Position(line=0, character=2),
        helpers.line_range(lines, 0),
        helpers.find_enclosing_rule_range,
        helpers.find_enclosing_section_range,
    )
    # line -> rule (no section level)
    assert _chain_depth(selection) == 2


def test_enclosing_ranges_return_none_outside_any_rule() -> None:
    position = Position(line=0, character=0)
    assert helpers.find_enclosing_rule_range("\n\n", position) is None
    assert helpers.find_enclosing_section_range("\n\n", position) is None


def test_enclosing_ranges_resolve_inside_rule() -> None:
    assert helpers.find_enclosing_rule_range(RULE_TEXT, Position(line=2, character=8)) is not None
    assert (
        helpers.find_enclosing_section_range(RULE_TEXT, Position(line=2, character=8)) is not None
    )
