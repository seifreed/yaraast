"""Additional real tests for LSP utilities (no mocks)."""

from __future__ import annotations

from lsprotocol.types import Position

from yaraast.ast.base import Location, YaraFile
from yaraast.ast.expressions import BinaryExpression
from yaraast.ast.rules import Rule
from yaraast.lexer.tokens import Token, TokenType
from yaraast.lsp.utf16 import utf8_col_to_utf16
from yaraast.lsp.utils import (
    find_node_at_position,
    get_word_at_position,
    location_to_range,
    offset_to_position,
    position_to_offset,
    token_to_range,
)
from yaraast.parser import Parser


def test_token_and_location_to_range() -> None:
    token = Token(type=TokenType.IDENTIFIER, value="rule", line=2, column=4)
    token_range = token_to_range(token)
    assert token_range.start.line == 1
    assert token_range.start.character == 3
    assert token_range.end.character == 7

    source_width_token = Token(
        type=TokenType.INTEGER,
        value=1,
        line=2,
        column=10,
        length=3,
    )
    source_width_range = token_to_range(source_width_token)
    assert source_width_range.end.character == 12

    loc = Location(line=3, column=2, file=None)
    loc_range = location_to_range(loc)
    assert loc_range.start.line == 2
    assert loc_range.end.character == loc_range.start.character + 1

    text = "rule alpha { condition: true }"
    text_loc = Location(line=1, column=text.index("alpha") + 1, file=None)
    text_range = location_to_range(text_loc, source_text=text)
    assert text_range.end.character > text_range.start.character + 1

    emoji_line = "    /* 😀😀 */ sample"
    sample_start = emoji_line.index("sample")
    emoji_loc = Location(
        line=1,
        column=sample_start + 1,
        end_line=1,
        end_column=sample_start + len("sample") + 1,
        file=None,
    )
    emoji_range = location_to_range(emoji_loc, source_text=emoji_line)
    assert emoji_range.start.character == utf8_col_to_utf16(emoji_line, sample_start)
    assert emoji_range.end.character == utf8_col_to_utf16(
        emoji_line,
        sample_start + len("sample"),
    )


def test_position_offset_roundtrip() -> None:
    text = "one\ntwo\nthree"
    pos = Position(line=1, character=2)
    offset = position_to_offset(text, pos)
    roundtrip = offset_to_position(text, offset)
    assert roundtrip.line == pos.line
    assert roundtrip.character == pos.character


def test_position_offset_roundtrip_uses_lsp_utf16_columns() -> None:
    text = "a😀b\nnext"

    after_emoji = Position(line=0, character=3)
    offset = position_to_offset(text, after_emoji)

    assert offset == 2
    assert offset_to_position(text, offset) == after_emoji


def test_get_word_at_position_and_find_node() -> None:
    text = "rule $a"
    pos = Position(line=0, character=6)
    word, word_range = get_word_at_position(text, pos)
    assert word == "$a"
    assert word_range.start.character == 5

    rule = Rule(name="r1")
    rule.location = Location(line=1, column=1, file=None)
    ast = YaraFile(rules=[rule])

    found = find_node_at_position(ast, Position(line=0, character=0))
    assert found is rule


def test_get_word_at_position_returns_lsp_utf16_range() -> None:
    word, word_range = get_word_at_position("😀 $a", Position(line=0, character=3))

    assert word == "$a"
    assert word_range.start.character == 3
    assert word_range.end.character == 5


def test_location_to_range_uses_parser_span_when_available() -> None:
    text = """
rule alpha {
  condition:
    true
}
""".lstrip()
    ast = Parser().parse(text)
    rule = ast.rules[0]
    assert rule.location is not None

    rule_range = location_to_range(rule.location, source_text=text)
    assert rule_range.start.line == 0
    assert rule_range.end.line >= rule_range.start.line
    assert rule_range.end.character > rule_range.start.character


def test_parser_span_uses_source_width_for_size_suffix_literals() -> None:
    text = "rule sample { condition: filesize < 1KB }\n"
    ast = Parser().parse(text)
    condition = ast.rules[0].condition
    assert isinstance(condition, BinaryExpression)
    size_literal = condition.right
    assert size_literal.location is not None

    size_range = location_to_range(size_literal.location, source_text=text)

    assert size_range.end.character - size_range.start.character == len("1KB")


def test_find_node_at_position_prefers_smallest_span_containing_position() -> None:
    text = """
rule sample {
  condition:
    alpha and beta
}
""".lstrip()
    ast = Parser().parse(text)
    condition = ast.rules[0].condition
    assert condition is not None

    found = find_node_at_position(ast, Position(line=2, character=5))
    assert found is not None
    assert found is not ast.rules[0]
