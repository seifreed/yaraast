from __future__ import annotations

import pytest

from yaraast.ast.expressions import ArrayAccess, Identifier, IntegerLiteral, ParenthesesExpression
from yaraast.lexer.tokens import Token, TokenType
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    DictExpression,
    ListExpression,
    SliceExpression,
    TupleExpression,
)
from yaraast.yarax.generator import YaraXGenerator
from yaraast.yarax.parser import YaraXParser


def _tok(
    token_type: TokenType,
    value: str | int | None,
    column: int = 1,
    length: int = 1,
) -> Token:
    return Token(token_type, value, 1, column, length)


def _manual_parser(tokens: list[Token]) -> YaraXParser:
    parser = YaraXParser("rule seed { condition: true }")
    parser.tokens = [*tokens, _tok(TokenType.EOF, None)]
    parser.current = 0
    return parser


def test_parser_collections_spread_dot_variant_and_regular_element_paths() -> None:
    parser = _manual_parser(
        [
            _tok(TokenType.LBRACKET, "["),
            _tok(TokenType.DOT, ".", column=2),
            _tok(TokenType.DOT, ".", column=3),
            _tok(TokenType.DOT, ".", column=4),
            _tok(TokenType.IDENTIFIER, "arr", column=5),
            _tok(TokenType.COMMA, ",", column=8),
            _tok(TokenType.INTEGER, 1, column=10),
            _tok(TokenType.RBRACKET, "]", column=11),
        ],
    )
    expr = parser._parse_list_or_comprehension()
    assert isinstance(expr, ListExpression)
    assert len(expr.elements) == 2


def test_parser_collections_comprehensions_cover_no_if_and_keyword_in_paths() -> None:
    parser = _manual_parser(
        [
            _tok(TokenType.LBRACKET, "["),
            _tok(TokenType.IDENTIFIER, "x"),
            _tok(TokenType.IDENTIFIER, "for"),
            _tok(TokenType.IDENTIFIER, "x"),
            _tok(TokenType.IDENTIFIER, "in"),
            _tok(TokenType.IDENTIFIER, "items"),
            _tok(TokenType.RBRACKET, "]"),
        ],
    )
    arr = parser._parse_list_or_comprehension()
    assert isinstance(arr, ArrayComprehension)
    assert arr.condition is None

    parser = _manual_parser(
        [
            _tok(TokenType.LBRACE, "{"),
            _tok(TokenType.IDENTIFIER, "k"),
            _tok(TokenType.COLON, ":"),
            _tok(TokenType.IDENTIFIER, "v"),
            _tok(TokenType.IDENTIFIER, "for"),
            _tok(TokenType.IDENTIFIER, "k"),
            _tok(TokenType.IDENTIFIER, "in"),
            _tok(TokenType.IDENTIFIER, "items"),
            _tok(TokenType.RBRACE, "}"),
        ],
    )
    dct = parser._parse_dict_or_comprehension()
    assert isinstance(dct, DictComprehension)
    assert dct.value_variable is None
    assert dct.condition is None


def test_parser_collections_regular_dict_parentheses_and_slice_variants() -> None:
    parser = _manual_parser(
        [
            _tok(TokenType.LBRACE, "{"),
            _tok(TokenType.STRING, "a"),
            _tok(TokenType.COLON, ":"),
            _tok(TokenType.INTEGER, 1),
            _tok(TokenType.COMMA, ","),
            _tok(TokenType.STRING, "b"),
            _tok(TokenType.COLON, ":"),
            _tok(TokenType.INTEGER, 2),
            _tok(TokenType.RBRACE, "}"),
        ],
    )
    regular = parser._parse_dict_or_comprehension()
    assert isinstance(regular, DictExpression)
    assert len(regular.items) == 2

    parenthesized = YaraXParser("(1)").parse_expression()
    assert isinstance(parenthesized, ParenthesesExpression)

    indexed_parenthesized = YaraXParser("([x for x in arr])[0]").parse_expression()
    assert isinstance(indexed_parenthesized, ArrayAccess)
    assert isinstance(indexed_parenthesized.array, ParenthesesExpression)
    assert isinstance(indexed_parenthesized.array.expression, ArrayComprehension)
    assert YaraXGenerator().visit(indexed_parenthesized) == "([x for x in arr])[0]"

    trailing_tuple = YaraXParser("(1,)").parse_expression()
    assert isinstance(trailing_tuple, TupleExpression)
    tuple_value = trailing_tuple.elements[0]
    assert isinstance(tuple_value, IntegerLiteral)
    assert tuple_value.value == 1

    parser = _manual_parser(
        [
            _tok(TokenType.INTEGER, 1),
            _tok(TokenType.COLON, ":"),
            _tok(TokenType.RBRACKET, "]"),
        ],
    )
    slice_no_stop = parser._parse_bracket_access(Identifier(name="arr"))
    assert isinstance(slice_no_stop, SliceExpression)
    assert slice_no_stop.stop is None

    parser = _manual_parser(
        [
            _tok(TokenType.COLON, ":"),
            _tok(TokenType.COLON, ":"),
            _tok(TokenType.INTEGER, 2),
            _tok(TokenType.RBRACKET, "]"),
        ],
    )
    slice_step_only = parser._parse_bracket_access(Identifier(name="arr"))
    assert isinstance(slice_step_only, SliceExpression)
    assert slice_step_only.start is None
    assert slice_step_only.step is not None

    parser = _manual_parser(
        [
            _tok(TokenType.INTEGER, 1),
            _tok(TokenType.COLON, ":"),
            _tok(TokenType.INTEGER, 4),
            _tok(TokenType.COLON, ":"),
            _tok(TokenType.RBRACKET, "]"),
        ],
    )
    slice_empty_step = parser._parse_bracket_access(Identifier(name="arr"))
    assert isinstance(slice_empty_step, SliceExpression)
    assert slice_empty_step.step is None


def test_parser_collections_spread_list_requires_separator() -> None:
    parser = _manual_parser(
        [
            _tok(TokenType.LBRACKET, "["),
            _tok(TokenType.DOT, ".", column=2),
            _tok(TokenType.DOT, ".", column=3),
            _tok(TokenType.DOT, ".", column=4),
            _tok(TokenType.IDENTIFIER, "arr", column=5),
            _tok(TokenType.INTEGER, 1, column=9),
            _tok(TokenType.RBRACKET, "]", column=10),
        ],
    )
    with pytest.raises(Exception, match="Expected ',' or ']'"):
        parser._parse_list_or_comprehension()
