"""Additional branch coverage for YARA-X collection parser helpers (no mocks)."""

from __future__ import annotations

from yaraast.ast.expressions import Expression, Identifier, ParenthesesExpression
from yaraast.lexer.tokens import Token, TokenType
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    DictExpression,
    ListExpression,
    SpreadOperator,
    TupleExpression,
)
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


def _parse_expr(text: str) -> Expression:
    return YaraXParser(text).parse_expression()


def test_empty_and_trailing_collection_variants() -> None:
    assert _parse_expr("[]") == ListExpression(elements=[])

    empty_dict = _parse_expr("{}")
    assert isinstance(empty_dict, DictExpression)
    assert empty_dict.items == []

    empty_tuple = _parse_expr("()")
    assert isinstance(empty_tuple, TupleExpression)
    assert empty_tuple.elements == []

    trailing = _parse_expr('[1, "x",]')
    assert isinstance(trailing, ListExpression)
    assert len(trailing.elements) == 2

    trailing_dict = _parse_expr('{"a": 1,}')
    assert isinstance(trailing_dict, DictExpression)
    assert len(trailing_dict.items) == 1


def test_spread_and_keyword_keyword_fallback_paths() -> None:
    parser = _manual_parser(
        [
            _tok(TokenType.LBRACKET, "["),
            _tok(TokenType.DOUBLE_DOT, "..", column=2, length=2),
            _tok(TokenType.DOT, ".", column=4),
            _tok(TokenType.IDENTIFIER, "arr", column=5),
            _tok(TokenType.RBRACKET, "]", column=8),
        ],
    )
    spread_list = parser._parse_list_or_comprehension()
    assert isinstance(spread_list, ListExpression)
    assert isinstance(spread_list.elements[0], SpreadOperator)

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
    comp = parser._parse_list_or_comprehension()
    assert isinstance(comp, ArrayComprehension)
    assert comp.variable == "x"

    parser = _manual_parser(
        [
            _tok(TokenType.LBRACE, "{"),
            _tok(TokenType.IDENTIFIER, "k"),
            _tok(TokenType.COLON, ":"),
            _tok(TokenType.IDENTIFIER, "v"),
            _tok(TokenType.IDENTIFIER, "for"),
            _tok(TokenType.IDENTIFIER, "k"),
            _tok(TokenType.COMMA, ","),
            _tok(TokenType.IDENTIFIER, "v"),
            _tok(TokenType.IDENTIFIER, "in"),
            _tok(TokenType.IDENTIFIER, "data"),
            _tok(TokenType.IDENTIFIER, "if"),
            _tok(TokenType.IDENTIFIER, "v"),
            _tok(TokenType.RBRACE, "}"),
        ],
    )
    dict_comp = parser._parse_dict_or_comprehension()
    assert isinstance(dict_comp, DictComprehension)
    assert dict_comp.value_variable == "v"
    assert dict_comp.condition is not None


def test_tuple_or_parentheses_single_value() -> None:
    parser = _manual_parser(
        [
            _tok(TokenType.LPAREN, "("),
            _tok(TokenType.IDENTIFIER, "x"),
            _tok(TokenType.RPAREN, ")"),
        ],
    )
    single_parenthesized = parser._parse_tuple_or_parentheses()
    assert isinstance(single_parenthesized, ParenthesesExpression)
    assert single_parenthesized.expression == Identifier(name="x")
