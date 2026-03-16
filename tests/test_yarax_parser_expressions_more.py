from __future__ import annotations

import pytest

from yaraast.ast.expressions import ArrayAccess, FunctionCall, Identifier, IntegerLiteral
from yaraast.lexer.tokens import Token, TokenType
from yaraast.yarax.ast_nodes import LambdaExpression, PatternMatch, SliceExpression, TupleIndexing
from yaraast.yarax.parser import YaraXParser


def _tok(token_type: TokenType, value: str | int | None) -> Token:
    return Token(token_type, value, 1, 1)


def _manual_parser(tokens: list[Token]) -> YaraXParser:
    parser = YaraXParser("rule seed { condition: true }")
    parser.tokens = [*tokens, _tok(TokenType.EOF, None)]
    parser.current = 0
    return parser


def test_parse_primary_expression_supports_slice_and_array_access() -> None:
    parser = _manual_parser(
        [
            _tok(TokenType.IDENTIFIER, "arr"),
            _tok(TokenType.LBRACKET, "["),
            _tok(TokenType.COLON, ":"),
            _tok(TokenType.INTEGER, 3),
            _tok(TokenType.RBRACKET, "]"),
        ],
    )
    sliced = parser.parse_primary_expression()
    assert isinstance(sliced, SliceExpression)
    assert sliced.start is None
    assert isinstance(sliced.stop, IntegerLiteral)

    parser = _manual_parser(
        [
            _tok(TokenType.IDENTIFIER, "arr"),
            _tok(TokenType.LBRACKET, "["),
            _tok(TokenType.INTEGER, 1),
            _tok(TokenType.COLON, ":"),
            _tok(TokenType.INTEGER, 4),
            _tok(TokenType.RBRACKET, "]"),
        ],
    )
    sliced_with_start = parser.parse_primary_expression()
    assert isinstance(sliced_with_start, SliceExpression)
    assert isinstance(sliced_with_start.start, IntegerLiteral)
    assert isinstance(sliced_with_start.stop, IntegerLiteral)

    parser = _manual_parser(
        [
            _tok(TokenType.IDENTIFIER, "arr"),
            _tok(TokenType.LBRACKET, "["),
            _tok(TokenType.INTEGER, 1),
            _tok(TokenType.RBRACKET, "]"),
        ],
    )
    indexed = parser.parse_primary_expression()
    assert isinstance(indexed, ArrayAccess)
    assert indexed.array == Identifier(name="arr")


def test_parse_lambda_supports_empty_and_multi_parameter_forms() -> None:
    empty_lambda = YaraXParser("lambda: 1").parse_expression()
    assert isinstance(empty_lambda, LambdaExpression)
    assert empty_lambda.parameters == []

    multi_lambda = YaraXParser("lambda x, y, z: x").parse_expression()
    assert isinstance(multi_lambda, LambdaExpression)
    assert multi_lambda.parameters == ["x", "y", "z"]


def test_parse_pattern_match_supports_default_and_trailing_comma() -> None:
    expr = YaraXParser("match x { 1 => 2, foo => 3, _ => 4, }").parse_expression()
    assert isinstance(expr, PatternMatch)
    assert len(expr.cases) == 2
    assert expr.default == IntegerLiteral(4)


def test_parse_bracket_access_supports_slice_tuple_indexing_and_array_access() -> None:
    parser = _manual_parser(
        [
            _tok(TokenType.COLON, ":"),
            _tok(TokenType.INTEGER, 2),
            _tok(TokenType.RBRACKET, "]"),
        ],
    )
    sliced = parser._parse_bracket_access(Identifier(name="arr"))
    assert isinstance(sliced, SliceExpression)
    assert sliced.start is None

    parser = _manual_parser(
        [
            _tok(TokenType.INTEGER, 0),
            _tok(TokenType.RBRACKET, "]"),
        ],
    )
    tuple_index = parser._parse_bracket_access(
        FunctionCall(function="foo", arguments=[]),
    )
    assert isinstance(tuple_index, TupleIndexing)

    parser = _manual_parser(
        [
            _tok(TokenType.INTEGER, 1),
            _tok(TokenType.RBRACKET, "]"),
        ],
    )
    array_index = parser._parse_bracket_access(Identifier(name="arr"))
    assert isinstance(array_index, ArrayAccess)


def test_parse_expression_and_primary_support_function_call_tuple_indexing() -> None:
    parser = _manual_parser(
        [
            _tok(TokenType.IDENTIFIER, "foo"),
            _tok(TokenType.LPAREN, "("),
            _tok(TokenType.RPAREN, ")"),
            _tok(TokenType.LBRACKET, "["),
            _tok(TokenType.INTEGER, 0),
            _tok(TokenType.RBRACKET, "]"),
        ],
    )
    expr = parser.parse_expression()
    assert isinstance(expr, TupleIndexing)
    assert isinstance(expr.tuple_expr, FunctionCall)
    assert expr.tuple_expr.function == "foo"


def test_parse_lambda_requires_parameter_after_comma() -> None:
    parser = _manual_parser(
        [
            _tok(TokenType.IDENTIFIER, "lambda"),
            _tok(TokenType.IDENTIFIER, "x"),
            _tok(TokenType.COMMA, ","),
            _tok(TokenType.COLON, ":"),
        ],
    )
    with pytest.raises(Exception, match="Expected parameter"):
        parser._parse_lambda()
