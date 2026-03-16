"""Additional real coverage for binary expression parsing."""

from __future__ import annotations

from yaraast.ast.expressions import BinaryExpression
from yaraast.lexer import Lexer
from yaraast.parser import Parser


def test_parse_bitwise_expression_chain() -> None:
    parser = Parser()
    parser.tokens = Lexer("1 & 2 | 3 ^ 4").tokenize()
    parser.current = 0
    expr = parser._parse_or_expression()

    assert isinstance(expr, BinaryExpression)
    assert expr.operator == "^"
    assert isinstance(expr.left, BinaryExpression)
    assert expr.left.operator == "|"
    assert isinstance(expr.left.left, BinaryExpression)
    assert expr.left.left.operator == "&"


def test_parse_shift_expression_chain() -> None:
    parser = Parser()
    parser.tokens = Lexer("1 << 2 >> 3").tokenize()
    parser.current = 0
    expr = parser._parse_or_expression()

    assert isinstance(expr, BinaryExpression)
    assert expr.operator == ">>"
    assert isinstance(expr.left, BinaryExpression)
    assert expr.left.operator == "<<"
