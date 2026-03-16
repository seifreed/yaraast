from __future__ import annotations

import pytest

from yaraast.ast.expressions import BooleanLiteral
from yaraast.lexer.tokens import Token, TokenType
from yaraast.yarax.ast_nodes import WithStatement
from yaraast.yarax.parser import YaraXParser


def _tok(token_type: TokenType, value: str | int | None) -> Token:
    return Token(token_type, value, 1, 1)


def _manual_parser(tokens: list[Token]) -> YaraXParser:
    parser = YaraXParser("rule seed { condition: true }")
    parser.tokens = [*tokens, _tok(TokenType.EOF, None)]
    parser.current = 0
    return parser


def test_parse_condition_supports_with_and_fallback_condition() -> None:
    with_expr = YaraXParser("with local = 1: true").parse_condition()
    assert isinstance(with_expr, WithStatement)

    plain = YaraXParser("true").parse_condition()
    assert plain == BooleanLiteral(True)


def test_parse_with_declaration_rejects_invalid_variable_token() -> None:
    parser = _manual_parser(
        [
            _tok(TokenType.IDENTIFIER, "with"),
            _tok(TokenType.INTEGER, 1),
        ],
    )
    parser._consume_keyword("with")
    with pytest.raises(Exception, match="Expected variable"):
        parser._parse_with_declaration()
