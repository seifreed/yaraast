from __future__ import annotations

import pytest

from yaraast.lexer.tokens import Token, TokenType
from yaraast.yarax.parser import YaraXParser


def _tok(token_type: TokenType, value: str | int | None) -> Token:
    return Token(token_type, value, 1, 1)


def _manual_parser(tokens: list[Token]) -> YaraXParser:
    parser = YaraXParser("rule seed { condition: true }")
    parser.tokens = [*tokens, _tok(TokenType.EOF, None)]
    parser.current = 0
    return parser


def test_yarax_parser_helper_keyword_peek_and_consume_paths() -> None:
    parser = _manual_parser([_tok(TokenType.IDENTIFIER, "for"), _tok(TokenType.IDENTIFIER, "x")])
    assert parser._check_keyword("for")
    assert parser._consume_keyword("for").value == "for"
    assert parser._peek_ahead(0).value == "x"
    assert parser._peek_ahead(10) is None

    parser2 = _manual_parser([_tok(TokenType.IDENTIFIER, "nope")])
    assert not parser2._check_keyword("for")
    with pytest.raises(Exception, match="Expected keyword 'for'"):
        parser2._consume_keyword("for")


def test_yarax_parser_helper_consume_arrow_and_consume_errors() -> None:
    parser = _manual_parser([_tok(TokenType.ASSIGN, "="), _tok(TokenType.GT, ">")])
    assert parser._consume_arrow() is None

    parser_bad_arrow = _manual_parser([_tok(TokenType.ASSIGN, "="), _tok(TokenType.INTEGER, 1)])
    with pytest.raises(Exception, match="Expected '>'"):
        parser_bad_arrow._consume_arrow()

    parser_consume = _manual_parser([_tok(TokenType.INTEGER, 7)])
    assert parser_consume._consume(TokenType.INTEGER, "need integer").value == 7

    parser_bad_consume = _manual_parser([_tok(TokenType.STRING, "x")])
    with pytest.raises(Exception, match="need integer"):
        parser_bad_consume._consume(TokenType.INTEGER, "need integer")


def test_yarax_parser_helper_end_of_input_paths() -> None:
    parser = _manual_parser([])
    assert not parser._check_keyword("for")
    assert parser._peek_ahead(1) is None
