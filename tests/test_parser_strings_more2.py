"""Additional branch coverage for parser string helpers (no mocks)."""

from __future__ import annotations

import pytest

from yaraast.lexer.tokens import Token, TokenType
from yaraast.parser._shared import ParserError
from yaraast.parser.parser import Parser


def _t(tt: TokenType, value) -> Token:
    return Token(type=tt, value=value, line=1, column=1)


def _parser_with_tokens(tokens: list[Token]) -> Parser:
    p = Parser("rule seed { condition: true }")
    p.tokens = [*tokens, _t(TokenType.EOF, None)]
    p.current = 0
    return p


def test_parse_strings_section_success_and_main_errors() -> None:
    p = _parser_with_tokens(
        [
            _t(TokenType.STRING_IDENTIFIER, "$"),
            _t(TokenType.ASSIGN, "="),
            _t(TokenType.STRING, "abc"),
            _t(TokenType.NOCASE, "nocase"),
            _t(TokenType.STRING_IDENTIFIER, "$h"),
            _t(TokenType.ASSIGN, "="),
            _t(TokenType.HEX_STRING, "AA BB"),
            _t(TokenType.STRING_IDENTIFIER, "$r"),
            _t(TokenType.ASSIGN, "="),
            _t(TokenType.REGEX, "x+"),
            _t(TokenType.CONDITION, "condition"),
        ],
    )
    out = p._parse_strings_section()
    assert len(out) == 3
    assert out[0].identifier == "$anon_1"
    assert out[0].modifiers and out[0].modifiers[0].name == "nocase"

    p = _parser_with_tokens([_t(TokenType.STRING_IDENTIFIER, "$a")])
    with pytest.raises(ParserError, match="Expected '=' after string identifier"):
        p._parse_strings_section()

    p = _parser_with_tokens(
        [
            _t(TokenType.STRING_IDENTIFIER, "$a"),
            _t(TokenType.ASSIGN, "="),
            _t(TokenType.IDENTIFIER, "bad"),
        ],
    )
    with pytest.raises(ParserError, match="Invalid string value"):
        p._parse_strings_section()


def test_parse_string_modifiers_xor_variants_and_errors() -> None:
    p = _parser_with_tokens(
        [
            _t(TokenType.NOCASE, "nocase"),
            _t(TokenType.WIDE, "wide"),
            _t(TokenType.XOR_MOD, "xor"),
            _t(TokenType.LPAREN, "("),
            _t(TokenType.INTEGER, 3),
            _t(TokenType.MINUS, "-"),
            _t(TokenType.INTEGER, 9),
            _t(TokenType.RPAREN, ")"),
        ],
    )
    mods = p._parse_string_modifiers()
    assert [m.name for m in mods[:2]] == ["nocase", "wide"]
    assert mods[2].name == "xor"
    assert mods[2].value == (3, 9)

    p = _parser_with_tokens(
        [
            _t(TokenType.XOR_MOD, "xor"),
            _t(TokenType.LPAREN, "("),
            _t(TokenType.INTEGER, 5),
            _t(TokenType.RPAREN, ")"),
        ],
    )
    mods = p._parse_string_modifiers()
    assert mods[0].value == 5

    p = _parser_with_tokens(
        [_t(TokenType.XOR_MOD, "xor"), _t(TokenType.LPAREN, "("), _t(TokenType.RPAREN, ")")]
    )
    with pytest.raises(ParserError, match="Expected integer or range in xor"):
        p._parse_string_modifiers()

    p = _parser_with_tokens(
        [
            _t(TokenType.XOR_MOD, "xor"),
            _t(TokenType.LPAREN, "("),
            _t(TokenType.INTEGER, 2),
            _t(TokenType.MINUS, "-"),
            _t(TokenType.RPAREN, ")"),
        ],
    )
    with pytest.raises(ParserError, match="Expected integer after '-'"):
        p._parse_string_modifiers()

    p = _parser_with_tokens(
        [
            _t(TokenType.XOR_MOD, "xor"),
            _t(TokenType.LPAREN, "("),
            _t(TokenType.INTEGER, 2),
        ],
    )
    with pytest.raises(ParserError, match="Expected '\\)' after xor parameter"):
        p._parse_string_modifiers()


def test_parse_hex_string_error_conversion() -> None:
    p = _parser_with_tokens([_t(TokenType.EOF, None)])
    with pytest.raises(ParserError):
        p._parse_hex_string("AA [1-")
