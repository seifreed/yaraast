from __future__ import annotations

import pytest

from yaraast.lexer.tokens import TokenType as T
from yaraast.yaral._shared import YaraLParserError
from yaraast.yaral.lexer import YaraLToken
from yaraast.yaral.parser import YaraLParser
from yaraast.yaral.tokens import YaraLTokenType


def _tok(token_type: T, value: object, yaral_type: YaraLTokenType | None = None) -> YaraLToken:
    return YaraLToken(
        type=token_type,
        value=value,
        line=1,
        column=1,
        length=1,
        yaral_type=yaral_type,
    )


def _set_tokens(parser: YaraLParser, tokens: list[YaraLToken]) -> None:
    parser.tokens = tokens
    parser.current = 0


def test_parse_match_section_with_multiple_variables_and_skip_token() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "match"),
            _tok(T.COLON, ":"),
            _tok(T.PLUS, "+"),
            _tok(T.STRING_IDENTIFIER, "$e1", YaraLTokenType.EVENT_VAR),
            _tok(T.IDENTIFIER, "over"),
            _tok(T.IDENTIFIER, "every"),
            _tok(T.IDENTIFIER, "5m", YaraLTokenType.TIME_LITERAL),
            _tok(T.STRING_IDENTIFIER, "$e2", YaraLTokenType.EVENT_VAR),
            _tok(T.IDENTIFIER, "over"),
            _tok(T.INTEGER, "2"),
            _tok(T.IDENTIFIER, "hours"),
            _tok(T.RBRACE, "}"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )

    section = parser._parse_match_section()
    assert len(section.variables) == 2
    assert section.variables[0].variable == "e1"
    assert section.variables[0].time_window.modifier == "every"
    assert section.variables[0].time_window.duration == 5
    assert section.variables[0].time_window.unit == "m"
    assert section.variables[1].variable == "e2"
    assert section.variables[1].time_window.duration == 2
    assert section.variables[1].time_window.unit == "h"


def test_parse_match_section_comma_separated_variables() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "match"),
            _tok(T.COLON, ":"),
            _tok(T.STRING_IDENTIFIER, "$e1", YaraLTokenType.EVENT_VAR),
            _tok(T.COMMA, ","),
            _tok(T.STRING_IDENTIFIER, "$e2", YaraLTokenType.EVENT_VAR),
            _tok(T.IDENTIFIER, "over"),
            _tok(T.IDENTIFIER, "5m", YaraLTokenType.TIME_LITERAL),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )

    match = parser._parse_match_section()
    assert len(match.variables) == 2
    assert match.variables[0].variable == "e1"
    assert match.variables[1].variable == "e2"
    assert match.variables[0].time_window.duration == 5
    assert match.variables[1].time_window.duration == 5


def test_parse_time_window_time_literal_integer_default_and_error() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "10h", YaraLTokenType.TIME_LITERAL),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    tw = parser._parse_time_window()
    assert tw.duration == 10
    assert tw.unit == "h"

    parser2 = YaraLParser("")
    _set_tokens(
        parser2,
        [
            _tok(T.IDENTIFIER, "nonsense", YaraLTokenType.TIME_LITERAL),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    with pytest.raises(YaraLParserError, match="Expected time window"):
        parser2._parse_time_window()

    parser3 = YaraLParser("")
    _set_tokens(
        parser3,
        [_tok(T.INTEGER, "7"), _tok(T.IDENTIFIER, "days"), _tok(T.EOF, None, YaraLTokenType.EOF)],
    )
    tw2 = parser3._parse_time_window("every")
    assert tw2.duration == 7
    assert tw2.unit == "d"
    assert tw2.modifier == "every"

    parser4 = YaraLParser("")
    _set_tokens(parser4, [_tok(T.INTEGER, "3"), _tok(T.EOF, None, YaraLTokenType.EOF)])
    tw3 = parser4._parse_time_window()
    assert tw3.duration == 3
    assert tw3.unit == "m"

    parser5 = YaraLParser("")
    _set_tokens(parser5, [_tok(T.STRING, "bad"), _tok(T.EOF, None, YaraLTokenType.EOF)])
    with pytest.raises(YaraLParserError, match="Expected time window"):
        parser5._parse_time_window()
