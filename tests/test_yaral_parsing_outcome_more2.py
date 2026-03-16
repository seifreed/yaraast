from __future__ import annotations

from yaraast.lexer.tokens import TokenType as T
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


def test_parse_outcome_section_skips_unknown_and_aggregation_multiple_args() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "outcome"),
            _tok(T.COLON, ":"),
            _tok(T.PLUS, "+"),
            _tok(T.STRING_IDENTIFIER, "$score", YaraLTokenType.EVENT_VAR),
            _tok(T.EQ, "="),
            _tok(T.IDENTIFIER, "count"),
            _tok(T.LPAREN, "("),
            _tok(T.INTEGER, "1"),
            _tok(T.COMMA, ","),
            _tok(T.INTEGER, "2"),
            _tok(T.COMMA, ","),
            _tok(T.INTEGER, "3"),
            _tok(T.RPAREN, ")"),
            _tok(T.RBRACE, "}"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )

    section = parser._parse_outcome_section()
    assert len(section.assignments) == 1
    expr = section.assignments[0].expression
    assert expr.function == "count"
    assert expr.arguments == [1, 2, 3]
