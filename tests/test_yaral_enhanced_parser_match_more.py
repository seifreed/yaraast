"""Direct coverage for enhanced parser match mixin."""

from __future__ import annotations

from yaraast.lexer.tokens import TokenType as T
from yaraast.yaral.enhanced_parser import EnhancedYaraLParser
from yaraast.yaral.lexer import YaraLToken
from yaraast.yaral.tokens import YaraLTokenType


def _tok(tt: T, value, yt: YaraLTokenType | None = None) -> YaraLToken:
    return YaraLToken(type=tt, value=value, line=1, column=1, length=1, yaral_type=yt)


def _set_tokens(p: EnhancedYaraLParser, toks: list[YaraLToken]) -> None:
    p.tokens = [*toks, _tok(T.EOF, None, YaraLTokenType.EOF)]
    p.current = 0


def test_parse_match_variable_with_field_and_over_condition() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "m"),
            _tok(T.EQ, "="),
            _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "principal"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "ip"),
            _tok(T.IDENTIFIER, "over"),
            _tok(T.INTEGER, 5),
            _tok(T.IDENTIFIER, "m"),
        ],
    )

    parsed = p._parse_match_variable()
    assert parsed.variable == "m"
    assert parsed.time_window.duration == 5
    assert parsed.time_window.unit == "m"


def test_parse_match_variable_without_optional_parts() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(p, [_tok(T.IDENTIFIER, "m"), _tok(T.EQ, "=")])
    parsed = p._parse_match_variable()
    assert parsed.variable == "m"
    assert parsed.time_window.duration == 1
    assert parsed.time_window.unit == "m"


def test_parse_match_section_with_variable_time_window_and_skip_token() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "match"),
            _tok(T.COLON, ":"),
            _tok(T.IDENTIFIER, "v"),
            _tok(T.EQ, "="),
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "event_type"),
            _tok(T.IDENTIFIER, "over"),
            _tok(T.INTEGER, 1),
            _tok(T.IDENTIFIER, "h"),
            _tok(T.PLUS, "+"),
            _tok(T.IDENTIFIER, "over"),
            _tok(T.IDENTIFIER, "10m", YaraLTokenType.TIME_LITERAL),
            _tok(T.RBRACE, "}"),
        ],
    )

    section = p._parse_match_section()
    assert len(section.variables) == 1
    assert section.variables[0].variable == "v"
    assert section.variables[0].time_window.duration == 10
    assert section.variables[0].time_window.unit == "m"
