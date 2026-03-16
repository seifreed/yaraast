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


def test_parse_rule_with_all_sections_and_unknown_skip() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "rule"),
            _tok(T.IDENTIFIER, "r1"),
            _tok(T.LBRACE, "{"),
            _tok(T.PLUS, "+"),
            _tok(T.IDENTIFIER, "meta"),
            _tok(T.COLON, ":"),
            _tok(T.IDENTIFIER, "author"),
            _tok(T.EQ, "="),
            _tok(T.STRING, "me"),
            _tok(T.IDENTIFIER, "events"),
            _tok(T.COLON, ":"),
            _tok(T.STRING_IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.EQ, "="),
            _tok(T.STRING_IDENTIFIER, "$x", YaraLTokenType.EVENT_VAR),
            _tok(T.IDENTIFIER, "match"),
            _tok(T.COLON, ":"),
            _tok(T.STRING_IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.IDENTIFIER, "over"),
            _tok(T.IDENTIFIER, "5m", YaraLTokenType.TIME_LITERAL),
            _tok(T.CONDITION, "condition"),
            _tok(T.COLON, ":"),
            _tok(T.STRING_IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.IDENTIFIER, "outcome"),
            _tok(T.COLON, ":"),
            _tok(T.STRING_IDENTIFIER, "$score", YaraLTokenType.EVENT_VAR),
            _tok(T.EQ, "="),
            _tok(T.INTEGER, "1"),
            _tok(T.IDENTIFIER, "options"),
            _tok(T.COLON, ":"),
            _tok(T.IDENTIFIER, "flag"),
            _tok(T.EQ, "="),
            _tok(T.BOOLEAN_TRUE, True),
            _tok(T.RBRACE, "}"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )

    rule = parser._parse_rule()
    assert rule.name == "r1"
    assert rule.meta is not None and len(rule.meta.entries) == 1
    assert rule.events is not None
    assert rule.match is not None and len(rule.match.variables) == 1
    assert rule.condition is not None
    assert rule.outcome is not None and len(rule.outcome.assignments) == 1
    assert rule.options is not None and rule.options.options["flag"] is True


def test_parse_meta_section_value_variants_and_fallback() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "meta"),
            _tok(T.COLON, ":"),
            _tok(T.IDENTIFIER, "text"),
            _tok(T.EQ, "="),
            _tok(T.STRING, "abc"),
            _tok(T.IDENTIFIER, "count"),
            _tok(T.EQ, "="),
            _tok(T.INTEGER, "5"),
            _tok(T.IDENTIFIER, "enabled"),
            _tok(T.EQ, "="),
            _tok(T.BOOLEAN_TRUE, True),
            _tok(T.IDENTIFIER, "disabled"),
            _tok(T.EQ, "="),
            _tok(T.BOOLEAN_FALSE, False),
            _tok(T.IDENTIFIER, "mode"),
            _tok(T.EQ, "="),
            _tok(T.IDENTIFIER, "custom"),
            _tok(T.RBRACE, "}"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )

    meta = parser._parse_meta_section()
    values = {entry.key: entry.value for entry in meta.entries}
    assert values == {
        "text": "abc",
        "count": 5,
        "enabled": True,
        "disabled": False,
        "mode": "custom",
    }


def test_parse_options_section_value_variants_and_skip() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "options"),
            _tok(T.COLON, ":"),
            _tok(T.PLUS, "+"),
            _tok(T.IDENTIFIER, "text"),
            _tok(T.EQ, "="),
            _tok(T.STRING, "abc"),
            _tok(T.IDENTIFIER, "count"),
            _tok(T.EQ, "="),
            _tok(T.INTEGER, "5"),
            _tok(T.IDENTIFIER, "enabled"),
            _tok(T.EQ, "="),
            _tok(T.BOOLEAN_TRUE, True),
            _tok(T.IDENTIFIER, "disabled"),
            _tok(T.EQ, "="),
            _tok(T.BOOLEAN_FALSE, False),
            _tok(T.IDENTIFIER, "mode"),
            _tok(T.EQ, "="),
            _tok(T.IDENTIFIER, "custom"),
            _tok(T.RBRACE, "}"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )

    options = parser._parse_options_section()
    assert options.options == {
        "text": "abc",
        "count": 5,
        "enabled": True,
        "disabled": False,
        "mode": "custom",
    }
