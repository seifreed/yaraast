from __future__ import annotations

import pytest

from yaraast.lexer.tokens import TokenType as T
from yaraast.yaral.enhanced_parser import EnhancedYaraLParser
from yaraast.yaral.lexer import YaraLToken
from yaraast.yaral.tokens import YaraLTokenType


def _tok(tt: T, value, yt: YaraLTokenType | None = None) -> YaraLToken:
    return YaraLToken(type=tt, value=value, line=1, column=1, length=1, yaral_type=yt)


def _set_tokens(p: EnhancedYaraLParser, toks: list[YaraLToken]) -> None:
    p.tokens = [*toks, _tok(T.EOF, None, YaraLTokenType.EOF)]
    p.current = 0


def test_enhanced_parse_rule_all_sections_and_skip_unknown_token() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
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
            _tok(T.IDENTIFIER, "enabled"),
            _tok(T.EQ, "="),
            _tok(T.BOOLEAN_TRUE, True),
            _tok(T.IDENTIFIER, "events"),
            _tok(T.COLON, ":"),
            _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "event_type"),
            _tok(T.EQ, "="),
            _tok(T.STRING, "LOGIN"),
            _tok(T.IDENTIFIER, "match"),
            _tok(T.COLON, ":"),
            _tok(T.IDENTIFIER, "m"),
            _tok(T.EQ, "="),
            _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "event_type"),
            _tok(T.IDENTIFIER, "over"),
            _tok(T.IDENTIFIER, "5m", YaraLTokenType.TIME_LITERAL),
            _tok(T.CONDITION, "condition"),
            _tok(T.COLON, ":"),
            _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.IDENTIFIER, "outcome"),
            _tok(T.COLON, ":"),
            _tok(T.STRING_IDENTIFIER, "$score", YaraLTokenType.EVENT_VAR),
            _tok(T.EQ, "="),
            _tok(T.INTEGER, "1"),
            _tok(T.IDENTIFIER, "options"),
            _tok(T.COLON, ":"),
            _tok(T.IDENTIFIER, "flag"),
            _tok(T.EQ, "="),
            _tok(T.IDENTIFIER, "true"),
            _tok(T.IDENTIFIER, "limit"),
            _tok(T.EQ, "="),
            _tok(T.INTEGER, "7"),
            _tok(T.RBRACE, "}"),
        ],
    )

    rule = p._parse_rule()
    assert rule.name == "r1"
    assert rule.meta is not None and len(rule.meta.entries) == 2
    assert rule.events is not None and rule.events.statements
    assert rule.match is not None and len(rule.match.variables) == 1
    assert rule.match.variables[0].variable == "m"
    assert rule.condition is not None
    assert rule.outcome is not None and len(rule.outcome.assignments) == 1
    assert rule.options is not None
    assert rule.options.options["flag"] is True
    assert rule.options.options["limit"] == 7


def test_enhanced_parse_meta_section_values_and_fallback() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
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
            _tok(T.BOOLEAN_FALSE, False),
            _tok(T.IDENTIFIER, "mode"),
            _tok(T.EQ, "="),
            _tok(T.IDENTIFIER, "custom"),
            _tok(T.RBRACE, "}"),
        ],
    )

    meta = p._parse_meta_section()
    values = {entry.key: entry.value for entry in meta.entries}
    assert values == {"text": "abc", "count": 5, "enabled": False, "mode": "custom"}


def test_enhanced_parse_options_section_values_skip_and_error() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "options"),
            _tok(T.COLON, ":"),
            _tok(T.PLUS, "+"),
            _tok(T.IDENTIFIER, "enabled"),
            _tok(T.EQ, "="),
            _tok(T.BOOLEAN_TRUE, True),
            _tok(T.IDENTIFIER, "strict"),
            _tok(T.EQ, "="),
            _tok(T.BOOLEAN_FALSE, False),
            _tok(T.IDENTIFIER, "label"),
            _tok(T.EQ, "="),
            _tok(T.STRING, "x"),
            _tok(T.IDENTIFIER, "mode"),
            _tok(T.EQ, "="),
            _tok(T.IDENTIFIER, "custom"),
            _tok(T.RBRACE, "}"),
        ],
    )

    options = p._parse_options_section()
    assert options.options == {
        "enabled": True,
        "strict": False,
        "label": "x",
        "mode": "custom",
    }

    p2 = EnhancedYaraLParser("")
    _set_tokens(p2, [_tok(T.PLUS, "+")])
    with pytest.raises(ValueError, match="Expected option value"):
        p2._parse_option_value()
