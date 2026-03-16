"""Additional direct coverage for EnhancedYaraLParser helper mixin methods."""

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


def test_parse_udm_paths_and_access() -> None:
    p = EnhancedYaraLParser("")

    _set_tokens(
        p, [_tok(T.IDENTIFIER, "metadata"), _tok(T.DOT, "."), _tok(T.IDENTIFIER, "event_type")]
    )
    path = p._parse_udm_field_path()
    assert path.parts == ["metadata", "event_type"]

    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "principal"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "ip"),
        ],
    )
    access = p._parse_udm_field_access()
    assert access.event.name == "$e"
    assert access.field.parts == ["principal", "ip"]


def test_parse_comparison_operators_and_errors() -> None:
    p = EnhancedYaraLParser("")

    cases = [
        (_tok(T.EQ, "=="), "="),
        (_tok(T.NEQ, "!="), "!="),
        (_tok(T.GT, ">"), ">"),
        (_tok(T.LT, "<"), "<"),
        (_tok(T.GE, ">="), ">="),
        (_tok(T.LE, "<="), "<="),
        (_tok(T.IDENTIFIER, "matches"), "=~"),
        (_tok(T.IN, "in"), "in"),
        (_tok(T.IDENTIFIER, "in"), "in"),
    ]
    for tk, expected in cases:
        _set_tokens(p, [tk])
        assert p._parse_comparison_operator() == expected

    _set_tokens(p, [_tok(T.IDENTIFIER, "not"), _tok(T.IDENTIFIER, "matches")])
    assert p._parse_comparison_operator() == "!~"

    _set_tokens(p, [_tok(T.IDENTIFIER, "oops")])
    with pytest.raises(ValueError, match="Expected comparison operator"):
        p._parse_comparison_operator()


def test_parse_time_and_event_values() -> None:
    p = EnhancedYaraLParser("")

    _set_tokens(
        p, [_tok(T.IDENTIFIER, "over"), _tok(T.IDENTIFIER, "5m", YaraLTokenType.TIME_LITERAL)]
    )
    tw = p._parse_time_window()
    assert tw.duration == 5 and tw.unit == "m"

    _set_tokens(p, [_tok(T.INTEGER, 10), _tok(T.IDENTIFIER, "h")])
    assert p._parse_time_duration() == "10h"

    value_cases = [
        ([_tok(T.BOOLEAN_TRUE, True)], True),
        ([_tok(T.BOOLEAN_FALSE, False)], False),
        ([_tok(T.STRING, "abc")], "abc"),
        ([_tok(T.INTEGER, 7)], 7),
        ([_tok(T.IDENTIFIER, "%watch%", YaraLTokenType.REFERENCE_LIST)], "ReferenceList"),
        (
            [
                _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
                _tok(T.DOT, "."),
                _tok(T.IDENTIFIER, "metadata"),
                _tok(T.DOT, "."),
                _tok(T.IDENTIFIER, "event_type"),
            ],
            "UDMFieldAccess",
        ),
        ([_tok(T.IDENTIFIER, "true")], True),
        ([_tok(T.IDENTIFIER, "false")], False),
        (
            [_tok(T.IDENTIFIER, "metadata"), _tok(T.DOT, "."), _tok(T.IDENTIFIER, "id")],
            "UDMFieldPath",
        ),
        ([_tok(T.REGEX, "/abc/i")], "RegexPattern"),
    ]

    for toks, expected in value_cases:
        _set_tokens(p, toks)
        value = p._parse_event_value()
        if expected in [True, False, "abc", 7]:
            assert value == expected
        else:
            assert value.__class__.__name__ == expected

    _set_tokens(p, [_tok(T.PLUS, "+")])
    with pytest.raises(ValueError, match="Expected value"):
        p._parse_event_value()


def test_parse_regex_pattern_variants() -> None:
    p = EnhancedYaraLParser("")

    _set_tokens(p, [_tok(T.REGEX, "/foo.*/im")])
    rp = p._parse_regex_pattern()
    assert rp.pattern == "foo.*"
    assert rp.flags == ["i", "m"]

    _set_tokens(
        p,
        [
            _tok(T.DIVIDE, "/"),
            _tok(T.IDENTIFIER, "ab"),
            _tok(T.DIVIDE, "/"),
            _tok(T.IDENTIFIER, "ig"),
        ],
    )
    rp2 = p._parse_regex_pattern()
    assert rp2.pattern == "ab"
    assert rp2.flags == ["i", "g"]

    _set_tokens(
        p,
        [
            _tok(T.DIVIDE, "/"),
            _tok(T.IDENTIFIER, "ab"),
            _tok(T.DIVIDE, "/"),
            _tok(T.IDENTIFIER, "toolong"),
        ],
    )
    rp3 = p._parse_regex_pattern()
    assert rp3.flags == []

    _set_tokens(p, [_tok(T.IDENTIFIER, "not_regex")])
    with pytest.raises(ValueError, match="Expected '/' for regex"):
        p._parse_regex_pattern()
