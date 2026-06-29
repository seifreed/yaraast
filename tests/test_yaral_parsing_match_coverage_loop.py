# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""
Regression coverage for yaraast.yaral._parsing_match (YaraLMatchParsingMixin).

Target missing lines before this file: 83, 92-94, 100, 108-115, 130, 150->162.

Every test drives the real parser through genuine token streams — either by
parsing full YARA-L source with YaraLParser, or by injecting synthetic token
sequences directly onto a YaraLParser instance when the real lexer cannot
produce the required token arrangement (error-path branches).
"""

from __future__ import annotations

import pytest

from yaraast.lexer.tokens import TokenType as BaseTokenType
from yaraast.yaral._shared import YaraLParserError
from yaraast.yaral.ast_nodes import (
    EventVariable,
    TimeWindow,
    UDMFieldAccess,
    UDMFieldPath,
)
from yaraast.yaral.lexer import YaraLToken
from yaraast.yaral.parser import YaraLParser
from yaraast.yaral.tokens import YaraLTokenType

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_EVENTS_SINGLE = '  events:\n    $e.metadata.event_type = "A"\n'
_EVENTS_TWO = '  events:\n    $e1.metadata.event_type = "A"\n    $e2.metadata.event_type = "B"\n'


def _rule(match_line: str, events: str = _EVENTS_SINGLE) -> str:
    """Build a minimal YARA-L rule around a single match line."""
    return f"rule r {{\n{events}  match:\n    {match_line}\n  condition:\n    $e\n}}"


def _tok(
    token_type: BaseTokenType,
    value: str | int | float | None,
    yaral_type: YaraLTokenType | None = None,
) -> YaraLToken:
    return YaraLToken(
        type=token_type,
        value=value,
        line=1,
        column=1,
        length=1,
        yaral_type=yaral_type,
    )


def _inject(parser: YaraLParser, tokens: list[YaraLToken]) -> None:
    """Replace the token stream on an existing parser instance."""
    parser.tokens = [
        *tokens,
        _tok(BaseTokenType.EOF, None, YaraLTokenType.EOF),
    ]
    parser.current = 0


# ---------------------------------------------------------------------------
# Line 83 — break when comma in variable list is not followed by a variable
# ---------------------------------------------------------------------------


def test_variable_list_trailing_comma_breaks_before_keyword() -> None:
    """
    Line 83: _parse_match_variable_list breaks when the token after COMMA is
    neither EVENT_VAR nor STRING_IDENTIFIER.

    The production scenario is "$e1, over 5m" where "over" is a keyword token
    that signals the time window, not another variable.  The parser must stop
    consuming variables after the comma and return only the variables seen so far.
    """
    parser = YaraLParser("")
    _inject(
        parser,
        [
            _tok(BaseTokenType.STRING_IDENTIFIER, "$e1", YaraLTokenType.EVENT_VAR),
            _tok(BaseTokenType.COMMA, ","),
            # "over" is an IDENTIFIER with yaral_type OVER — not a match variable
            _tok(BaseTokenType.IDENTIFIER, "over", YaraLTokenType.OVER),
        ],
    )

    var_names = parser._parse_match_variable_list()

    assert var_names == ["e1"]


def test_variable_list_trailing_comma_with_punctuation_breaks() -> None:
    """
    A PLUS token after COMMA also triggers the break at line 83 — any token
    that is not EVENT_VAR or STRING_IDENTIFIER causes the list to stop.
    """
    parser = YaraLParser("")
    _inject(
        parser,
        [
            _tok(BaseTokenType.STRING_IDENTIFIER, "$m", YaraLTokenType.EVENT_VAR),
            _tok(BaseTokenType.COMMA, ","),
            _tok(BaseTokenType.PLUS, "+"),
        ],
    )

    var_names = parser._parse_match_variable_list()

    assert var_names == ["m"]


# ---------------------------------------------------------------------------
# Lines 92-94 — grouping field starting with an event variable
# ---------------------------------------------------------------------------


def test_grouping_field_with_event_variable_prefix_full_parse() -> None:
    """
    Lines 92-94: when the grouping-field token is EVENT_VAR (e.g. $e),
    _parse_match_grouping_field advances past the event variable, consumes the
    DOT, then reads the field identifier.

    Verified through a complete YaraLParser run so the real lexer is involved.
    """
    source = _rule("$m = $e.principal.ip over 5m")
    ast = YaraLParser(source).parse()

    assert len(ast.rules) == 1
    assert ast.rules[0].match is not None
    match_var = ast.rules[0].match.variables[0]
    grouping = match_var.grouping_field

    assert grouping is not None
    assert isinstance(grouping, UDMFieldAccess)
    # Event variable was captured (lines 92-93)
    assert isinstance(grouping.event, EventVariable)
    assert grouping.event.name == "$e"
    # Field path was built from the identifier consumed at line 94
    assert isinstance(grouping.field, UDMFieldPath)
    assert "principal.ip" in grouping.field.parts


def test_grouping_field_with_event_variable_token_injection() -> None:
    """
    Lines 92-94: direct token injection isolates _parse_match_grouping_field
    from lexer behaviour, confirming that the code path sets event= and
    advances past DOT and the field identifier correctly.
    """
    parser = YaraLParser("")
    _inject(
        parser,
        [
            _tok(BaseTokenType.STRING_IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(BaseTokenType.DOT, "."),
            _tok(BaseTokenType.IDENTIFIER, "principal"),
        ],
    )

    result = parser._parse_match_grouping_field()

    assert isinstance(result.event, EventVariable)
    assert result.event.name == "$e"
    assert isinstance(result.field, UDMFieldPath)
    assert result.field.parts == ["principal"]


def test_grouping_field_with_string_identifier_prefix() -> None:
    """
    Lines 92-94: STRING_IDENTIFIER (not EVENT_VAR yaral_type) also enters the
    event-variable branch because the condition checks BOTH yaral types.
    """
    parser = YaraLParser("")
    _inject(
        parser,
        [
            _tok(BaseTokenType.STRING_IDENTIFIER, "$src"),  # no yaral_type
            _tok(BaseTokenType.DOT, "."),
            _tok(BaseTokenType.IDENTIFIER, "hostname"),
        ],
    )

    result = parser._parse_match_grouping_field()

    assert isinstance(result.event, EventVariable)
    assert result.event.name == "$src"
    assert result.field.parts == ["hostname"]


# ---------------------------------------------------------------------------
# Line 100 — grouping field error: no valid token type
# ---------------------------------------------------------------------------


def test_grouping_field_raises_when_no_valid_token() -> None:
    """
    Line 100: _parse_match_grouping_field raises YaraLParserError when the
    current token is neither EVENT_VAR, STRING_IDENTIFIER, nor IDENTIFIER.
    """
    parser = YaraLParser("")
    _inject(
        parser,
        [
            _tok(BaseTokenType.INTEGER, 42),
        ],
    )

    with pytest.raises(YaraLParserError, match="Expected match grouping field"):
        parser._parse_match_grouping_field()


# ---------------------------------------------------------------------------
# Lines 108-110 — DOT continuation: DOT + IDENTIFIER
# ---------------------------------------------------------------------------


def test_field_path_continuation_dot_identifier_full_parse() -> None:
    """
    Lines 108-110: when a bracket-accessed field is followed by DOT and an
    IDENTIFIER, _parse_match_field_path_continuation advances past the DOT and
    appends the identifier.

    The lexer produces IDENTIFIER + LBRACKET + INTEGER + RBRACKET + DOT + IDENTIFIER
    for 'field[0].subfield', so this exercises the full real path.
    """
    source = _rule("$m = field[0].subfield over 5m")
    ast = YaraLParser(source).parse()

    assert len(ast.rules) == 1
    assert ast.rules[0].match is not None
    grouping_field = ast.rules[0].match.variables[0].grouping_field
    assert grouping_field is not None
    parts = grouping_field.field.parts
    assert "field" in parts
    assert "[0]" in parts
    assert "subfield" in parts


def test_field_path_continuation_dot_identifier_token_injection() -> None:
    """
    Lines 108-110: token injection verifies the DOT-then-IDENTIFIER branch
    in isolation, starting the continuation at the DOT.
    """
    parser = YaraLParser("")
    _inject(
        parser,
        [
            _tok(BaseTokenType.DOT, "."),
            _tok(BaseTokenType.IDENTIFIER, "subfield"),
        ],
    )

    result = parser._parse_match_field_path_continuation(["field"])

    assert result == ["field", "subfield"]


# ---------------------------------------------------------------------------
# Lines 111-113 — DOT continuation: DOT + LBRACKET
# ---------------------------------------------------------------------------


def test_field_path_continuation_dot_lbracket_full_parse() -> None:
    """
    Lines 111-113: 'field[0].[1]' produces DOT + LBRACKET after the first
    bracket pair, exercising the elif branch that advances past LBRACKET and
    delegates to _parse_match_bracket_part.
    """
    source = _rule("$m = field[0].[1] over 5m")
    ast = YaraLParser(source).parse()

    assert len(ast.rules) == 1
    assert ast.rules[0].match is not None
    grouping_field = ast.rules[0].match.variables[0].grouping_field
    assert grouping_field is not None
    parts = grouping_field.field.parts
    assert "field" in parts
    assert "[0]" in parts
    assert "[1]" in parts


def test_field_path_continuation_dot_lbracket_token_injection() -> None:
    """
    Lines 111-113: direct injection — continuation receives DOT + LBRACKET +
    STRING + RBRACKET and must produce a quoted-string bracket segment.
    """
    parser = YaraLParser("")
    _inject(
        parser,
        [
            _tok(BaseTokenType.DOT, "."),
            _tok(BaseTokenType.LBRACKET, "["),
            _tok(BaseTokenType.STRING, "key"),
            _tok(BaseTokenType.RBRACKET, "]"),
        ],
    )

    result = parser._parse_match_field_path_continuation(["root"])

    assert result == ["root", '["key"]']


# ---------------------------------------------------------------------------
# Line 115 — DOT continuation error: DOT + unexpected token
# ---------------------------------------------------------------------------


def test_field_path_continuation_dot_unexpected_raises() -> None:
    """
    Line 115: after DOT, if the next token is neither IDENTIFIER nor LBRACKET,
    a YaraLParserError is raised.

    The real lexer produces DOT + INTEGER for 'f[0].1', so this error is
    reachable from genuine YARA-L source.
    """
    source = _rule("$m = f[0].1 over 5m")

    with pytest.raises(YaraLParserError, match="Expected field name"):
        YaraLParser(source).parse()


def test_field_path_continuation_dot_unexpected_token_injection() -> None:
    """
    Line 115: token injection variant to confirm the error message and that
    exactly DOT followed by a non-IDENTIFIER non-LBRACKET token triggers it.
    """
    parser = YaraLParser("")
    _inject(
        parser,
        [
            _tok(BaseTokenType.DOT, "."),
            _tok(BaseTokenType.INTEGER, 5),
        ],
    )

    with pytest.raises(YaraLParserError, match="Expected field name"):
        parser._parse_match_field_path_continuation(["field"])


# ---------------------------------------------------------------------------
# Line 130 — _parse_match_bracket_part error: neither STRING nor INTEGER
# ---------------------------------------------------------------------------


def test_bracket_part_raises_on_identifier_inside_brackets_full_parse() -> None:
    """
    Line 130: 'field[bad]' produces IDENTIFIER inside brackets; the parser
    cannot interpret that as a string key or integer index and raises.

    Triggered through the real YaraLParser so the lexer is on the critical path.
    """
    source = _rule("$m = field[bad] over 5m")

    with pytest.raises(YaraLParserError, match="Expected field key or index"):
        YaraLParser(source).parse()


def test_bracket_part_raises_on_unexpected_token_injection() -> None:
    """
    Line 130: token injection drives _parse_match_bracket_part directly with
    a token that is neither STRING nor INTEGER, confirming the error text.
    """
    parser = YaraLParser("")
    _inject(
        parser,
        [
            _tok(BaseTokenType.IDENTIFIER, "oops"),
            _tok(BaseTokenType.RBRACKET, "]"),
        ],
    )

    with pytest.raises(YaraLParserError, match="Expected field key or index"):
        parser._parse_match_bracket_part()


# ---------------------------------------------------------------------------
# Branch 150->162 — INTEGER time window with no unit identifier following
# ---------------------------------------------------------------------------


def test_time_window_integer_without_unit_defaults_to_minutes() -> None:
    """
    Branch 150->162: when an INTEGER token is consumed as the time value and
    the next token is NOT an IDENTIFIER, the unit check at line 148 is
    skipped (branch not taken) and the function falls through to return at
    line 162 with the default unit 'm'.

    Token injection is the only reliable way to reproduce this because the real
    lexer is unlikely to emit a bare INTEGER followed by a non-IDENTIFIER inside
    a match section; but the parser code must handle it defensively.
    """
    parser = YaraLParser("")
    _inject(
        parser,
        [
            _tok(BaseTokenType.INTEGER, "30"),
            # EOF follows — no unit identifier
        ],
    )

    window = parser._parse_time_window()

    assert isinstance(window, TimeWindow)
    assert window.duration == 30
    assert window.unit == "m"
    assert window.modifier is None


def test_time_window_integer_without_unit_with_modifier() -> None:
    """
    Branch 150->162: confirms the modifier parameter is threaded through
    correctly even when no unit follows the INTEGER.
    """
    parser = YaraLParser("")
    _inject(
        parser,
        [
            _tok(BaseTokenType.INTEGER, "15"),
        ],
    )

    window = parser._parse_time_window("every")

    assert window.duration == 15
    assert window.unit == "m"
    assert window.modifier == "every"


def test_time_window_integer_followed_by_invalid_unit_name_defaults_to_minutes() -> None:
    """
    Branch 150->162: INTEGER is followed by an IDENTIFIER whose value is NOT
    in the recognised unit list (s, m, h, d, seconds, minutes, hours, days).

    Line 148 check is True (an IDENTIFIER is present), but line 150's inner
    condition is False — the branch skips to line 162 and the default unit 'm'
    is returned without consuming the identifier token.
    """
    parser = YaraLParser("")
    _inject(
        parser,
        [
            _tok(BaseTokenType.INTEGER, "10"),
            # "over" is an IDENTIFIER but is not a valid unit name
            _tok(BaseTokenType.IDENTIFIER, "over", YaraLTokenType.OVER),
        ],
    )

    window = parser._parse_time_window()

    assert isinstance(window, TimeWindow)
    assert window.duration == 10
    assert window.unit == "m"
    # The "over" token must NOT have been consumed — it should still be current
    assert parser.current == 1
