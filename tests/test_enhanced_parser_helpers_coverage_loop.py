"""
// Copyright (c) 2026 Marc Rivero López
// Licensed under GPLv3. See LICENSE file for details.
// This test suite validates real code behavior without mocks or stubs.

Focused regression coverage for EnhancedYaraLParserHelpersMixin.

Each test exercises a specific branch or path that was previously uncovered.
All tests operate on real parser instances with real token sequences; no
mocking framework or test doubles are used.
"""

from __future__ import annotations

import pytest

from yaraast.lexer.tokens import TokenType as T
from yaraast.yaral.ast_nodes import (
    EventVariable,
    FunctionCall,
    RawConditionValue,
    ReferenceList,
    RegexPattern,
    UDMFieldAccess,
    UDMFieldPath,
)
from yaraast.yaral.enhanced_parser import EnhancedYaraLParser
from yaraast.yaral.lexer import YaraLToken
from yaraast.yaral.tokens import YaraLTokenType

# ---------------------------------------------------------------------------
# Helper utilities (no mocking — these construct real YaraLToken objects)
# ---------------------------------------------------------------------------


def _tok(
    tt: T,
    value: str | int | float | bool | None,
    yt: YaraLTokenType | None = None,
) -> YaraLToken:
    """Create a real YaraLToken with the given type and value."""
    return YaraLToken(type=tt, value=value, line=1, column=1, length=1, yaral_type=yt)


def _set_tokens(p: EnhancedYaraLParser, toks: list[YaraLToken]) -> None:
    """Replace the parser token stream and reset position to 0."""
    p.tokens = [*toks, _tok(T.EOF, None, YaraLTokenType.EOF)]
    p.current = 0


# ---------------------------------------------------------------------------
# _parse_udm_field_path — branches not yet covered
# ---------------------------------------------------------------------------


def test_udm_field_path_dot_followed_by_lbracket() -> None:
    """
    Purpose: cover lines 37-39 — dot in UDM path immediately followed by
    LBRACKET (string key), i.e. metadata.["key"] structure.

    Arrange: identifier + dot + lbracket + string key + rbracket.
    Act: parse the token stream via _parse_udm_field_path.
    Assert: parts contain the identifier and the bracket notation.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.DOT, "."),
            _tok(T.LBRACKET, "["),
            _tok(T.STRING, "key"),
            _tok(T.RBRACKET, "]"),
        ],
    )
    path = p._parse_udm_field_path()
    assert path.parts == ["metadata", '["key"]']


def test_udm_field_path_dot_followed_by_invalid_raises() -> None:
    """
    Purpose: cover line 41 — dot in UDM path followed by a token that is
    neither IDENTIFIER nor LBRACKET triggers the else-raise branch.

    Arrange: identifier + dot + integer (invalid after dot).
    Act: call _parse_udm_field_path.
    Assert: ValueError is raised with the expected message.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.DOT, "."),
            _tok(T.INTEGER, 99),
        ],
    )
    with pytest.raises(ValueError, match="Expected field name"):
        p._parse_udm_field_path()


def test_udm_field_path_direct_lbracket_at_top_of_while() -> None:
    """
    Purpose: cover lines 42-44 (elif LBRACKET branch at top of while loop) —
    the path starts with an identifier and is directly followed by LBRACKET
    (no preceding DOT), then a string key.

    Arrange: identifier + lbracket + string + rbracket.
    Act: call _parse_udm_field_path.
    Assert: the bracket key is appended to parts correctly.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "field"),
            _tok(T.LBRACKET, "["),
            _tok(T.INTEGER, 0),
            _tok(T.RBRACKET, "]"),
        ],
    )
    path = p._parse_udm_field_path()
    assert path.parts == ["field", "[0]"]


def test_udm_bracket_part_neither_string_nor_integer_raises() -> None:
    """
    Purpose: cover line 57 — _parse_udm_bracket_part raises when the token
    after '[' is neither STRING nor INTEGER.

    Arrange: identifier (simulating an open bracket already consumed) +
    the parser positioned at an IDENTIFIER as the bracket content.
    Act: call _parse_udm_bracket_part directly.
    Assert: ValueError is raised.
    """
    p = EnhancedYaraLParser("")
    # Simulates the parser being inside a bracket: current token is not
    # STRING or INTEGER.
    _set_tokens(p, [_tok(T.IDENTIFIER, "bad")])
    with pytest.raises(ValueError, match="Expected field key or index"):
        p._parse_udm_bracket_part()


# ---------------------------------------------------------------------------
# _parse_udm_field_access — EVENT_VAR without following DOT
# ---------------------------------------------------------------------------


def test_udm_field_access_event_var_without_dot() -> None:
    """
    Purpose: cover line 65->68 — when EVENT_VAR is present but NOT followed
    by DOT, the dot-advance branch is skipped and we go directly to
    _parse_udm_field_path.

    Arrange: EVENT_VAR token followed immediately by an IDENTIFIER (no DOT
    between them means no dot branch taken).
    Act: call _parse_udm_field_access.
    Assert: event is set and field.parts contains the subsequent identifier.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.IDENTIFIER, "field"),
        ],
    )
    access = p._parse_udm_field_access()
    assert access.event is not None
    assert access.event.name == "$e"
    assert access.field.parts == ["field"]


# ---------------------------------------------------------------------------
# _parse_comparison_operator — uncovered branches
# ---------------------------------------------------------------------------


def test_parse_comparison_iequals() -> None:
    """
    Purpose: cover lines 78-79 — IEQUALS token returns '=='.

    Arrange: single IEQUALS token.
    Act: call _parse_comparison_operator.
    Assert: returns '=='.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(p, [_tok(T.IEQUALS, "==")])
    assert p._parse_comparison_operator() == "=="


def test_parse_comparison_regex_keyword() -> None:
    """
    Purpose: cover lines 101-102 — 'regex' keyword returns 'regex'.

    Arrange: IDENTIFIER token with value 'regex'.
    Act: call _parse_comparison_operator.
    Assert: returns 'regex'.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(p, [_tok(T.IDENTIFIER, "regex")])
    assert p._parse_comparison_operator() == "regex"


def test_parse_comparison_not_in() -> None:
    """
    Purpose: cover lines 118-120 — 'not in' keyword pair returns 'not in'.

    Arrange: two IDENTIFIER tokens: 'not' then 'in'.
    Act: call _parse_comparison_operator.
    Assert: returns 'not in'.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(p, [_tok(T.IDENTIFIER, "not"), _tok(T.IDENTIFIER, "in")])
    assert p._parse_comparison_operator() == "not in"


# ---------------------------------------------------------------------------
# _parse_event_value — parenthesized path (lines 133-134)
# ---------------------------------------------------------------------------


def test_parse_event_value_parenthesized() -> None:
    """
    Purpose: cover lines 133-134 — _parse_event_value when the leading token
    is LPAREN, triggering _parse_parenthesized_event_value.

    Arrange: LPAREN + INTEGER + RPAREN.
    Act: call _parse_event_value.
    Assert: returns a RawConditionValue wrapping the integer.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.LPAREN, "("),
            _tok(T.INTEGER, 42),
            _tok(T.RPAREN, ")"),
        ],
    )
    result = p._parse_event_value()
    assert isinstance(result, RawConditionValue)
    assert "42" in str(result)


# ---------------------------------------------------------------------------
# _parse_event_primary_value — uncovered branches
# ---------------------------------------------------------------------------


def test_parse_event_primary_value_event_var_alone() -> None:
    """
    Purpose: cover line 154 — EVENT_VAR with no following token (peek_ahead
    returns None) returns the variable name as a plain string.

    Arrange: single EVENT_VAR token; the only following token is EOF so
    peek_ahead(1) returns None.
    Act: call _parse_event_primary_value.
    Assert: result is the string name of the event variable.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(p, [_tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR)])
    result = p._parse_event_primary_value()
    assert result == "$e"


def test_parse_event_primary_value_event_var_no_dot_next() -> None:
    """
    Purpose: cover line 154 — EVENT_VAR with a next token that is NOT a DOT
    returns the variable name as a plain string (not a UDMFieldAccess).

    Arrange: EVENT_VAR followed by RPAREN (not DOT).
    Act: call _parse_event_primary_value.
    Assert: result is the string name of the event variable.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "$login", YaraLTokenType.EVENT_VAR),
            _tok(T.RPAREN, ")"),
        ],
    )
    result = p._parse_event_primary_value()
    assert result == "$login"


def test_parse_event_primary_value_if_conditional() -> None:
    """
    Purpose: cover line 162 — IDENTIFIER with value 'if' triggers
    _parse_conditional_expression (parenthesized form: if(cond, then_val)).

    Arrange: 'if' IDENTIFIER + '(' + condition tokens + ',' + then-value + ')'.
    The condition must be a valid condition expression and the then-value a
    valid outcome expression. We use the parenthesised if(cond, val) form
    which only needs: if ( <field> <op> <value> , <outcome_literal> ).
    Act: call _parse_event_primary_value.
    Assert: the result is a ConditionalExpression (has condition + true_value).
    """
    p = EnhancedYaraLParser("")
    # Tokens: if ( $e.metadata.event_type = "LOGIN" , 1 )
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "if"),
            _tok(T.LPAREN, "("),
            _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "event_type"),
            _tok(T.EQ, "="),
            _tok(T.STRING, "LOGIN"),
            _tok(T.COMMA, ","),
            _tok(T.INTEGER, 1),
            _tok(T.RPAREN, ")"),
        ],
    )
    result = p._parse_event_primary_value()
    # ConditionalExpression carries condition and true_value attributes.
    assert hasattr(result, "condition")
    assert hasattr(result, "true_value")


def test_parse_event_primary_value_function_call() -> None:
    """
    Purpose: cover line 164 — IDENTIFIER followed by LPAREN triggers
    _parse_event_function_call_value via _is_event_function_call_value_start.

    Arrange: IDENTIFIER + LPAREN + STRING + RPAREN.
    Act: call _parse_event_primary_value.
    Assert: result is a FunctionCall with correct function name and arguments.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "lower"),
            _tok(T.LPAREN, "("),
            _tok(T.STRING, "ABC"),
            _tok(T.RPAREN, ")"),
        ],
    )
    result = p._parse_event_primary_value()
    assert isinstance(result, FunctionCall)
    assert result.function == "lower"
    assert len(result.arguments) == 1


# ---------------------------------------------------------------------------
# _parse_parenthesized_event_value (lines 171-174)
# ---------------------------------------------------------------------------


def test_parse_parenthesized_event_value_directly() -> None:
    """
    Purpose: cover lines 171-174 — direct call to
    _parse_parenthesized_event_value with a string literal inside parens.

    Arrange: parser positioned at a '(' token followed by a STRING then ')'.
    Note: _parse_parenthesized_event_value consumes '(' itself, so we position
    the parser such that the LPAREN is the current token.
    Act: call _parse_parenthesized_event_value.
    Assert: RawConditionValue wrapping the quoted string is returned.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.LPAREN, "("),
            _tok(T.STRING, "hello"),
            _tok(T.RPAREN, ")"),
        ],
    )
    result = p._parse_parenthesized_event_value()
    assert isinstance(result, RawConditionValue)
    assert "hello" in str(result)


# ---------------------------------------------------------------------------
# _parse_event_arithmetic_value / _parse_event_arithmetic_text (179-180, 184-187)
# ---------------------------------------------------------------------------


def test_parse_event_arithmetic_value_with_operator() -> None:
    """
    Purpose: cover lines 179-180 — when the value is followed by an arithmetic
    operator, _parse_event_arithmetic_value delegates to
    _parse_event_arithmetic_text and returns a RawConditionValue.

    Arrange: INTEGER + PLUS + INTEGER.
    Act: call _parse_event_value (which calls _parse_event_arithmetic_value).
    Assert: result is a RawConditionValue whose text contains the operator.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.INTEGER, 5),
            _tok(T.PLUS, "+"),
            _tok(T.INTEGER, 3),
        ],
    )
    result = p._parse_event_value()
    assert isinstance(result, RawConditionValue)
    assert str(result) == "5 + 3"


def test_parse_event_arithmetic_value_subtract() -> None:
    """
    Purpose: cover lines 184-187 — chained arithmetic operators.

    Arrange: INTEGER MINUS INTEGER MULTIPLY INTEGER.
    Act: call _parse_event_value.
    Assert: RawConditionValue encodes the full expression left-to-right.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.INTEGER, 10),
            _tok(T.MINUS, "-"),
            _tok(T.INTEGER, 3),
            _tok(T.MULTIPLY, "*"),
            _tok(T.INTEGER, 2),
        ],
    )
    result = p._parse_event_value()
    assert isinstance(result, RawConditionValue)
    assert str(result) == "10 - 3 * 2"


# ---------------------------------------------------------------------------
# _format_event_value_text — all isinstance branches
# ---------------------------------------------------------------------------


def test_format_event_value_text_raw_condition_value() -> None:
    """
    Purpose: cover line 200 — RawConditionValue branch in
    _format_event_value_text.

    Arrange: instantiate a real RawConditionValue and call the method directly.
    Act: call _format_event_value_text with a RawConditionValue.
    Assert: returns the string representation unchanged.
    """
    p = EnhancedYaraLParser("")
    val = RawConditionValue("some_raw_text")
    assert p._format_event_value_text(val) == "some_raw_text"


def test_format_event_value_text_udm_field_access() -> None:
    """
    Purpose: cover line 202 — UDMFieldAccess branch in
    _format_event_value_text.

    Arrange: real UDMFieldAccess with an event variable and field path.
    Act: call _format_event_value_text.
    Assert: returns the full dotted path string.
    """
    p = EnhancedYaraLParser("")
    access = UDMFieldAccess(
        event=EventVariable(name="$e"),
        field=UDMFieldPath(parts=["metadata", "event_type"]),
    )
    result = p._format_event_value_text(access)
    assert result == "$e.metadata.event_type"


def test_format_event_value_text_udm_field_path() -> None:
    """
    Purpose: cover line 204 — UDMFieldPath branch in _format_event_value_text.

    Arrange: real UDMFieldPath with multiple parts.
    Act: call _format_event_value_text.
    Assert: returns the dotted path string (no event variable prefix).
    """
    p = EnhancedYaraLParser("")
    field = UDMFieldPath(parts=["principal", "hostname"])
    result = p._format_event_value_text(field)
    assert result == "principal.hostname"


def test_format_event_value_text_event_variable() -> None:
    """
    Purpose: cover line 206 — EventVariable branch in _format_event_value_text.

    Arrange: real EventVariable with a name.
    Act: call _format_event_value_text.
    Assert: returns the variable name string.
    """
    p = EnhancedYaraLParser("")
    ev = EventVariable(name="$src")
    result = p._format_event_value_text(ev)
    assert result == "$src"


def test_format_event_value_text_reference_list() -> None:
    """
    Purpose: cover line 208 — ReferenceList branch in _format_event_value_text.

    Arrange: real ReferenceList with a name.
    Act: call _format_event_value_text.
    Assert: returns the percent-wrapped name.
    """
    p = EnhancedYaraLParser("")
    ref = ReferenceList(name="blocklist")
    result = p._format_event_value_text(ref)
    assert result == "%blocklist%"


def test_format_event_value_text_regex_pattern() -> None:
    """
    Purpose: cover line 210 — RegexPattern branch in _format_event_value_text.

    Arrange: real RegexPattern with a pattern and no flags.
    Act: call _format_event_value_text.
    Assert: returns the as_string representation.
    """
    p = EnhancedYaraLParser("")
    rp = RegexPattern(pattern="abc.*", flags=[])
    result = p._format_event_value_text(rp)
    assert result == rp.as_string
    assert "abc.*" in result


def test_format_event_value_text_function_call() -> None:
    """
    Purpose: cover lines 212-213 — FunctionCall branch in
    _format_event_value_text, including recursive argument formatting.

    Arrange: real FunctionCall with one string-literal argument.
    Act: call _format_event_value_text.
    Assert: returns 'function(formatted_arg)' string.
    """
    p = EnhancedYaraLParser("")
    fc = FunctionCall(function="re.regex", arguments=["test"])
    result = p._format_event_value_text(fc)
    assert result.startswith("re.regex(")
    assert "test" in result


# ---------------------------------------------------------------------------
# _is_event_function_call_value_start — True (LPAREN) and False (not DOT)
# ---------------------------------------------------------------------------


def test_is_event_function_call_value_start_lparen_next() -> None:
    """
    Purpose: cover line 219 — returns True when peek_ahead(1) is LPAREN.

    Arrange: IDENTIFIER (current) + LPAREN (next).
    Act: call _is_event_function_call_value_start.
    Assert: returns True.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "func"),
            _tok(T.LPAREN, "("),
        ],
    )
    assert p._is_event_function_call_value_start() is True


def test_is_event_function_call_value_start_non_dot_next() -> None:
    """
    Purpose: cover line 221 — returns False when peek_ahead(1) exists but is
    not LPAREN and not DOT.

    Arrange: IDENTIFIER (current) + INTEGER (next — neither LPAREN nor DOT).
    Act: call _is_event_function_call_value_start.
    Assert: returns False.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "field"),
            _tok(T.INTEGER, 1),
        ],
    )
    assert p._is_event_function_call_value_start() is False


# ---------------------------------------------------------------------------
# _parse_event_function_call_value (lines 234-249)
# ---------------------------------------------------------------------------


def test_parse_event_function_call_value_simple_no_args() -> None:
    """
    Purpose: cover lines 234-249 — _parse_event_function_call_value with a
    simple function name and no arguments.

    Arrange: IDENTIFIER ('func') + LPAREN + RPAREN.
    Act: call _parse_event_function_call_value.
    Assert: FunctionCall with empty argument list returned.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "func"),
            _tok(T.LPAREN, "("),
            _tok(T.RPAREN, ")"),
        ],
    )
    result = p._parse_event_function_call_value()
    assert isinstance(result, FunctionCall)
    assert result.function == "func"
    assert result.arguments == []


def test_parse_event_function_call_value_dotted_name() -> None:
    """
    Purpose: cover lines 235-238 — dotted function name like 're.regex'.

    Arrange: IDENTIFIER ('re') + DOT + IDENTIFIER ('regex') + LPAREN + STRING + RPAREN.
    Act: call _parse_event_function_call_value.
    Assert: FunctionCall with 're.regex' as function name and one argument.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "re"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "regex"),
            _tok(T.LPAREN, "("),
            _tok(T.STRING, "pattern"),
            _tok(T.RPAREN, ")"),
        ],
    )
    result = p._parse_event_function_call_value()
    assert isinstance(result, FunctionCall)
    assert result.function == "re.regex"
    assert len(result.arguments) == 1


def test_parse_event_function_call_value_multiple_args() -> None:
    """
    Purpose: cover lines 244-246 — COMMA-separated multiple arguments.

    Arrange: IDENTIFIER + LPAREN + STRING + COMMA + INTEGER + RPAREN.
    Act: call _parse_event_function_call_value.
    Assert: FunctionCall with two arguments.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "substr"),
            _tok(T.LPAREN, "("),
            _tok(T.STRING, "hello"),
            _tok(T.COMMA, ","),
            _tok(T.INTEGER, 2),
            _tok(T.RPAREN, ")"),
        ],
    )
    result = p._parse_event_function_call_value()
    assert isinstance(result, FunctionCall)
    assert result.function == "substr"
    assert len(result.arguments) == 2


# ---------------------------------------------------------------------------
# _parse_regex_pattern — REGEX token without '/' structure (lines 261-262)
# ---------------------------------------------------------------------------


def test_parse_regex_pattern_token_without_slash() -> None:
    """
    Purpose: cover lines 261-262 — REGEX token whose value does NOT begin with
    '/' or has no second '/', so the else-branch sets pattern=value, modifiers=''.

    Arrange: REGEX token with a plain value (no delimiters).
    Act: call _parse_regex_pattern.
    Assert: RegexPattern.pattern equals the raw token value and flags is empty.
    """
    p = EnhancedYaraLParser("")
    # A REGEX token without enclosing slashes exercises the else-branch.
    _set_tokens(p, [_tok(T.REGEX, "abc")])
    result = p._parse_regex_pattern()
    assert isinstance(result, RegexPattern)
    assert result.pattern == "abc"
    assert result.flags == []


def test_parse_regex_pattern_regex_token_starts_with_slash_no_second_slash() -> None:
    """
    Purpose: cover lines 261-262 — REGEX token that starts with '/' but has no
    second '/' (the value[1:] contains no '/'), falling into the else-branch.

    Arrange: REGEX token value '/abc' (slash at start, no closing slash).
    Act: call _parse_regex_pattern.
    Assert: pattern equals the raw value and flags is empty.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(p, [_tok(T.REGEX, "/abc")])
    result = p._parse_regex_pattern()
    assert isinstance(result, RegexPattern)
    assert result.pattern == "/abc"
    assert result.flags == []


# ---------------------------------------------------------------------------
# _parse_regex_word_modifiers with 'nocase' (lines 286-290)
# ---------------------------------------------------------------------------


def test_parse_regex_word_modifiers_nocase_appended() -> None:
    """
    Purpose: cover lines 286-290 — 'nocase' keyword after a regex token is
    consumed and added to the flags list.

    Arrange: REGEX token + IDENTIFIER('nocase').
    Act: call _parse_regex_pattern.
    Assert: flags list contains 'nocase'.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.REGEX, "/foo/"),
            _tok(T.IDENTIFIER, "nocase"),
        ],
    )
    result = p._parse_regex_pattern()
    assert isinstance(result, RegexPattern)
    assert "nocase" in result.flags


def test_parse_regex_word_modifiers_nocase_already_present_not_duplicated() -> None:
    """
    Purpose: cover lines 288-289 — the guard 'if "nocase" not in pattern.flags'
    prevents duplicate insertion of 'nocase'.

    Arrange: DIVIDE-delimited regex with 'nocase' modifier token; manually
    test via _parse_regex_word_modifiers directly with a pre-populated flags list.
    Act: call _parse_regex_word_modifiers with a pattern that already has 'nocase'.
    Assert: 'nocase' appears exactly once in flags.
    """
    p = EnhancedYaraLParser("")
    existing = RegexPattern(pattern="bar", flags=["nocase"])
    _set_tokens(p, [_tok(T.IDENTIFIER, "nocase")])
    result = p._parse_regex_word_modifiers(existing)
    assert result.flags.count("nocase") == 1


def test_parse_divide_delimited_regex_nocase_modifier() -> None:
    """
    Purpose: cover lines 276-282 and the nocase word-modifier path together
    via the DIVIDE-delimited form of _parse_regex_pattern.

    Arrange: DIVIDE + IDENTIFIER ('pat') + DIVIDE + IDENTIFIER ('nocase').
    Act: call _parse_regex_pattern.
    Assert: pattern is 'pat' and flags contains 'nocase'.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.DIVIDE, "/"),
            _tok(T.IDENTIFIER, "pat"),
            _tok(T.DIVIDE, "/"),
            _tok(T.IDENTIFIER, "nocase"),
        ],
    )
    result = p._parse_regex_pattern()
    assert isinstance(result, RegexPattern)
    assert result.pattern == "pat"
    assert "nocase" in result.flags


def test_parse_divide_delimited_regex_no_modifier_after_close() -> None:
    """
    Purpose: cover branch 276->281 — DIVIDE-form regex where no IDENTIFIER
    follows the closing '/', making the outer 'if _check(IDENTIFIER)' at line
    276 evaluate to False and jump directly to 'return' at line 281.

    Arrange: DIVIDE + IDENTIFIER content + DIVIDE (no trailing modifier token).
    Act: call _parse_regex_pattern.
    Assert: RegexPattern has the correct pattern and empty flags list.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.DIVIDE, "/"),
            _tok(T.IDENTIFIER, "content"),
            _tok(T.DIVIDE, "/"),
        ],
    )
    result = p._parse_regex_pattern()
    assert isinstance(result, RegexPattern)
    assert result.pattern == "content"
    assert result.flags == []


# ---------------------------------------------------------------------------
# _is_event_function_call_value_start — line 219 (peek_ahead returns None)
# ---------------------------------------------------------------------------


def test_is_event_function_call_value_start_no_next_token() -> None:
    """
    Purpose: cover line 219 (return False when peek_ahead(1) is None) inside
    _is_event_function_call_value_start.

    The only way peek_ahead(1) returns None is when current+1 is beyond the
    token list length. We achieve this by giving the parser a single-token
    list (just EOF) and calling the method at current=0; peek_ahead(1) then
    tries tokens[1] which does not exist, returning None.

    Arrange: parser with only an EOF token (tokens=[EOF], current=0).
    Act: call _is_event_function_call_value_start directly.
    Assert: returns False.
    """
    p = EnhancedYaraLParser("")
    # Manually set a single-token stream with no EOF appended; the existing
    # EOF from _set_tokens is what we point at as the sole token.
    p.tokens = [_tok(T.EOF, None, YaraLTokenType.EOF)]
    p.current = 0
    assert p._is_event_function_call_value_start() is False


# ---------------------------------------------------------------------------
# _parse_udm_field_path — branch 42->32 (elif LBRACKET loops back)
# ---------------------------------------------------------------------------


def test_udm_field_path_two_consecutive_bracket_parts() -> None:
    """
    Purpose: cover branch 42->32 — the elif LBRACKET branch at line 42
    fires, processes a bracket part, then the while loop at line 32 is
    re-entered. This requires at least two consecutive bracket expressions
    so the elif body completes and the while condition is checked again
    (and fires a second time for the elif path).

    Arrange: IDENTIFIER + LBRACKET + INTEGER + RBRACKET + LBRACKET + STRING + RBRACKET.
    Act: call _parse_udm_field_path.
    Assert: parts list contains the identifier plus both bracket notations.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "arr"),
            _tok(T.LBRACKET, "["),
            _tok(T.INTEGER, 0),
            _tok(T.RBRACKET, "]"),
            _tok(T.LBRACKET, "["),
            _tok(T.INTEGER, 1),
            _tok(T.RBRACKET, "]"),
        ],
    )
    path = p._parse_udm_field_path()
    assert path.parts == ["arr", "[0]", "[1]"]
