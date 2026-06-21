# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests that close the coverage gap in _parsing_conditions.py.

Missing lines targeted (82.50% -> higher):
  33-38         - _parse_condition_section full body
  49-51         - _parse_or_condition body (or branch)
  60-62         - _parse_and_condition body (and branch)
  69-71         - _parse_unary_condition not branch
  79, 83        - _parse_primary_condition parenthesized + event-count paths
  95-99         - _parse_primary_condition identifier fallback + error
  111           - _parse_parenthesized_condition plain return
  127, 129-134  - _format_condition_expression_text branches
  138-152       - _parse_event_count_condition full body
  166, 171      - _parse_n_of_condition error paths
  192-193       - _consume_comparison_operator error
  198-199       - _parse_comparison_value parenthesized branch
  210           - _parse_comparison_value REFERENCE_LIST branch
  215-227       - _parse_comparison_value EVENT_VAR branch + error
  236-248       - _parse_condition_regex_pattern DIVIDE-delimited branch
  255->257      - _parse_condition_regex_word_modifiers nocase branch guard
  262           - _parse_condition_identifier_value function-call branch
  266-269       - _parse_parenthesized_comparison_value full body
  273           - _check_comparison_operator IEQUALS branch
  299           - _consume_condition_operator MATCHES token
  301-302       - _consume_condition_operator IN keyword
  304-305       - _consume_condition_operator 'matches' keyword
  307-308       - _consume_condition_operator 'regex' keyword branch
  310-312       - _consume_condition_operator 'not matches' branch
  314-316       - _consume_condition_operator 'not in' branch
  318-319       - _consume_condition_operator error branch
  331           - _parse_null_check_condition error branch
  338           - _token_ahead_value out-of-bounds branch
  348-352       - _parse_condition_reference_text DOT-then-LBRACKET branch
  367           - _parse_condition_bracket_part error branch
  381-382       - _parse_condition_arithmetic_value arithmetic branch
  394           - _parse_condition_arithmetic_operand_text DOUBLE branch
  398           - _parse_condition_arithmetic_operand_text string-identifier branch
  399-402       - _parse_condition_arithmetic_operand_text identifier branch + error
  417, 419, 421, 423, 427 - _format_condition_raw_value branches
  428-430       - _format_condition_raw_value full_path + int/float fallbacks
  453-466       - _parse_identifier_condition full body
"""

from __future__ import annotations

import pytest

from yaraast.lexer.tokens import TokenType as T
from yaraast.yaral._shared import YaraLParserError
from yaraast.yaral.ast_nodes import (
    BinaryCondition,
    EventCountCondition,
    EventExistsCondition,
    FunctionCall,
    NOfCondition,
    NullCheckCondition,
    RawConditionValue,
    ReferenceList,
    RegexPattern,
    StringLiteral,
    UnaryCondition,
    VariableComparisonCondition,
)
from yaraast.yaral.lexer import YaraLToken
from yaraast.yaral.parser import YaraLParser
from yaraast.yaral.tokens import YaraLTokenType

# ---------------------------------------------------------------------------
# Token construction helpers (mirror the pattern in test_yaral_parsing_conditions_real.py)
# ---------------------------------------------------------------------------


def _tok(
    token_type: T,
    value: str | int | float | None,
    line: int = 1,
    yaral_type: YaraLTokenType | None = None,
) -> YaraLToken:
    return YaraLToken(
        type=token_type,
        value=value,
        line=line,
        column=1,
        length=1,
        yaral_type=yaral_type,
    )


def _eof() -> YaraLToken:
    return _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF)


def _set_tokens(parser: YaraLParser, tokens: list[YaraLToken]) -> None:
    parser.tokens = tokens
    parser.current = 0


# ---------------------------------------------------------------------------
# _format_condition_expression_text  (lines 127, 129-134)
# ---------------------------------------------------------------------------


def test_format_condition_expression_text_event_exists_with_dollar_prefix() -> None:
    """EventExistsCondition where event already starts with '$' returns event as-is (line 127)."""
    parser = YaraLParser("")

    # Arrange: build an EventExistsCondition whose event field already carries the dollar sign.
    event_with_dollar = EventExistsCondition(event="$e1")

    # Act
    result = parser._format_condition_expression_text(event_with_dollar)

    # Assert: line 127 path - the value is returned unchanged.
    assert result == "$e1"


def test_format_condition_expression_text_event_exists_without_dollar_prefix() -> None:
    """EventExistsCondition where event lacks '$' has it prepended (line 128)."""
    parser = YaraLParser("")

    event_without_dollar = EventExistsCondition(event="e1")

    result = parser._format_condition_expression_text(event_without_dollar)

    assert result == "$e1"


def test_format_condition_expression_text_variable_comparison_condition() -> None:
    """VariableComparisonCondition branch formats as 'variable op value' (lines 129-131)."""
    parser = YaraLParser("")

    cond = VariableComparisonCondition(
        variable="$e.field",
        operator="==",
        value=StringLiteral("admin"),
    )

    result = parser._format_condition_expression_text(cond)

    assert result == '$e.field == "admin"'


def test_format_condition_expression_text_event_count_condition() -> None:
    """EventCountCondition branch formats as '#event op count' (lines 132-133)."""
    parser = YaraLParser("")

    count_cond = EventCountCondition(event="e", operator=">", count=5)

    result = parser._format_condition_expression_text(count_cond)

    assert result == "#e > 5"


def test_format_condition_expression_text_fallback_str() -> None:
    """Non-matching node falls back to str() representation (line 134)."""
    parser = YaraLParser("")

    # BinaryCondition is not handled by any specific branch.
    binary = BinaryCondition(
        operator="and",
        left=EventExistsCondition(event="e1"),
        right=EventExistsCondition(event="e2"),
    )

    result = parser._format_condition_expression_text(binary)

    # The fallback just calls str(), which produces a non-empty string.
    assert isinstance(result, str)
    assert len(result) > 0


# ---------------------------------------------------------------------------
# _parse_parenthesized_condition + _parse_parenthesized_comparison_condition
# These require _format_condition_expression_text to reach the right branch.
# ---------------------------------------------------------------------------


def test_parenthesized_condition_with_comparison_after_paren() -> None:
    """(EventExists) > 5 exercises _parse_parenthesized_comparison_condition via event-count text."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.LPAREN, "("),
            _tok(T.STRING_IDENTIFIER, "$e1", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.RPAREN, ")"),
            _tok(T.GT, ">"),
            _tok(T.INTEGER, "0"),
            _eof(),
        ],
    )

    cond = parser._parse_parenthesized_condition()

    # The outer parenthesized expression becomes a VariableComparisonCondition
    assert isinstance(cond, VariableComparisonCondition)
    assert cond.operator == ">"
    assert cond.value == 0


# ---------------------------------------------------------------------------
# _parse_n_of_condition error paths (lines 166, 171)
# ---------------------------------------------------------------------------


def test_parse_n_of_condition_invalid_token_inside_list() -> None:
    """Non-event-var / non-string-identifier inside N-of list raises (line 166)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            # INTEGER '2' consumed by _parse_n_of_condition as count
            _tok(T.INTEGER, "2"),
            _tok(T.IDENTIFIER, "of"),
            _tok(T.LPAREN, "("),
            # An integer where a $var is expected
            _tok(T.INTEGER, "99"),
            _eof(),
        ],
    )

    with pytest.raises(YaraLParserError, match="Expected event variable in N-of condition"):
        parser._parse_n_of_condition()


def test_parse_n_of_condition_missing_comma_or_rparen() -> None:
    """Token that is neither comma nor rparen after an event entry raises (line 171)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.INTEGER, "1"),
            _tok(T.IDENTIFIER, "of"),
            _tok(T.LPAREN, "("),
            _tok(T.STRING_IDENTIFIER, "$e1", yaral_type=YaraLTokenType.EVENT_VAR),
            # Missing comma or rparen - use a stray identifier
            _tok(T.IDENTIFIER, "oops"),
            _eof(),
        ],
    )

    with pytest.raises(YaraLParserError, match="Expected ',' or '\\)' in N-of condition"):
        parser._parse_n_of_condition()


def test_parse_n_of_condition_success_single_event() -> None:
    """N-of condition with exactly one event variable parses correctly."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.INTEGER, "1"),
            _tok(T.IDENTIFIER, "of"),
            _tok(T.LPAREN, "("),
            _tok(T.STRING_IDENTIFIER, "$e1", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.RPAREN, ")"),
            _eof(),
        ],
    )

    cond = parser._parse_n_of_condition()

    assert isinstance(cond, NOfCondition)
    assert cond.count == 1
    assert cond.events == ["$e1"]


# ---------------------------------------------------------------------------
# _parse_condition_regex_pattern  DIVIDE-delimited path (lines 236-248)
# ---------------------------------------------------------------------------


def test_parse_condition_regex_pattern_divide_delimited_no_flags() -> None:
    """Regex constructed from DIVIDE tokens without flags (lines 236-248, flags list empty)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.DIVIDE, "/"),
            _tok(T.IDENTIFIER, "admin"),
            _tok(T.DIVIDE, "/"),
            _eof(),
        ],
    )

    pattern = parser._parse_condition_regex_pattern()

    assert isinstance(pattern, RegexPattern)
    assert pattern.pattern == "admin"
    assert pattern.flags == []


def test_parse_condition_regex_pattern_divide_delimited_with_flags() -> None:
    """Regex constructed from DIVIDE tokens with valid flag chars (line 246 branch)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.DIVIDE, "/"),
            _tok(T.IDENTIFIER, "root"),
            _tok(T.DIVIDE, "/"),
            _tok(T.IDENTIFIER, "ig"),
            _eof(),
        ],
    )

    pattern = parser._parse_condition_regex_pattern()

    assert isinstance(pattern, RegexPattern)
    assert pattern.pattern == "root"
    assert "i" in pattern.flags
    assert "g" in pattern.flags


def test_parse_condition_regex_pattern_divide_delimited_identifier_too_long_for_flags() -> None:
    """Identifier after closing slash that is too long is NOT consumed as flags."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.DIVIDE, "/"),
            _tok(T.IDENTIFIER, "admin"),
            _tok(T.DIVIDE, "/"),
            # 'some_field' has more than 3 chars — not treated as flags.
            _tok(T.IDENTIFIER, "some_field"),
            _eof(),
        ],
    )

    pattern = parser._parse_condition_regex_pattern()

    assert isinstance(pattern, RegexPattern)
    assert pattern.pattern == "admin"
    assert pattern.flags == []


# ---------------------------------------------------------------------------
# _parse_condition_regex_word_modifiers  nocase-already-present guard (line 255->257)
# ---------------------------------------------------------------------------


def test_parse_condition_regex_word_modifiers_nocase_already_present() -> None:
    """When 'nocase' is already in flags it is not appended again (branch 255->257)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "nocase"),
            _eof(),
        ],
    )

    existing_pattern = RegexPattern(pattern="test", flags=["nocase"])
    result = parser._parse_condition_regex_word_modifiers(existing_pattern)

    # The 'nocase' token is consumed but not duplicated in flags.
    assert result.flags.count("nocase") == 1


def test_parse_condition_regex_word_modifiers_nocase_not_present() -> None:
    """When 'nocase' is not yet in flags it is appended (line 256)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "nocase"),
            _eof(),
        ],
    )

    fresh_pattern = RegexPattern(pattern="test", flags=[])
    result = parser._parse_condition_regex_word_modifiers(fresh_pattern)

    assert "nocase" in result.flags


# ---------------------------------------------------------------------------
# _check_comparison_operator  IEQUALS branch (line 273 is inside check method,
# exercised by consuming an IEQUALS token through _consume_comparison_operator)
# ---------------------------------------------------------------------------


def test_consume_comparison_operator_iequals() -> None:
    """IEQUALS token is mapped to '==' by _consume_comparison_operator (line 273 path)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IEQUALS, "=="),
            _eof(),
        ],
    )

    operator = parser._consume_comparison_operator()

    assert operator == "=="


# ---------------------------------------------------------------------------
# _consume_condition_operator  'regex' keyword branch (lines 307-308)
# ---------------------------------------------------------------------------


def test_consume_condition_operator_regex_keyword() -> None:
    """'regex' keyword is consumed and returns 'regex' (lines 307-308)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "regex"),
            _eof(),
        ],
    )

    operator = parser._consume_condition_operator()

    assert operator == "regex"


# ---------------------------------------------------------------------------
# _consume_condition_operator  'not matches' branch (lines 310-312)
# ---------------------------------------------------------------------------


def test_consume_condition_operator_not_matches() -> None:
    """'not matches' token pair is consumed and returns '!~' (lines 310-312)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "not"),
            _tok(T.IDENTIFIER, "matches"),
            _eof(),
        ],
    )

    operator = parser._consume_condition_operator()

    assert operator == "!~"


# ---------------------------------------------------------------------------
# _consume_condition_operator  error branch (lines 318-319)
# ---------------------------------------------------------------------------


def test_consume_condition_operator_raises_on_unexpected_token() -> None:
    """No operator token raises YaraLParserError (lines 318-319)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.RBRACE, "}"),
            _eof(),
        ],
    )

    with pytest.raises(YaraLParserError, match="Expected comparison operator"):
        parser._consume_condition_operator()


# ---------------------------------------------------------------------------
# _parse_null_check_condition  error when no 'null' after 'is' (line 331)
# ---------------------------------------------------------------------------


def test_parse_null_check_condition_missing_null_raises() -> None:
    """'is' not followed by 'null' or IS-typed 'null' raises (line 331)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            # 'is' token — consumed by _parse_null_check_condition via _advance()
            _tok(T.IDENTIFIER, "is"),
            # Next token is not 'null'
            _tok(T.IDENTIFIER, "something_else"),
            _eof(),
        ],
    )

    with pytest.raises(YaraLParserError, match="Expected 'null' after 'is'"):
        parser._parse_null_check_condition("field")


def test_parse_null_check_condition_negated_success() -> None:
    """'is not null' parses into a negated NullCheckCondition."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "is"),
            _tok(T.IDENTIFIER, "not"),
            _tok(T.IDENTIFIER, "null"),
            _eof(),
        ],
    )

    result = parser._parse_null_check_condition("$e.field")

    assert isinstance(result, NullCheckCondition)
    assert result.negated is True
    assert result.field == "$e.field"


def test_parse_null_check_condition_non_negated_success() -> None:
    """'is null' parses into a non-negated NullCheckCondition."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "is"),
            _tok(T.IDENTIFIER, "null"),
            _eof(),
        ],
    )

    result = parser._parse_null_check_condition("$e.field")

    assert isinstance(result, NullCheckCondition)
    assert result.negated is False


# ---------------------------------------------------------------------------
# _token_ahead_value  out-of-bounds branch (line 338)
# ---------------------------------------------------------------------------


def test_token_ahead_value_out_of_bounds_returns_none() -> None:
    """Requesting an offset beyond the token list returns None (line 338)."""
    parser = YaraLParser("")
    _set_tokens(parser, [_eof()])

    # current is 0, offset 10 reaches position 10 which is >= len(tokens)=1.
    result = parser._token_ahead_value(10)

    assert result is None


# ---------------------------------------------------------------------------
# _parse_condition_reference_text  DOT then LBRACKET branch (lines 348-352)
# ---------------------------------------------------------------------------


def test_parse_condition_reference_text_dot_then_bracket_string_key() -> None:
    """'name.[\"key\"]' path: DOT followed by LBRACKET then STRING (lines 348-350)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.DOT, "."),
            _tok(T.LBRACKET, "["),
            _tok(T.STRING, "mykey"),
            _tok(T.RBRACKET, "]"),
            _eof(),
        ],
    )

    result = parser._parse_condition_reference_text("event")

    assert '["mykey"]' in result
    assert result.startswith("event")


def test_parse_condition_reference_text_dot_then_unexpected_token_raises() -> None:
    """DOT followed by a token that is neither IDENTIFIER nor LBRACKET raises (line 352)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.DOT, "."),
            _tok(T.RPAREN, ")"),
            _eof(),
        ],
    )

    with pytest.raises(YaraLParserError, match="Expected field name"):
        parser._parse_condition_reference_text("event")


# ---------------------------------------------------------------------------
# _parse_condition_bracket_part  error branch (line 367)
# ---------------------------------------------------------------------------


def test_parse_condition_bracket_part_unexpected_token_raises() -> None:
    """A bracket part with neither STRING nor INTEGER raises (line 367)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.RPAREN, ")"),
            _eof(),
        ],
    )

    with pytest.raises(YaraLParserError, match="Expected field key or index"):
        parser._parse_condition_bracket_part()


def test_parse_condition_bracket_part_integer_index() -> None:
    """Integer bracket index path produces correct string representation (line 363-366)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.INTEGER, "0"),
            _tok(T.RBRACKET, "]"),
            _eof(),
        ],
    )

    result = parser._parse_condition_bracket_part()

    assert result == "[0]"


# ---------------------------------------------------------------------------
# _parse_condition_arithmetic_operand_text  identifier branch + error (lines 399-402)
# ---------------------------------------------------------------------------


def test_parse_condition_arithmetic_operand_text_identifier_branch() -> None:
    """An IDENTIFIER token in arithmetic position calls _parse_condition_identifier_value (lines 399-401)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "count"),
            _eof(),
        ],
    )

    result = parser._parse_condition_arithmetic_operand_text()

    # The identifier is resolved as a RawConditionValue and formatted back to a string.
    assert result == "count"


def test_parse_condition_arithmetic_operand_text_unexpected_token_raises() -> None:
    """A token that is not integer, double, event-var, string-id, or identifier raises (line 402)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.RPAREN, ")"),
            _eof(),
        ],
    )

    with pytest.raises(YaraLParserError, match="Expected arithmetic operand"):
        parser._parse_condition_arithmetic_operand_text()


# ---------------------------------------------------------------------------
# _format_condition_raw_value  uncovered branches
# Lines 417 (RegexPattern), 419 (ReferenceList), 421 (bool false),
# 423 (StringLiteral), 427 (plain str that starts with '$' or '%')
# ---------------------------------------------------------------------------


def test_format_condition_raw_value_regex_pattern() -> None:
    """RegexPattern is formatted via its as_string property (line 417)."""
    parser = YaraLParser("")

    regex = RegexPattern(pattern="admin.*", flags=["i"])
    result = parser._format_condition_raw_value(regex)

    assert "/admin.*/i" in result


def test_format_condition_raw_value_reference_list() -> None:
    """ReferenceList is formatted with percent-wrapped name (line 419)."""
    parser = YaraLParser("")

    ref = ReferenceList(name="blocked")
    result = parser._format_condition_raw_value(ref)

    assert result == "%blocked%"


def test_format_condition_raw_value_bool_false() -> None:
    """Boolean False formats to 'false' (line 421 false-branch)."""
    parser = YaraLParser("")

    result = parser._format_condition_raw_value(False)

    assert result == "false"


def test_format_condition_raw_value_bool_true() -> None:
    """Boolean True formats to 'true' (line 421 true-branch)."""
    parser = YaraLParser("")

    result = parser._format_condition_raw_value(True)

    assert result == "true"


def test_format_condition_raw_value_string_literal() -> None:
    """StringLiteral is quoted (line 423)."""
    parser = YaraLParser("")

    lit = StringLiteral("hello world")
    result = parser._format_condition_raw_value(lit)

    assert '"hello world"' in result


def test_format_condition_raw_value_plain_str_starts_with_dollar() -> None:
    """Plain str starting with '$' is returned as-is (line 425-426)."""
    parser = YaraLParser("")

    result = parser._format_condition_raw_value("$e.field")

    assert result == "$e.field"


def test_format_condition_raw_value_plain_str_starts_with_percent() -> None:
    """Plain str starting with '%' is returned as-is (line 425-426)."""
    parser = YaraLParser("")

    result = parser._format_condition_raw_value("%mylist%")

    assert result == "%mylist%"


def test_format_condition_raw_value_raw_condition_value_subclass() -> None:
    """RawConditionValue (str subclass) is returned as-is (line 425, isinstance check)."""
    parser = YaraLParser("")

    raw = RawConditionValue("some.reference")
    result = parser._format_condition_raw_value(raw)

    assert result == "some.reference"


def test_format_condition_raw_value_plain_str_no_prefix_is_quoted() -> None:
    """Plain str without '$' or '%' prefix is quoted (line 427)."""
    parser = YaraLParser("")

    result = parser._format_condition_raw_value("ordinary_string")

    assert '"ordinary_string"' in result


def test_format_condition_raw_value_function_call() -> None:
    """FunctionCall is formatted as function(args) (lines 413-415)."""
    parser = YaraLParser("")

    call = FunctionCall(
        function="timestamp.get_epoch",
        arguments=[RawConditionValue("$e.metadata.event_timestamp")],
    )
    result = parser._format_condition_raw_value(call)

    assert result == "timestamp.get_epoch($e.metadata.event_timestamp)"


# ---------------------------------------------------------------------------
# End-to-end parsing that exercises multiple paths together via real YARA-L text
# ---------------------------------------------------------------------------


def test_condition_regex_keyword_via_real_parser() -> None:
    """'regex' keyword operator is produced through the real lexer+parser pipeline."""
    parser = YaraLParser("$e.field regex /pattern/")
    condition = parser._parse_condition_expression()

    assert isinstance(condition, VariableComparisonCondition)
    assert condition.operator == "regex"
    assert isinstance(condition.value, RegexPattern)


def test_condition_not_matches_via_real_parser() -> None:
    """'not matches' operator parses to '!~' through the real lexer+parser pipeline."""
    parser = YaraLParser("$e.hostname not matches /badhost.*/")
    condition = parser._parse_condition_expression()

    assert isinstance(condition, VariableComparisonCondition)
    assert condition.operator == "!~"
    assert isinstance(condition.value, RegexPattern)


def test_condition_is_null_via_real_parser() -> None:
    """'is null' parses into NullCheckCondition (negated=False) via real pipeline."""
    parser = YaraLParser("$e.field is null")
    condition = parser._parse_condition_expression()

    assert isinstance(condition, NullCheckCondition)
    assert condition.negated is False


def test_condition_is_not_null_via_real_parser() -> None:
    """'is not null' parses into NullCheckCondition (negated=True) via real pipeline."""
    parser = YaraLParser("$e.field is not null")
    condition = parser._parse_condition_expression()

    assert isinstance(condition, NullCheckCondition)
    assert condition.negated is True


def test_condition_boolean_true_comparison_via_real_parser() -> None:
    """Comparison with literal 'true' resolves to Python True as the value."""
    parser = YaraLParser("$e.success = true")
    condition = parser._parse_condition_expression()

    assert isinstance(condition, VariableComparisonCondition)
    assert condition.value is True


def test_condition_boolean_false_comparison_via_real_parser() -> None:
    """Comparison with literal 'false' resolves to Python False as the value."""
    parser = YaraLParser("$e.success = false")
    condition = parser._parse_condition_expression()

    assert isinstance(condition, VariableComparisonCondition)
    assert condition.value is False


def test_condition_n_of_via_real_parser() -> None:
    """N-of condition parses through the real lexer+parser pipeline."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.INTEGER, "2"),
            _tok(T.IDENTIFIER, "of"),
            _tok(T.LPAREN, "("),
            _tok(T.STRING_IDENTIFIER, "$e1", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.COMMA, ","),
            _tok(T.STRING_IDENTIFIER, "$e2", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.RPAREN, ")"),
            _eof(),
        ],
    )
    # _parse_primary_condition dispatches to _parse_n_of_condition when
    # INTEGER is followed by "of".
    cond = parser._parse_primary_condition()

    assert isinstance(cond, NOfCondition)
    assert cond.count == 2
    assert len(cond.events) == 2


def test_condition_arithmetic_with_identifier_operand() -> None:
    """Arithmetic expression where right operand is a bare identifier exercises line 399-401."""
    parser = YaraLParser("$count + threshold > 0")
    condition = parser._parse_condition_expression()

    assert isinstance(condition, VariableComparisonCondition)
    assert "threshold" in condition.variable


def test_condition_divide_delimited_regex_via_real_parser() -> None:
    """Slash-delimited regex in a condition comparison exercises the DIVIDE path."""
    parser = YaraLParser("$e.hostname = /admin.*/")
    condition = parser._parse_condition_expression()

    assert isinstance(condition, VariableComparisonCondition)
    assert isinstance(condition.value, RegexPattern)
    assert condition.value.pattern == "admin.*"


def test_condition_bracket_string_key_in_field_reference() -> None:
    """Field reference with string bracket key exercises DOT->LBRACKET path (lines 348-350)."""
    parser = YaraLParser('$e.labels["env"] = "prod"')
    condition = parser._parse_condition_expression()

    assert isinstance(condition, VariableComparisonCondition)
    assert '["env"]' in condition.variable


# ---------------------------------------------------------------------------
# _parse_condition_section  full body (lines 33-38)
# ---------------------------------------------------------------------------


def test_parse_condition_section_full_body() -> None:
    """Exercises the complete _parse_condition_section body (lines 33-38)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "condition"),
            _tok(T.COLON, ":"),
            _tok(T.STRING_IDENTIFIER, "$e1", yaral_type=YaraLTokenType.EVENT_VAR),
            _eof(),
        ],
    )

    from yaraast.yaral.ast_nodes import ConditionSection

    section = parser._parse_condition_section()

    assert isinstance(section, ConditionSection)
    assert isinstance(section.expression, EventExistsCondition)


# ---------------------------------------------------------------------------
# _parse_or_condition  OR body (lines 49-51)
# ---------------------------------------------------------------------------


def test_parse_or_condition_branches_combined() -> None:
    """Two event references joined by 'or' exercises the OR body (lines 49-51)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$e1", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.IDENTIFIER, "or"),
            _tok(T.STRING_IDENTIFIER, "$e2", yaral_type=YaraLTokenType.EVENT_VAR),
            _eof(),
        ],
    )

    result = parser._parse_or_condition()

    assert isinstance(result, BinaryCondition)
    assert result.operator == "or"


# ---------------------------------------------------------------------------
# _parse_and_condition  AND body (lines 60-62)
# ---------------------------------------------------------------------------


def test_parse_and_condition_branches_combined() -> None:
    """Two event references joined by 'and' exercises the AND body (lines 60-62)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$e1", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.IDENTIFIER, "and"),
            _tok(T.STRING_IDENTIFIER, "$e2", yaral_type=YaraLTokenType.EVENT_VAR),
            _eof(),
        ],
    )

    result = parser._parse_and_condition()

    assert isinstance(result, BinaryCondition)
    assert result.operator == "and"


# ---------------------------------------------------------------------------
# _parse_unary_condition  NOT body (lines 69-71)
# ---------------------------------------------------------------------------


def test_parse_unary_condition_not_branch() -> None:
    """'not' keyword exercises the NOT branch of _parse_unary_condition (lines 69-71)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "not"),
            _tok(T.STRING_IDENTIFIER, "$e1", yaral_type=YaraLTokenType.EVENT_VAR),
            _eof(),
        ],
    )

    result = parser._parse_unary_condition()

    assert isinstance(result, UnaryCondition)
    assert result.operator == "not"


# ---------------------------------------------------------------------------
# _parse_primary_condition  parenthesized path (line 79) and event-count (line 83)
# These are already hit by other tests but included explicitly for clarity.
# _parse_primary_condition  identifier fallback + error (lines 95-99)
# ---------------------------------------------------------------------------


def test_parse_primary_condition_identifier_exists_fallback() -> None:
    """IDENTIFIER with no operator returns EventExistsCondition (lines 95-96)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "standalone"),
            _eof(),
        ],
    )

    result = parser._parse_primary_condition()

    assert isinstance(result, EventExistsCondition)
    assert result.event == "standalone"


def test_parse_primary_condition_unexpected_token_raises() -> None:
    """An unrecognised token causes YaraLParserError (lines 98-99)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.RBRACE, "}"),
            _eof(),
        ],
    )

    with pytest.raises(YaraLParserError, match="Unexpected token in condition"):
        parser._parse_primary_condition()


# ---------------------------------------------------------------------------
# _parse_parenthesized_condition  plain return path (line 111)
# ---------------------------------------------------------------------------


def test_parse_parenthesized_condition_plain_return() -> None:
    """A parenthesized expression not followed by an operator returns the inner expr (line 111)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.LPAREN, "("),
            _tok(T.STRING_IDENTIFIER, "$e1", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.RPAREN, ")"),
            _eof(),
        ],
    )

    result = parser._parse_parenthesized_condition()

    # Inner expression returned directly — not wrapped in VariableComparisonCondition.
    assert isinstance(result, EventExistsCondition)


# ---------------------------------------------------------------------------
# _parse_event_count_condition  full body (lines 138-152)
# ---------------------------------------------------------------------------


def test_parse_event_count_condition_full_body() -> None:
    """Exercises _parse_event_count_condition with all its consuming steps (lines 138-152)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_COUNT, "#"),
            _tok(T.IDENTIFIER, "evt"),
            _tok(T.GT, ">"),
            _tok(T.INTEGER, "3"),
            _eof(),
        ],
    )

    cond = parser._parse_event_count_condition()

    assert isinstance(cond, EventCountCondition)
    assert cond.event == "evt"
    assert cond.operator == ">"
    assert cond.count == 3


# ---------------------------------------------------------------------------
# _consume_comparison_operator  error path (lines 192-193)
# ---------------------------------------------------------------------------


def test_consume_comparison_operator_error_on_non_operator() -> None:
    """No operator token causes YaraLParserError from _consume_comparison_operator (lines 192-193)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.RBRACE, "}"),
            _eof(),
        ],
    )

    with pytest.raises(YaraLParserError, match="Expected comparison operator"):
        parser._consume_comparison_operator()


# ---------------------------------------------------------------------------
# _parse_comparison_value  parenthesized branch (lines 198-199)
# ---------------------------------------------------------------------------


def test_parse_comparison_value_parenthesized_integer() -> None:
    """LPAREN triggers _parse_parenthesized_comparison_value (lines 197-199).

    Exercised via _parse_condition_expression to stay in a typed call context.
    """
    # "$e.field = (42)" — the right-hand side is a parenthesized integer.
    parser = YaraLParser("$e.field = (42)")
    condition = parser._parse_condition_expression()

    assert isinstance(condition, VariableComparisonCondition)
    assert isinstance(condition.value, RawConditionValue)
    assert "42" in condition.value


# ---------------------------------------------------------------------------
# _parse_comparison_value  REFERENCE_LIST branch (line 210)
# ---------------------------------------------------------------------------


def test_parse_comparison_value_reference_list() -> None:
    """REFERENCE_LIST token returns a ReferenceList node (line 209-210).

    Exercised via _parse_condition_expression so we stay in a typed call context.
    """
    # "$e.field in %blocked%" — right-hand side is a REFERENCE_LIST.
    parser = YaraLParser("$e.field in %blocked%")
    condition = parser._parse_condition_expression()

    assert isinstance(condition, VariableComparisonCondition)
    assert isinstance(condition.value, ReferenceList)
    assert condition.value.name == "blocked"


# ---------------------------------------------------------------------------
# _parse_comparison_value  EVENT_VAR branch (lines 215-221)
# ---------------------------------------------------------------------------


def test_parse_comparison_value_event_var_branch() -> None:
    """EVENT_VAR token on the right side produces a RawConditionValue (lines 215-221).

    Exercised via _parse_condition_expression to stay in a typed call context.
    """
    # "$e.field = $other" — right-hand side is an EVENT_VAR-typed token.
    parser = YaraLParser("$e.field = $other")
    condition = parser._parse_condition_expression()

    assert isinstance(condition, VariableComparisonCondition)
    assert isinstance(condition.value, RawConditionValue)
    assert "$other" in condition.value


# ---------------------------------------------------------------------------
# _parse_parenthesized_comparison_value  full body (lines 266-269)
# ---------------------------------------------------------------------------


def test_parse_parenthesized_comparison_value_full_body() -> None:
    """Exercises all lines of _parse_parenthesized_comparison_value (lines 266-269).

    Uses a full expression that routes comparison value parsing through LPAREN.
    """
    # "$e.count = (10)" — right-hand (10) triggers _parse_parenthesized_comparison_value.
    parser = YaraLParser("$e.count = (10)")
    condition = parser._parse_condition_expression()

    assert isinstance(condition, VariableComparisonCondition)
    result = condition.value
    assert isinstance(result, RawConditionValue)
    assert "10" in result
    assert result.startswith("(")


# ---------------------------------------------------------------------------
# _consume_condition_operator  MATCHES token branch (line 299)
# ---------------------------------------------------------------------------


def test_consume_condition_operator_matches_token() -> None:
    """BaseTokenType.MATCHES token returns its value as the operator (line 298-299)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.MATCHES, "matches"),
            _eof(),
        ],
    )

    operator = parser._consume_condition_operator()

    assert operator == "matches"


# ---------------------------------------------------------------------------
# _consume_condition_operator  IN keyword branch (lines 301-302)
# ---------------------------------------------------------------------------


def test_consume_condition_operator_in_keyword() -> None:
    """'in' keyword returns 'in' (lines 300-302 keyword branch)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "in"),
            _eof(),
        ],
    )

    operator = parser._consume_condition_operator()

    assert operator == "in"


# ---------------------------------------------------------------------------
# _consume_condition_operator  'matches' keyword branch (lines 303-305)
# ---------------------------------------------------------------------------


def test_consume_condition_operator_matches_keyword() -> None:
    """'matches' as an IDENTIFIER keyword returns '=~' (lines 303-305)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "matches"),
            _eof(),
        ],
    )

    operator = parser._consume_condition_operator()

    assert operator == "=~"


# ---------------------------------------------------------------------------
# _consume_condition_operator  'not in' branch (lines 313-316)
# ---------------------------------------------------------------------------


def test_consume_condition_operator_not_in() -> None:
    """'not in' token pair returns 'not in' (lines 313-316)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "not"),
            _tok(T.IDENTIFIER, "in"),
            _eof(),
        ],
    )

    operator = parser._consume_condition_operator()

    assert operator == "not in"


# ---------------------------------------------------------------------------
# _parse_condition_arithmetic_value  arithmetic branch (lines 381-382)
# ---------------------------------------------------------------------------


def test_parse_condition_arithmetic_value_with_arithmetic_operator() -> None:
    """When an arithmetic operator follows a value, it is wrapped in RawConditionValue (lines 381-382).

    Uses a full comparison expression where the right-hand side contains arithmetic.
    """
    # "$e.field = $other + 1" — arithmetic after right-hand event-var exercises lines 381-382.
    parser = YaraLParser("$e.field = $other + 1")
    condition = parser._parse_condition_expression()

    assert isinstance(condition, VariableComparisonCondition)
    assert isinstance(condition.value, RawConditionValue)
    assert "+" in condition.value


# ---------------------------------------------------------------------------
# _parse_condition_arithmetic_operand_text  DOUBLE branch (line 394)
# ---------------------------------------------------------------------------


def test_parse_condition_arithmetic_operand_text_double_branch() -> None:
    """DOUBLE token in arithmetic position returns its formatted numeric string (line 394)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.DOUBLE, "3.14"),
            _eof(),
        ],
    )

    result = parser._parse_condition_arithmetic_operand_text()

    assert result == "3.14"


# ---------------------------------------------------------------------------
# _parse_condition_arithmetic_operand_text  STRING_IDENTIFIER branch (line 398)
# ---------------------------------------------------------------------------


def test_parse_condition_arithmetic_operand_text_string_identifier_branch() -> None:
    """STRING_IDENTIFIER in arithmetic position resolves via reference text (line 395-398)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$other"),
            _eof(),
        ],
    )

    result = parser._parse_condition_arithmetic_operand_text()

    assert "$other" in result


# ---------------------------------------------------------------------------
# _format_condition_raw_value  full_path attribute fallback (lines 428-429)
# and integer/float fallback (line 430)
# ---------------------------------------------------------------------------


class _FakeNodeWithFullPath:
    """Minimal object that has a full_path attribute, simulating a field-path node."""

    def __init__(self, path: str) -> None:
        self.full_path = path


def test_format_condition_raw_value_full_path_attribute() -> None:
    """Object with full_path attribute is formatted via str(value.full_path) (lines 428-429)."""
    parser = YaraLParser("")

    node = _FakeNodeWithFullPath("$e.principal.ip")
    result = parser._format_condition_raw_value(node)

    assert result == "$e.principal.ip"


def test_format_condition_raw_value_integer_fallback() -> None:
    """An integer without any of the special branches falls back to str() (line 430)."""
    parser = YaraLParser("")

    result = parser._format_condition_raw_value(42)

    assert result == "42"


def test_format_condition_raw_value_float_fallback() -> None:
    """A float without any of the special branches falls back to str() (line 430)."""
    parser = YaraLParser("")

    result = parser._format_condition_raw_value(3.14)

    assert result == "3.14"


# ---------------------------------------------------------------------------
# _parse_identifier_condition  full body (lines 453-466)
# ---------------------------------------------------------------------------


def test_parse_identifier_condition_exists_fallback() -> None:
    """An IDENTIFIER with no following operator returns EventExistsCondition (line 466)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "field_name"),
            _eof(),
        ],
    )

    result = parser._parse_identifier_condition()

    assert isinstance(result, EventExistsCondition)
    assert result.event == "field_name"


def test_parse_identifier_condition_comparison() -> None:
    """An IDENTIFIER followed by a comparison operator and value produces VariableComparisonCondition."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "count"),
            _tok(T.GT, ">"),
            _tok(T.INTEGER, "5"),
            _eof(),
        ],
    )

    result = parser._parse_identifier_condition()

    assert isinstance(result, VariableComparisonCondition)
    assert result.variable == "count"
    assert result.operator == ">"
    assert result.value == 5


def test_parse_identifier_condition_null_check() -> None:
    """An IDENTIFIER followed by 'is null' produces NullCheckCondition (lines 457-458)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "field"),
            _tok(T.IDENTIFIER, "is"),
            _tok(T.IDENTIFIER, "null"),
            _eof(),
        ],
    )

    result = parser._parse_identifier_condition()

    assert isinstance(result, NullCheckCondition)
    assert result.field == "field"
    assert result.negated is False


# ---------------------------------------------------------------------------
# _parse_condition_identifier_value  function-call branch (line 262)
# ---------------------------------------------------------------------------


def test_parse_condition_identifier_value_function_call_branch() -> None:
    """IDENTIFIER followed by LPAREN triggers the function-call branch (line 261-262)."""
    parser = YaraLParser("timestamp.get_epoch($e.metadata.event_timestamp) > 0")
    condition = parser._parse_condition_expression()

    # The function call becomes the variable side of a comparison.
    assert isinstance(condition, VariableComparisonCondition)
    assert "timestamp.get_epoch" in condition.variable


# ---------------------------------------------------------------------------
# Additional real-parser end-to-end tests for OR/AND/NOT chains
# ---------------------------------------------------------------------------


def test_condition_or_and_chain_via_real_parser() -> None:
    """Complex OR+AND chain exercises lines 49-51, 60-62, 69-71 together."""
    parser = YaraLParser("$e1 or $e2 and not $e3")
    condition = parser._parse_condition_expression()

    # OR has lower precedence: ($e1) or (($e2) and (not ($e3)))
    assert isinstance(condition, BinaryCondition)
    assert condition.operator == "or"
    right = condition.right
    assert isinstance(right, BinaryCondition)
    assert right.operator == "and"
    assert isinstance(right.right, UnaryCondition)


def test_condition_event_count_via_real_parser() -> None:
    """#event > count condition exercises _parse_event_count_condition via real pipeline."""
    parser = YaraLParser("#e > 5")
    condition = parser._parse_condition_expression()

    assert isinstance(condition, EventCountCondition)
    assert condition.event == "e"
    assert condition.operator == ">"
    assert condition.count == 5


def test_condition_identifier_comparison_via_real_parser() -> None:
    """Plain identifier comparison exercises _parse_identifier_condition (lines 453-464)."""
    parser = YaraLParser('principal.hostname = "server01"')
    condition = parser._parse_condition_expression()

    assert isinstance(condition, VariableComparisonCondition)
    assert condition.variable == "principal.hostname"
    assert isinstance(condition.value, StringLiteral)


def test_condition_in_list_via_real_parser() -> None:
    """'in' list operator exercises _consume_condition_operator IN branch via real pipeline."""
    parser = YaraLParser("$e.ip in %blocklist%")
    condition = parser._parse_condition_expression()

    assert isinstance(condition, VariableComparisonCondition)
    assert condition.operator == "in"
    assert isinstance(condition.value, ReferenceList)


def test_condition_arithmetic_in_comparison_value_via_real_parser() -> None:
    """Arithmetic expression on right side of comparison exercises _parse_condition_arithmetic_value (lines 381-382)."""
    parser = YaraLParser("$e.count > 1 + 2")
    condition = parser._parse_condition_expression()

    assert isinstance(condition, VariableComparisonCondition)
    assert condition.operator == ">"
    # Right side is an arithmetic expression wrapped in RawConditionValue.
    assert isinstance(condition.value, RawConditionValue)
    assert "1" in condition.value
    assert "2" in condition.value


def test_condition_double_value_comparison_via_real_parser() -> None:
    """Floating-point value in comparison exercises the DOUBLE branch (line 394 path)."""
    parser = YaraLParser("$e.score > 3.14")
    condition = parser._parse_condition_expression()

    assert isinstance(condition, VariableComparisonCondition)
    assert condition.operator == ">"
    assert abs(float(condition.value) - 3.14) < 1e-9


# ---------------------------------------------------------------------------
# Remaining gap: line 79 — _parse_primary_condition LPAREN dispatch
# Must call _parse_primary_condition, not _parse_parenthesized_condition directly.
# ---------------------------------------------------------------------------


def test_parse_primary_condition_dispatches_to_parenthesized_via_lparen() -> None:
    """LPAREN as first token causes _parse_primary_condition to return a parenthesized result (line 79)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.LPAREN, "("),
            _tok(T.STRING_IDENTIFIER, "$e1", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.RPAREN, ")"),
            _eof(),
        ],
    )

    result = parser._parse_primary_condition()

    # Returns the inner expression directly (no following comparison operator).
    assert isinstance(result, EventExistsCondition)


def test_parse_primary_condition_parenthesized_then_comparison() -> None:
    """LPAREN condition followed by comparison operator produces VariableComparisonCondition (line 79 + 109-111)."""
    parser = YaraLParser("($e.count) > 5")
    result = parser._parse_primary_condition()

    assert isinstance(result, VariableComparisonCondition)
    assert result.operator == ">"


# ---------------------------------------------------------------------------
# Remaining gap: lines 222-227 — IDENTIFIER branch in _parse_comparison_value
# and the error branch (226-227) — require an IDENTIFIER-valued comparison value.
# ---------------------------------------------------------------------------


def test_parse_comparison_value_identifier_branch() -> None:
    """A plain IDENTIFIER token as comparison value uses lines 222-224.

    Exercised via _parse_condition_expression with a real text input.
    """
    # "$e.field = some_field" — right-hand side is a bare IDENTIFIER.
    parser = YaraLParser("$e.field = some_field")
    condition = parser._parse_condition_expression()

    assert isinstance(condition, VariableComparisonCondition)
    assert isinstance(condition.value, RawConditionValue)
    assert "some_field" in condition.value


def test_parse_comparison_value_error_on_unknown_token() -> None:
    """An unrecognised token in comparison value position raises (lines 226-227).

    Token sequence forces _parse_comparison_value to be called with a RBRACE token.
    """
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$e", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.EQ, "="),
            _tok(T.RBRACE, "}"),
            _eof(),
        ],
    )

    with pytest.raises(YaraLParserError, match="Expected value after comparison operator"):
        parser._parse_condition_expression()


# ---------------------------------------------------------------------------
# Remaining gap: line 273 — IEQUALS short-circuit branch in _check_comparison_operator.
# Covered when IEQUALS appears and earlier checks (GT,LT,GE,LE,EQ) are False.
# ---------------------------------------------------------------------------


def test_check_comparison_operator_true_for_iequals() -> None:
    """_check_comparison_operator returns True when current token is IEQUALS (line 273 branch)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IEQUALS, "=="),
            _eof(),
        ],
    )

    assert parser._check_comparison_operator() is True


def test_variable_comparison_with_iequals_operator_via_real_pipeline() -> None:
    """IEQUALS operator in a variable comparison fully exercises the IEQUALS branch."""
    parser = YaraLParser('$e.name == "root"')
    condition = parser._parse_condition_expression()

    assert isinstance(condition, VariableComparisonCondition)
    assert condition.operator == "=="
    assert isinstance(condition.value, StringLiteral)
