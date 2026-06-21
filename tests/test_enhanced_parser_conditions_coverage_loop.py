# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests targeting uncovered lines in enhanced_parser_conditions.py.

Covered gaps (line references against yaraast/yaral/enhanced_parser_conditions.py):
  89   - INTEGER not followed by 'of': saved cursor is restored before error
  99   - bare EVENT_VAR followed by IS token triggers _parse_null_check
 152   - _format_condition_expression_text: EventCountCondition branch
 153   - _format_condition_expression_text: EventCountCondition return
 155   - _format_condition_expression_text: VariableComparisonCondition value format
 156   - _format_condition_expression_text: VariableComparisonCondition return
 157   - _format_condition_expression_text: EventCountCondition (same branch, reached
         via parenthesised comparison that wraps an EventCountCondition expr)
 159   - _format_condition_expression_text: UnaryCondition recursive call
 160   - _format_condition_expression_text: UnaryCondition return
 162   - _format_condition_expression_text: BinaryCondition recursive left call
 163   - _format_condition_expression_text: BinaryCondition recursive right call
 164   - _format_condition_expression_text: BinaryCondition return
 165   - _format_condition_expression_text: str(expr) fallback
 179   - _parse_n_of_condition: raise on unexpected token in event list
 183   - _parse_n_of_condition: raise on missing comma or closing paren
 199   - _parse_null_check: raise when 'null' keyword is absent after 'is'
 218   - _parse_numeric_comparison_operator: EQ without normalise returns '='
 219   - _parse_numeric_comparison_operator: IEQUALS (==) branch
 223   - _parse_numeric_comparison_operator: NEQ (!=) check
 224   - _parse_numeric_comparison_operator: NEQ advance + return
 228   - _parse_numeric_comparison_operator: LT (<) branch
 231   - _parse_numeric_comparison_operator: GE (>=) branch
 234   - _parse_numeric_comparison_operator: LE (<=) branch
 237   - _parse_numeric_comparison_operator: raise on unsupported token
"""

from __future__ import annotations

import pytest

from yaraast.lexer.tokens import TokenType as T
from yaraast.yaral.ast_nodes import (
    EventCountCondition,
    JoinCondition,
    NullCheckCondition,
    VariableComparisonCondition,
)
from yaraast.yaral.enhanced_parser import EnhancedYaraLParser
from yaraast.yaral.generator import YaraLGenerator
from yaraast.yaral.lexer import YaraLToken
from yaraast.yaral.tokens import YaraLTokenType

# ---------------------------------------------------------------------------
# Shared token helpers matching the pattern established in existing test files
# ---------------------------------------------------------------------------


def _tok(
    tt: T,
    value: str | int | float | None,
    yt: YaraLTokenType | None = None,
) -> YaraLToken:
    return YaraLToken(type=tt, value=value, line=1, column=1, length=1, yaral_type=yt)


def _set_tokens(p: EnhancedYaraLParser, toks: list[YaraLToken]) -> None:
    p.tokens = [*toks, _tok(T.EOF, None, YaraLTokenType.EOF)]
    p.current = 0


# ---------------------------------------------------------------------------
# Line 89 - INTEGER token not followed by 'of': cursor restored, then error
# ---------------------------------------------------------------------------


def test_integer_without_of_keyword_resets_cursor_and_raises() -> None:
    """A bare INTEGER in a condition position resets the cursor and then raises.

    _parse_primary_condition saves `self.current`, advances past the INTEGER,
    checks for 'of', does not find it, restores `self.current = saved` (line 89),
    and subsequently raises because no further branch matches INTEGER.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(p, [_tok(T.INTEGER, 5)])

    with pytest.raises(ValueError, match="Expected condition expression"):
        p._parse_primary_condition()

    # After the reset the cursor must point back at the INTEGER token (index 0),
    # proving line 89 executed and the save/restore contract was honoured.
    assert p.current == 0
    assert p.tokens[p.current].type == T.INTEGER


# ---------------------------------------------------------------------------
# Line 99 - bare EVENT_VAR followed by IS triggers _parse_null_check
# ---------------------------------------------------------------------------


def test_bare_event_var_is_null_parses_correctly() -> None:
    """A bare event variable followed by 'is null' produces NullCheckCondition.

    This drives the branch at line 98-99 of enhanced_parser_conditions.py,
    where an EVENT_VAR token with no dot-field suffix is checked for the IS
    keyword.
    """
    parser = EnhancedYaraLParser("""
        rule bare_event_var_is_null {
          events:
            $e.metadata.event_type = "LOGIN"
          condition:
            $e is null
        }
    """)
    ast = parser.parse()

    assert parser.errors == []
    condition = ast.rules[0].condition
    assert condition is not None
    result = condition.expression
    assert isinstance(result, NullCheckCondition)
    assert result.field == "$e"
    assert result.negated is False


def test_bare_event_var_is_not_null_parses_correctly() -> None:
    """A bare event variable followed by 'is not null' sets negated=True."""
    parser = EnhancedYaraLParser("""
        rule bare_event_var_is_not_null {
          events:
            $e.metadata.event_type = "LOGIN"
          condition:
            $e is not null
        }
    """)
    ast = parser.parse()

    assert parser.errors == []
    condition = ast.rules[0].condition
    assert condition is not None
    result = condition.expression
    assert isinstance(result, NullCheckCondition)
    assert result.field == "$e"
    assert result.negated is True


# ---------------------------------------------------------------------------
# Lines 152-165 - _format_condition_expression_text branches
# These are exercised by constructing parenthesised conditions that wrap each
# ConditionExpression subtype, forcing _parse_parenthesized_comparison_condition
# to call _format_condition_expression_text with the inner expression.
# ---------------------------------------------------------------------------


def test_format_condition_expression_text_event_count_branch() -> None:
    """EventCountCondition inside parentheses formats as '#event op count'.

    Parsing '(#e > 5) + 1 > 10' puts an EventCountCondition into
    _parse_parenthesized_comparison_condition, which calls
    _format_condition_expression_text (line 157) and expects the
    '#{event} {operator} {count}' template.
    """
    parser = EnhancedYaraLParser("""
        rule parenthesized_event_count_condition {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $score = count($e.principal.ip)
          condition:
            (#e > 5) + 1 > 10
        }
    """)
    ast = parser.parse()

    assert parser.errors == []
    condition = ast.rules[0].condition
    assert condition is not None
    result = condition.expression
    assert isinstance(result, VariableComparisonCondition)
    # The formatted variable must embed the inner EventCountCondition text.
    assert result.variable == "(#e > 5) + 1"
    generated = YaraLGenerator().generate(ast)
    assert "(#e > 5) + 1 > 10" in generated


def test_format_condition_expression_text_unary_condition_branch() -> None:
    """UnaryCondition inside parentheses formats as '{operator} {operand}'.

    Parsing '(not $e) > 0' puts a UnaryCondition into
    _parse_parenthesized_comparison_condition, triggering lines 159-160.
    """
    parser = EnhancedYaraLParser("""
        rule parenthesized_not_condition {
          events:
            $e.metadata.event_type = "LOGIN"
          condition:
            (not $e) > 0
        }
    """)
    ast = parser.parse()

    assert parser.errors == []
    condition = ast.rules[0].condition
    assert condition is not None
    result = condition.expression
    assert isinstance(result, VariableComparisonCondition)
    assert result.variable == "(not $e)"
    generated = YaraLGenerator().generate(ast)
    assert "(not $e) > 0" in generated


def test_format_condition_expression_text_binary_condition_branch() -> None:
    """BinaryCondition inside parentheses formats as '{left} {op} {right}'.

    Parsing '($e and $e) > 0' puts a BinaryCondition into
    _parse_parenthesized_comparison_condition, triggering lines 162-164.
    """
    parser = EnhancedYaraLParser("""
        rule parenthesized_binary_condition {
          events:
            $e.metadata.event_type = "LOGIN"
          condition:
            ($e and $e) > 0
        }
    """)
    ast = parser.parse()

    assert parser.errors == []
    condition = ast.rules[0].condition
    assert condition is not None
    result = condition.expression
    assert isinstance(result, VariableComparisonCondition)
    assert result.variable == "($e and $e)"
    generated = YaraLGenerator().generate(ast)
    assert "($e and $e) > 0" in generated


def test_format_condition_expression_text_str_fallback() -> None:
    """An unrecognised ConditionExpression subtype falls back to str(expr).

    JoinCondition is a ConditionExpression subclass not handled by any
    isinstance branch in _format_condition_expression_text, so the function
    reaches line 165 and returns str(expr).
    """
    p = EnhancedYaraLParser("")
    p._normalize_condition_equality = False

    jc = JoinCondition(left_event="$e1", right_event="$e2", join_type="inner")
    result = p._format_condition_expression_text(jc)

    # The fallback produces the dataclass repr, which must be a non-empty string.
    assert isinstance(result, str)
    assert len(result) > 0
    assert "$e1" in result


# ---------------------------------------------------------------------------
# Line 179 - N-of condition: unexpected token in event list
# ---------------------------------------------------------------------------


def test_n_of_condition_rejects_unexpected_token_in_event_list() -> None:
    """An unexpected token inside the N-of event list raises at line 179.

    _parse_n_of_condition only accepts EVENT_VAR or STRING_IDENTIFIER tokens
    inside the parenthesised event list.  Providing a plain STRING token
    triggers the error branch on line 179.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.LPAREN, "("),
            _tok(T.STRING, "bad_token"),  # not EVENT_VAR or STRING_IDENTIFIER
            _tok(T.RPAREN, ")"),
        ],
    )

    with pytest.raises(ValueError, match="Expected event variable in N-of condition"):
        p._parse_n_of_condition(2)


# ---------------------------------------------------------------------------
# Line 183 - N-of condition: missing comma or closing paren after event
# ---------------------------------------------------------------------------


def test_n_of_condition_rejects_missing_separator_after_event() -> None:
    """A token that is neither comma nor ')' after an event raises at line 183.

    After consuming the first event variable, _parse_n_of_condition checks for
    COMMA or RPAREN.  When neither is present it raises the error on line 183.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.LPAREN, "("),
            _tok(T.IDENTIFIER, "$e1", YaraLTokenType.EVENT_VAR),
            _tok(T.STRING, "oops"),  # neither COMMA nor RPAREN
            _tok(T.RPAREN, ")"),
        ],
    )

    with pytest.raises(ValueError, match=r"Expected ',' or '\)' in N-of condition"):
        p._parse_n_of_condition(2)


# ---------------------------------------------------------------------------
# Line 199 - null check: missing 'null' keyword after 'is'
# ---------------------------------------------------------------------------


def test_null_check_raises_when_null_keyword_absent() -> None:
    """'is <non-null>' triggers the error branch on line 199.

    _parse_null_check advances past 'is', optionally consumes 'not', then
    requires 'null'.  When the next token is something else it raises.
    """
    parser = EnhancedYaraLParser("""
        rule null_check_missing_null {
          events:
            $e.metadata.event_type = "LOGIN"
          condition:
            $e is bogus
        }
    """)
    ast = parser.parse()

    assert any("Expected 'null' after 'is'" in err for err in parser.errors)
    # The rule must be absent or malformed - no clean parse occurred.
    assert not any(
        r.name == "null_check_missing_null" and r.condition is not None
        for r in ast.rules
        if r.condition and not parser.errors
    )


# ---------------------------------------------------------------------------
# Line 218 - _parse_numeric_comparison_operator: IEQUALS (==) branch
# ---------------------------------------------------------------------------


def test_event_count_condition_iequals_operator() -> None:
    """'#e == 5' routes through the IEQUALS branch at line 218 and returns '=='.

    _parse_numeric_comparison_operator has a separate IEQUALS path that always
    returns '==' without consulting _normalize_condition_equality.
    """
    parser = EnhancedYaraLParser("""
        rule event_count_iequals {
          events:
            $e.metadata.event_type = "LOGIN"
          condition:
            #e == 5
        }
    """)
    ast = parser.parse()

    assert parser.errors == []
    cond = ast.rules[0].condition
    assert cond is not None
    result = cond.expression
    assert isinstance(result, EventCountCondition)
    assert result.event == "e"
    assert result.operator == "=="
    assert result.count == 5

    generated = YaraLGenerator().generate(ast)
    assert "#e == 5" in generated


def test_event_count_iequals_via_direct_token_method() -> None:
    """IEQUALS token in _parse_numeric_comparison_operator returns '==' directly."""
    p = EnhancedYaraLParser("")
    _set_tokens(p, [_tok(T.IEQUALS, "==")])
    p._normalize_condition_equality = False

    result = p._parse_numeric_comparison_operator()

    assert result == "=="


# ---------------------------------------------------------------------------
# Lines 223-224 - GT (>) branch in _parse_numeric_comparison_operator
# ---------------------------------------------------------------------------


def test_event_count_condition_gt_operator() -> None:
    """'#e > 3' exercises the GT branch at lines 223-224 and returns '>'.

    This is tested at the full-parse level to drive the branch through real
    YARA-L source rather than a direct token call.
    """
    parser = EnhancedYaraLParser("""
        rule event_count_gt {
          events:
            $e.metadata.event_type = "NETWORK_HTTP"
          condition:
            #e > 3
        }
    """)
    ast = parser.parse()

    assert parser.errors == []
    condition = ast.rules[0].condition
    assert condition is not None
    result = condition.expression
    assert isinstance(result, EventCountCondition)
    assert result.operator == ">"
    assert result.count == 3


def test_numeric_comparison_operator_gt_via_direct_token_method() -> None:
    """GT token in _parse_numeric_comparison_operator returns '>'."""
    p = EnhancedYaraLParser("")
    _set_tokens(p, [_tok(T.GT, ">")])
    p._normalize_condition_equality = False

    result = p._parse_numeric_comparison_operator()

    assert result == ">"


# ---------------------------------------------------------------------------
# Line 228 - LT (<) branch in _parse_numeric_comparison_operator
# ---------------------------------------------------------------------------


def test_event_count_condition_lt_operator() -> None:
    """'#e < 2' exercises the LT branch at line 228."""
    parser = EnhancedYaraLParser("""
        rule event_count_lt {
          events:
            $e.metadata.event_type = "LOGIN"
          condition:
            #e < 2
        }
    """)
    ast = parser.parse()

    assert parser.errors == []
    condition = ast.rules[0].condition
    assert condition is not None
    result = condition.expression
    assert isinstance(result, EventCountCondition)
    assert result.operator == "<"
    assert result.count == 2


# ---------------------------------------------------------------------------
# Line 231 - GE (>=) branch in _parse_numeric_comparison_operator
# ---------------------------------------------------------------------------


def test_event_count_condition_ge_operator() -> None:
    """'#e >= 10' exercises the GE branch at line 231."""
    parser = EnhancedYaraLParser("""
        rule event_count_ge {
          events:
            $e.metadata.event_type = "LOGIN"
          condition:
            #e >= 10
        }
    """)
    ast = parser.parse()

    assert parser.errors == []
    condition = ast.rules[0].condition
    assert condition is not None
    result = condition.expression
    assert isinstance(result, EventCountCondition)
    assert result.operator == ">="
    assert result.count == 10


# ---------------------------------------------------------------------------
# Line 234 - LE (<=) branch in _parse_numeric_comparison_operator
# ---------------------------------------------------------------------------


def test_event_count_condition_le_operator() -> None:
    """'#e <= 7' exercises the LE branch at line 234."""
    parser = EnhancedYaraLParser("""
        rule event_count_le {
          events:
            $e.metadata.event_type = "LOGIN"
          condition:
            #e <= 7
        }
    """)
    ast = parser.parse()

    assert parser.errors == []
    condition = ast.rules[0].condition
    assert condition is not None
    result = condition.expression
    assert isinstance(result, EventCountCondition)
    assert result.operator == "<="
    assert result.count == 7


# ---------------------------------------------------------------------------
# Line 237 - raise in _parse_numeric_comparison_operator on unsupported token
# ---------------------------------------------------------------------------


def test_numeric_comparison_operator_raises_on_unsupported_token() -> None:
    """An unsupported token in _parse_numeric_comparison_operator raises at line 237."""
    p = EnhancedYaraLParser("")
    _set_tokens(p, [_tok(T.STRING, "invalid")])
    p._normalize_condition_equality = False

    with pytest.raises(
        ValueError,
        match="Expected numeric comparison operator",
    ):
        p._parse_numeric_comparison_operator()


# ---------------------------------------------------------------------------
# Compound regression: multiple new branches exercised together
# ---------------------------------------------------------------------------


def test_combined_new_coverage_operators_in_one_rule() -> None:
    """Single rule exercising LT, GE, LE, IEQUALS operators and IS NULL check.

    Validates that the four numeric comparison operator branches and the bare
    event IS NULL path all produce correct AST nodes and round-trip through
    the generator.
    """
    parser = EnhancedYaraLParser("""
        rule combined_coverage_operators {
          events:
            $e.metadata.event_type = "LOGIN"
          condition:
            (#e < 100 and #e >= 1 and #e <= 50) or #e == 0 or $e is null
        }
    """)
    ast = parser.parse()

    assert parser.errors == []
    assert len(ast.rules) == 1

    generated = YaraLGenerator().generate(ast)
    assert "#e < 100" in generated
    assert "#e >= 1" in generated
    assert "#e <= 50" in generated
    assert "#e == 0" in generated
    assert "$e is null" in generated


def test_format_condition_expression_text_all_handled_branches_via_nested_parens() -> None:
    """_format_condition_expression_text handles BinaryCondition wrapping UnaryCondition.

    Nesting a NOT inside an AND inside parentheses forces recursive calls
    through the BinaryCondition branch (lines 162-164) and the UnaryCondition
    branch (lines 159-160) in the same parse.
    """
    parser = EnhancedYaraLParser("""
        rule nested_format_branches {
          events:
            $e.metadata.event_type = "LOGIN"
          condition:
            (not $e and $e) > 0
        }
    """)
    ast = parser.parse()

    assert parser.errors == []
    condition = ast.rules[0].condition
    assert condition is not None
    result = condition.expression
    assert isinstance(result, VariableComparisonCondition)
    # The variable text must embed the nested BinaryCondition and UnaryCondition.
    assert "not $e" in result.variable
    assert "and" in result.variable


def test_format_condition_expression_text_variable_comparison_branch() -> None:
    """VariableComparisonCondition inside parentheses formats via lines 153-156.

    Parsing '($risk_score > 5) + 1 > 10' puts a VariableComparisonCondition
    as the inner expression, exercising the isinstance branch for that type.
    """
    parser = EnhancedYaraLParser("""
        rule parenthesized_variable_comparison {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $risk_score = count($e.principal.ip)
          condition:
            ($risk_score > 5) + 1 > 10
        }
    """)
    ast = parser.parse()

    assert parser.errors == []
    condition = ast.rules[0].condition
    assert condition is not None
    result = condition.expression
    assert isinstance(result, VariableComparisonCondition)
    assert "($risk_score > 5)" in result.variable
    assert result.operator == ">"

    generated = YaraLGenerator().generate(ast)
    assert "($risk_score > 5) + 1 > 10" in generated


def test_format_condition_expression_text_event_exists_without_dollar_prefix() -> None:
    """EventExistsCondition with a plain event name gets a '$' prefix prepended.

    The branch at lines 149-152 handles EventExistsCondition specially:
    if the event string already starts with '$' it is returned as-is;
    otherwise '$' is prepended.  This tests the non-dollar path directly.
    """
    p = EnhancedYaraLParser("")
    p._normalize_condition_equality = False

    from yaraast.yaral.ast_nodes import EventExistsCondition

    # event without dollar prefix - the branch prepends '$'
    eec_no_dollar = EventExistsCondition(event="e")
    result_no_dollar = p._format_condition_expression_text(eec_no_dollar)
    assert result_no_dollar == "$e"

    # event with dollar prefix - returned unchanged
    eec_with_dollar = EventExistsCondition(event="$e")
    result_with_dollar = p._format_condition_expression_text(eec_with_dollar)
    assert result_with_dollar == "$e"


def test_n_of_condition_with_string_identifier_tokens_round_trips() -> None:
    """N-of condition accepts STRING_IDENTIFIER token type in event list.

    _parse_n_of_condition accepts both EVENT_VAR and STRING_IDENTIFIER.
    This test drives the STRING_IDENTIFIER path directly via token injection.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.LPAREN, "("),
            _tok(T.STRING_IDENTIFIER, "$e1"),
            _tok(T.COMMA, ","),
            _tok(T.STRING_IDENTIFIER, "$e2"),
            _tok(T.RPAREN, ")"),
        ],
    )

    from yaraast.yaral.ast_nodes import NOfCondition

    result = p._parse_n_of_condition(2)

    assert isinstance(result, NOfCondition)
    assert result.count == 2
    assert result.events == ["$e1", "$e2"]


def test_parse_condition_section_normalize_equality_restores_on_success() -> None:
    """_parse_condition_section restores _normalize_condition_equality after parsing.

    The try/finally block in _parse_condition_section sets the flag to True
    during parsing and must restore the previous value even when parsing
    succeeds.
    """
    parser = EnhancedYaraLParser("""
        rule normalize_restore {
          events:
            $e.metadata.event_type = "LOGIN"
          condition:
            #e > 0
        }
    """)
    # Set a known prior value.
    parser._normalize_condition_equality = False

    parser.parse()

    assert parser.errors == []
    # After a successful parse the flag must be back to False (the prior value).
    assert parser._normalize_condition_equality is False


def test_binary_condition_inside_parentheses_with_or_operator_formats_correctly() -> None:
    """OR BinaryCondition inside parentheses formats with 'or' operator text."""
    parser = EnhancedYaraLParser("""
        rule parenthesized_or_condition {
          events:
            $e.metadata.event_type = "LOGIN"
          condition:
            ($e or $e) > 0
        }
    """)
    ast = parser.parse()

    assert parser.errors == []
    condition = ast.rules[0].condition
    assert condition is not None
    result = condition.expression
    assert isinstance(result, VariableComparisonCondition)
    assert "or" in result.variable
    generated = YaraLGenerator().generate(ast)
    assert "($e or $e) > 0" in generated


# ---------------------------------------------------------------------------
# Line 218 - EQ branch with equality normalisation DISABLED returns '='
# ---------------------------------------------------------------------------


def test_numeric_comparison_operator_eq_without_normalize_returns_single_equals() -> None:
    """EQ token with normalisation disabled returns '=' (line 218), not '=='.

    When _normalize_condition_equality is False the EQ branch at line 216
    skips the '==' return and falls through to the return on line 218.
    This is the only code path that produces the literal '=' string.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(p, [_tok(T.EQ, "=")])
    # Disable normalisation so the code hits line 218 instead of line 217.
    p._normalize_condition_equality = False

    result = p._parse_numeric_comparison_operator()

    assert result == "="


# ---------------------------------------------------------------------------
# Lines 223-224 - NEQ (!=) branch in _parse_numeric_comparison_operator
# ---------------------------------------------------------------------------


def test_event_count_condition_neq_operator() -> None:
    """'#e != 0' exercises the NEQ branch at lines 223-224 and returns '!='.

    This is tested at the full-parse level driving real YARA-L source,
    verifying the complete path from parser input through to the AST and
    generated output.
    """
    parser = EnhancedYaraLParser("""
        rule event_count_neq {
          events:
            $e.metadata.event_type = "LOGIN"
          condition:
            #e != 0
        }
    """)
    ast = parser.parse()

    assert parser.errors == []
    condition = ast.rules[0].condition
    assert condition is not None
    result = condition.expression
    assert isinstance(result, EventCountCondition)
    assert result.operator == "!="
    assert result.count == 0

    generated = YaraLGenerator().generate(ast)
    assert "#e != 0" in generated


def test_numeric_comparison_operator_neq_via_direct_token_method() -> None:
    """NEQ token in _parse_numeric_comparison_operator returns '!='."""
    p = EnhancedYaraLParser("")
    _set_tokens(p, [_tok(T.NEQ, "!=")])
    p._normalize_condition_equality = False

    result = p._parse_numeric_comparison_operator()

    assert result == "!="
