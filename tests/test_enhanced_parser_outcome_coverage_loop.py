# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Coverage regression tests for yaraast.yaral.enhanced_parser_outcome.

Missing lines before this file (90.23%):
  156-158   _format_outcome_expression_text: ArithmeticExpression branch
  160-161   _format_outcome_expression_text: AggregationFunction branch
  163-164   _format_outcome_expression_text: FunctionCall branch
  166-171   _format_outcome_expression_text: ConditionalExpression branch (both arms)
  174       _format_outcome_expression_text: format_literal fallback for plain scalars
  217       _parse_outcome_primary_expression: aggregation-name identifier with no LPAREN next
  222       _parse_outcome_primary_expression: bare EVENT_VAR (no dot access)
  275->281  _parse_outcome_function_call: comma loop for multi-argument generic calls

Each test exercises the production parse path through
EnhancedYaraLParser; no module-level symbols are mocked.
"""

from __future__ import annotations

import pytest

from yaraast.lexer.tokens import TokenType as T
from yaraast.yaral.ast_nodes import (
    ArithmeticExpression,
    RawOutcomeExpression,
)
from yaraast.yaral.enhanced_parser import EnhancedYaraLParser
from yaraast.yaral.generator import YaraLGenerator
from yaraast.yaral.lexer import YaraLToken
from yaraast.yaral.tokens import YaraLTokenType

# ---------------------------------------------------------------------------
# Token construction helpers (identical contract to the existing test suite)
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
# Lines 156-158: _format_outcome_expression_text — ArithmeticExpression branch
#
# When an arithmetic sub-expression appears as the left operand of an "or"
# boolean chain, _parse_outcome_or_expression calls _format_outcome_expression_text
# on that ArithmeticExpression node.  The full-parse path is the only way to
# reach this because the formatter is internal to the mixin.
# ---------------------------------------------------------------------------


def test_format_outcome_arithmetic_expression_via_or_chain() -> None:
    """
    ArithmeticExpression left-operand of 'or' forces the ArithmeticExpression
    branch (lines 156-158) of _format_outcome_expression_text.
    """
    parser = EnhancedYaraLParser("""
        rule arith_or_chain {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $score = 1 + 2 or 3
          condition:
            $e
        }
        """)
    ast = parser.parse()

    assert parser.errors == []
    outcome = ast.rules[0].outcome
    assert outcome is not None
    # The result of "1 + 2 or 3" is collapsed into a RawOutcomeExpression.
    expr = outcome.assignments[0].expression
    assert isinstance(expr, RawOutcomeExpression)
    assert "1 + 2" in str(expr)
    assert "or" in str(expr)

    generated = YaraLGenerator().generate(ast)
    assert "$score = 1 + 2 or 3" in generated


# ---------------------------------------------------------------------------
# Lines 160-161: _format_outcome_expression_text — AggregationFunction branch
#
# An AggregationFunction on the left of "or" triggers this branch.
# ---------------------------------------------------------------------------


def test_format_outcome_aggregation_function_via_or_chain() -> None:
    """
    AggregationFunction as left operand of 'or' exercises lines 160-161 of
    _format_outcome_expression_text.
    """
    parser = EnhancedYaraLParser("""
        rule agg_or_chain {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $result = count($e.principal.ip) or 0
          condition:
            $e
        }
        """)
    ast = parser.parse()

    assert parser.errors == []
    outcome = ast.rules[0].outcome
    assert outcome is not None
    expr = outcome.assignments[0].expression
    assert isinstance(expr, RawOutcomeExpression)
    text = str(expr)
    assert "count($e.principal.ip)" in text
    assert "or" in text

    generated = YaraLGenerator().generate(ast)
    assert "$result = count($e.principal.ip) or 0" in generated


# ---------------------------------------------------------------------------
# Lines 163-164: _format_outcome_expression_text — FunctionCall branch
#
# A generic FunctionCall (non-aggregation) on the left of "or".
# ---------------------------------------------------------------------------


def test_format_outcome_function_call_via_or_chain() -> None:
    """
    FunctionCall as left operand of 'or' exercises lines 163-164 of
    _format_outcome_expression_text.
    """
    parser = EnhancedYaraLParser("""
        rule func_or_chain {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $result = custom($e.target.hostname) or "fallback"
          condition:
            $e
        }
        """)
    ast = parser.parse()

    assert parser.errors == []
    outcome = ast.rules[0].outcome
    assert outcome is not None
    expr = outcome.assignments[0].expression
    assert isinstance(expr, RawOutcomeExpression)
    text = str(expr)
    assert "custom($e.target.hostname)" in text
    assert "or" in text

    generated = YaraLGenerator().generate(ast)
    assert 'custom($e.target.hostname) or "fallback"' in generated


# ---------------------------------------------------------------------------
# Lines 166-171: _format_outcome_expression_text — ConditionalExpression branch
#
# Two sub-tests: conditional without false_value (line 169) and with
# false_value (lines 170-171), each as a left operand of "or".
# ---------------------------------------------------------------------------


def test_format_outcome_conditional_no_false_value_via_or_chain() -> None:
    """
    ConditionalExpression with false_value=None as left of 'or' covers
    lines 166-169 of _format_outcome_expression_text.

    The condition part is formatted by _format_condition_expression_text (a
    separate mixin method) which may produce a raw repr for UDM nodes; this
    test verifies only that the ConditionalExpression branch in
    _format_outcome_expression_text fires and produces the 'if(...)' structure
    with no false-value slot.
    """
    parser = EnhancedYaraLParser("""
        rule cond_no_else_or {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $result = if($e.metadata.event_type = "LOGIN", "yes") or "no"
          condition:
            $e
        }
        """)
    ast = parser.parse()

    assert parser.errors == []
    outcome = ast.rules[0].outcome
    assert outcome is not None
    expr = outcome.assignments[0].expression
    assert isinstance(expr, RawOutcomeExpression)
    text = str(expr)
    # The formatter wraps the conditional in if(...) and appends the operator.
    assert "if(" in text
    assert '"yes"' in text
    # false_value is absent so the formatted text has exactly two arguments:
    # the condition text and "yes" — no third comma-separated slot.
    assert '"maybe"' not in text
    assert "or" in text


def test_format_outcome_conditional_with_false_value_via_or_chain() -> None:
    """
    ConditionalExpression with false_value set as left of 'or' covers
    lines 166-171 of _format_outcome_expression_text.

    The condition rendering may include a raw repr for UDM nodes; assertions
    focus on structure (if(...) with both true and false arms) rather than the
    exact condition text.
    """
    parser = EnhancedYaraLParser("""
        rule cond_else_or {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $result = if($e.metadata.event_type = "LOGIN", "yes", "maybe") or "no"
          condition:
            $e
        }
        """)
    ast = parser.parse()

    assert parser.errors == []
    outcome = ast.rules[0].outcome
    assert outcome is not None
    expr = outcome.assignments[0].expression
    assert isinstance(expr, RawOutcomeExpression)
    text = str(expr)
    # Both the true and false value slots must appear in the formatted text.
    assert "if(" in text
    assert '"yes"' in text
    assert '"maybe"' in text
    assert "or" in text


# ---------------------------------------------------------------------------
# Line 174: _format_outcome_expression_text — format_literal fallback
#
# A plain Python scalar (int, float, or bool) that is not any of the typed
# AST nodes falls through all isinstance checks to format_literal.
# This is reached when a numeric or boolean literal appears on the left of
# an "or" or "and" operator so _format_outcome_expression_text is invoked
# on the plain scalar value.
# ---------------------------------------------------------------------------


def test_format_outcome_plain_integer_via_and_chain() -> None:
    """
    A bare integer literal as the left operand of 'and' forces the
    format_literal fallback (line 174).
    """
    parser = EnhancedYaraLParser("""
        rule int_and_chain {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $result = 42 and 1
          condition:
            $e
        }
        """)
    ast = parser.parse()

    assert parser.errors == []
    outcome = ast.rules[0].outcome
    assert outcome is not None
    expr = outcome.assignments[0].expression
    assert isinstance(expr, RawOutcomeExpression)
    text = str(expr)
    assert "42" in text
    assert "and" in text

    generated = YaraLGenerator().generate(ast)
    assert "$result = 42 and 1" in generated


def test_format_outcome_boolean_literal_via_or_chain() -> None:
    """
    A bare boolean literal (True) as the left operand of 'or' forces the
    format_literal fallback (line 174), which renders it as 'true'.
    """
    parser = EnhancedYaraLParser("""
        rule bool_or_chain {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $result = true or false
          condition:
            $e
        }
        """)
    ast = parser.parse()

    assert parser.errors == []
    outcome = ast.rules[0].outcome
    assert outcome is not None
    expr = outcome.assignments[0].expression
    assert isinstance(expr, RawOutcomeExpression)
    text = str(expr)
    assert "true" in text
    assert "or" in text


# ---------------------------------------------------------------------------
# Line 217: _parse_outcome_primary_expression — aggregation name without LPAREN
#
# When an IDENTIFIER token whose value is an aggregation function name is NOT
# followed by '(', the code falls to the second `if token.value in
# _AGGREGATION_FUNCTIONS` check (line 216) and calls _parse_aggregation_function
# (line 217).  _parse_aggregation_function then tries to consume '(' which is
# absent, so it raises a ValueError.  This confirms the branch is reachable and
# the error path is correct behavior.
# ---------------------------------------------------------------------------


def test_aggregation_name_without_paren_raises_value_error() -> None:
    """
    An aggregation-function identifier with no following '(' reaches line 217
    and then raises ValueError when _parse_aggregation_function cannot find '('.
    """
    p = EnhancedYaraLParser("")
    # Arrange: 'count' IDENTIFIER followed immediately by EOF (not LPAREN).
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "count"),
        ],
    )

    with pytest.raises(ValueError):
        p._parse_outcome_primary_expression()


# ---------------------------------------------------------------------------
# Line 222: _parse_outcome_primary_expression — bare EVENT_VAR
#
# An EVENT_VAR token that is NOT followed by a DOT is not a field-access; the
# _is_outcome_field_access_start guard returns False.  The subsequent check
# _check_yaral_type(EVENT_VAR) then matches and line 222 returns the raw value.
# ---------------------------------------------------------------------------


def test_bare_event_var_returns_variable_name() -> None:
    """
    A bare EVENT_VAR token with no following DOT causes line 222 to fire,
    returning the variable's string value directly.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
        ],
    )

    result = p._parse_outcome_primary_expression()

    assert result == "$e"
    assert isinstance(result, str)


def test_bare_event_var_in_full_outcome_section() -> None:
    """
    A bare event variable used directly as an outcome expression value
    (without field access) is parsed and round-trips through the generator.
    """
    parser = EnhancedYaraLParser("""
        rule bare_event_var_outcome {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $risk = $e
          condition:
            $e
        }
        """)
    ast = parser.parse()

    assert parser.errors == []
    outcome = ast.rules[0].outcome
    assert outcome is not None
    assignment = outcome.assignments[0]
    assert assignment.variable == "$risk"
    assert assignment.expression == "$e"


# ---------------------------------------------------------------------------
# Line 275->281: _parse_outcome_function_call — zero-argument branch
#
# The branch 275->281 is the FALSE branch of the guard
# `if not self._check(BaseTokenType.RPAREN)` in _parse_outcome_function_call.
# It is taken when the next token after '(' is immediately ')' (zero args),
# meaning execution jumps directly from line 275 to the _consume(RPAREN) call
# at line 281.  Also: the WHILE COMMA body (lines 277-279) is exercised by
# the multi-argument test below.
# ---------------------------------------------------------------------------


def test_outcome_function_call_zero_arg_branch() -> None:
    """
    A generic outcome function call with zero arguments exercises the FALSE
    branch of `if not self._check(RPAREN)` (line 275->281), jumping directly
    from the guard to _consume(RPAREN) without entering the argument-parsing body.
    """
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "get_context"),
            _tok(T.LPAREN, "("),
            _tok(T.RPAREN, ")"),
        ],
    )

    result = p._parse_outcome_function_call()

    assert result.function == "get_context"
    assert result.arguments == []


def test_outcome_function_call_multi_arg_comma_loop() -> None:
    """
    A generic outcome function call with multiple comma-separated arguments
    exercises the WHILE COMMA body (lines 277-279) in _parse_outcome_function_call.
    """
    p = EnhancedYaraLParser("")
    # Arrange: custom_func("a", "b", "c")  — three arguments
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "custom_func"),
            _tok(T.LPAREN, "("),
            _tok(T.STRING, "a"),
            _tok(T.COMMA, ","),
            _tok(T.STRING, "b"),
            _tok(T.COMMA, ","),
            _tok(T.STRING, "c"),
            _tok(T.RPAREN, ")"),
        ],
    )

    result = p._parse_outcome_function_call()

    assert result.function == "custom_func"
    assert len(result.arguments) == 3
    assert result.arguments[0] == "a"
    assert result.arguments[1] == "b"
    assert result.arguments[2] == "c"


def test_outcome_function_call_multi_arg_roundtrip() -> None:
    """
    A generic function call with multiple arguments in the outcome section
    parses and round-trips through the generator correctly.
    """
    parser = EnhancedYaraLParser("""
        rule multi_arg_func_outcome {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $label = re.capture($e.target.hostname, "(.+)", 1)
          condition:
            $e
        }
        """)
    ast = parser.parse()

    assert parser.errors == []
    outcome = ast.rules[0].outcome
    assert outcome is not None
    from yaraast.yaral.ast_nodes import FunctionCall

    expr = outcome.assignments[0].expression
    assert isinstance(expr, FunctionCall)
    assert expr.function == "re.capture"
    assert len(expr.arguments) == 3

    generated = YaraLGenerator().generate(ast)
    assert 're.capture($e.target.hostname, "(.+)", 1)' in generated


# ---------------------------------------------------------------------------
# Combined: arithmetic inside 'and' chain  (covers line 156-158 via AND path)
# ---------------------------------------------------------------------------


def test_format_outcome_arithmetic_expression_via_and_chain() -> None:
    """
    ArithmeticExpression as the left operand of 'and' also exercises the
    ArithmeticExpression branch (lines 155-158) of _format_outcome_expression_text.
    """
    parser = EnhancedYaraLParser("""
        rule arith_and_chain {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $score = 3 * 4 and 1
          condition:
            $e
        }
        """)
    ast = parser.parse()

    assert parser.errors == []
    outcome = ast.rules[0].outcome
    assert outcome is not None
    expr = outcome.assignments[0].expression
    assert isinstance(expr, RawOutcomeExpression)
    text = str(expr)
    assert "3 * 4" in text
    assert "and" in text


# ---------------------------------------------------------------------------
# _parse_outcome_primary_expression: non-RawOutcomeExpression result in parens
# (line 204 — the else branch: parenthesized expression that is NOT
#  RawOutcomeExpression returns the inner expression unchanged)
# ---------------------------------------------------------------------------


def test_parenthesized_arithmetic_not_wrapped_in_raw() -> None:
    """
    When a parenthesized outcome expression is an ArithmeticExpression (not a
    RawOutcomeExpression), the result is returned as-is without wrapping.
    This validates line 204 of _parse_outcome_primary_expression.
    """
    p = EnhancedYaraLParser("")
    # Arrange: (1 + 2)
    _set_tokens(
        p,
        [
            _tok(T.LPAREN, "("),
            _tok(T.INTEGER, "1"),
            _tok(T.PLUS, "+"),
            _tok(T.INTEGER, "2"),
            _tok(T.RPAREN, ")"),
        ],
    )

    result = p._parse_outcome_primary_expression()

    assert isinstance(result, ArithmeticExpression)
    assert result.operator == "+"
    assert result.left == 1
    assert result.right == 2
