# Copyright (c) 2026 Marc Rivero Lopez
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Targeted coverage for yaraast/parser/_expressions_binary.py missing lines.

Missing lines identified from full-suite coverage report (91.48%):
    163, 175-176, 191, 221-222, 231, 404, 436,
    452->454, 468, 482, 486, 490, 494-497,
    523->525, 542, 548

Lines 486, 490, and 496->498 are structurally unreachable dead-code guards
(the pre-check at line 467-468 already returns None when right < 0 for both
<< and >>; 496->498 cannot be reached because the operator set is exhaustive),
so this file does not attempt to cover them and instead documents the finding.
"""

from __future__ import annotations

import pytest

from yaraast.ast.conditions import AtExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    IntegerLiteral,
    UnaryExpression,
)
from yaraast.lexer import Lexer
from yaraast.parser import Parser
from yaraast.parser._expressions_binary import (
    _integer_remainder,
    _normalize_int64,
    _shift_left_int64,
    _shift_right_int64,
)
from yaraast.parser._shared import ParserError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parser_at(source: str, index: int = 0) -> Parser:
    """Return a Parser whose token stream is *source* with current=*index*."""
    p = Parser()
    p.tokens = Lexer(source).tokenize()
    p.current = index
    return p


def _rule_condition(source: str) -> object:
    """Parse a complete YARA rule and return its condition node."""
    p = Parser()
    result = p.parse(source)
    return result.rules[0].condition


# ---------------------------------------------------------------------------
# Line 163 - _parse_of_restriction_postfix: early return for non-OfExpression
# ---------------------------------------------------------------------------


def test_of_restriction_postfix_returns_non_of_expression_unchanged() -> None:
    """_parse_of_restriction_postfix returns its argument when it is not an
    OfExpression (the guard at line 163)."""
    # Arrange
    p = _parser_at("1")
    non_of_expr = IntegerLiteral(value=42)

    # Act
    result = p._parse_of_restriction_postfix(non_of_expr)

    # Assert - the same object is returned without modification
    assert result is non_of_expr
    assert isinstance(result, IntegerLiteral)
    assert result.value == 42


# ---------------------------------------------------------------------------
# Lines 175-176 - _validate_of_restriction_string_set: rule-set with at/in
# ---------------------------------------------------------------------------


def test_rule_set_with_at_restriction_raises_parser_error() -> None:
    """Referencing a rule set (not a string set) in an of-expression with an
    'at' restriction must raise ParserError (lines 175-176)."""
    # Arrange - 'all of (base_rule)' is a rule-set quantifier; 'at 0' is invalid
    source = """
rule base_rule { condition: true }
rule test { condition: 1 of (base_rule) at 0 }
"""
    p = Parser()

    # Act & Assert
    with pytest.raises(ParserError, match="Rule sets cannot use at/in restrictions"):
        p.parse(source)


def test_rule_set_with_in_restriction_raises_parser_error() -> None:
    """Referencing a rule set in an of-expression with an 'in' restriction must
    raise ParserError (lines 175-176)."""
    source = """
rule base_rule { condition: true }
rule test { condition: 1 of (base_rule) in (0..10) }
"""
    p = Parser()

    with pytest.raises(ParserError, match="Rule sets cannot use at/in restrictions"):
        p.parse(source)


# ---------------------------------------------------------------------------
# Line 191 - _parse_expression_of_postfix: else branch (quantifier.location None)
# ---------------------------------------------------------------------------


def test_expression_of_postfix_without_quantifier_location() -> None:
    """When the quantifier lacks a location, _parse_expression_of_postfix must
    fall through to _set_node_location_from_tokens (line 191)."""
    # Arrange - 'of them' remains in the token stream; quantifier has no location
    p = _parser_at("of them")
    quantifier = IntegerLiteral(value=1)
    quantifier.location = None  # forces the else branch at line 191

    # Act
    result = p._parse_expression_of_postfix(quantifier)

    # Assert
    assert isinstance(result, OfExpression)
    assert result.location is not None  # location was set by _set_node_location_from_tokens
    assert isinstance(result.quantifier, IntegerLiteral)
    assert result.quantifier.value == 1


# ---------------------------------------------------------------------------
# Lines 221-222 - _parse_percentage_expression_of_postfix: 'of' missing error
# ---------------------------------------------------------------------------


def test_percentage_of_postfix_missing_of_token_raises() -> None:
    """When the MODULO token is consumed but 'of' is absent, a ParserError is
    raised (lines 221-222). This path is only reachable through direct invocation."""
    # Arrange - tokens: '50 % 5'; position 1 points at '%'
    p = _parser_at("50 % 5", index=1)
    quantifier = IntegerLiteral(value=50)

    # Act & Assert
    with pytest.raises(ParserError, match="Expected 'of' after percentage quantifier"):
        p._parse_percentage_expression_of_postfix(quantifier)


# ---------------------------------------------------------------------------
# Line 231 - _parse_percentage_expression_of_postfix: else branch (location None)
# ---------------------------------------------------------------------------


def test_percentage_of_postfix_without_quantifier_location() -> None:
    """When the percentage quantifier lacks a location, the else branch at
    line 231 calls _set_node_location_from_tokens."""
    # Arrange - '% of them'; current at '%'
    p = _parser_at("% of them", index=0)
    quantifier = IntegerLiteral(value=50)
    quantifier.location = None  # forces the else branch at line 231

    # Act
    result = p._parse_percentage_expression_of_postfix(quantifier)

    # Assert
    assert isinstance(result, OfExpression)
    assert result.location is not None
    assert isinstance(result.quantifier, UnaryExpression)
    assert result.quantifier.operator == "%"


# ---------------------------------------------------------------------------
# Line 404 - _reject_invalid_numeric_unary_operand: operator not in {'-', '~'}
# ---------------------------------------------------------------------------


def test_reject_invalid_numeric_unary_operand_ignores_non_numeric_operators() -> None:
    """When the operator is not '-' or '~', _reject_invalid_numeric_unary_operand
    returns immediately (line 404) without raising."""
    # Arrange
    p = _parser_at("1")
    operand = IntegerLiteral(value=1)
    token = p.tokens[0]

    # Act & Assert - no exception raised for logical or string operators
    for operator in ("not", "defined", "or", "and"):
        p._reject_invalid_numeric_unary_operand(operator, operand, token)


# ---------------------------------------------------------------------------
# Line 436 - _validate_static_percentage_quantifier: early return guard
# ---------------------------------------------------------------------------


def test_validate_static_percentage_quantifier_non_unary_expression() -> None:
    """A non-UnaryExpression quantifier causes an immediate return (line 436)."""
    # Arrange
    p = _parser_at("1")
    token = p.tokens[0]
    non_unary = IntegerLiteral(value=50)

    # Act - must not raise; validation is skipped for non-UnaryExpression nodes
    p._validate_static_percentage_quantifier(non_unary, token)


def test_validate_static_percentage_quantifier_wrong_operator_returns_early() -> None:
    """A UnaryExpression whose operator is not '%' returns immediately (line 436)."""
    # Arrange
    p = _parser_at("1")
    token = p.tokens[0]
    minus_expr = UnaryExpression(operator="-", operand=IntegerLiteral(value=50))

    # Act - must not raise
    p._validate_static_percentage_quantifier(minus_expr, token)


# ---------------------------------------------------------------------------
# Line 452->454 - _static_integer_value: UnaryExpression with unknown operator
# ---------------------------------------------------------------------------


def test_static_integer_value_unary_non_negation_non_complement() -> None:
    """A UnaryExpression with an operator other than '-' or '~' falls through
    the if-chain at lines 450-453 and reaches line 454 (BinaryExpression check).
    The method must return None for such an expression."""
    # Arrange
    p = _parser_at("1")
    expr = UnaryExpression(operator="defined", operand=IntegerLiteral(value=5))

    # Act
    result = p._static_integer_value(expr)

    # Assert
    assert result is None


def test_static_integer_value_unary_complement_returns_bitwise_not() -> None:
    """UnaryExpression with '~' reaches line 453 and returns ~value."""
    # Arrange
    p = _parser_at("1")
    expr = UnaryExpression(operator="~", operand=IntegerLiteral(value=5))

    # Act
    result = p._static_integer_value(expr)

    # Assert - Python ~5 == -6 (two's-complement)
    assert result == ~5


# ---------------------------------------------------------------------------
# Line 468 - _static_integer_value: right < 0 in shift pre-check
# ---------------------------------------------------------------------------


def test_static_integer_value_left_shift_negative_right_returns_none() -> None:
    """A left-shift BinaryExpression with a negative right operand hits the
    early-return at line 468 and returns None."""
    # Arrange - right = -1 (UnaryExpression negation of 1)
    p = _parser_at("1")
    expr = BinaryExpression(
        left=IntegerLiteral(value=1),
        operator="<<",
        right=UnaryExpression(operator="-", operand=IntegerLiteral(value=1)),
    )

    # Act
    result = p._static_integer_value(expr)

    # Assert
    assert result is None


def test_static_integer_value_right_shift_negative_right_returns_none() -> None:
    """A right-shift BinaryExpression with a negative right operand hits line 468."""
    # Arrange
    p = _parser_at("1")
    expr = BinaryExpression(
        left=IntegerLiteral(value=8),
        operator=">>",
        right=UnaryExpression(operator="-", operand=IntegerLiteral(value=2)),
    )

    # Act
    result = p._static_integer_value(expr)

    # Assert
    assert result is None


# ---------------------------------------------------------------------------
# Line 482 - _static_integer_value: modulo with zero divisor
# ---------------------------------------------------------------------------


def test_static_integer_value_modulo_by_zero_returns_none() -> None:
    """Modulo where the right operand statically evaluates to zero must
    return None (line 482) to avoid ZeroDivisionError."""
    # Arrange
    p = _parser_at("1")
    expr = BinaryExpression(
        left=IntegerLiteral(value=7),
        operator="%",
        right=IntegerLiteral(value=0),
    )

    # Act
    result = p._static_integer_value(expr)

    # Assert
    assert result is None


def test_static_integer_value_modulo_nonzero_returns_remainder() -> None:
    """Modulo with a non-zero divisor returns the correct remainder."""
    # Arrange
    p = _parser_at("1")
    expr = BinaryExpression(
        left=IntegerLiteral(value=7),
        operator="%",
        right=IntegerLiteral(value=3),
    )

    # Act
    result = p._static_integer_value(expr)

    # Assert
    assert result == 1


# ---------------------------------------------------------------------------
# Lines 494-497 - _static_integer_value: bitwise &, |, ^ operators
# ---------------------------------------------------------------------------


def test_static_integer_value_bitwise_and() -> None:
    """BinaryExpression '&' is evaluated at line 493-494."""
    p = _parser_at("1")
    expr = BinaryExpression(
        left=IntegerLiteral(value=0b1100),
        operator="&",
        right=IntegerLiteral(value=0b1010),
    )
    result = p._static_integer_value(expr)
    assert result == 0b1000  # 8


def test_static_integer_value_bitwise_or() -> None:
    """BinaryExpression '|' is evaluated at lines 494-495."""
    p = _parser_at("1")
    expr = BinaryExpression(
        left=IntegerLiteral(value=0b1100),
        operator="|",
        right=IntegerLiteral(value=0b1010),
    )
    result = p._static_integer_value(expr)
    assert result == 0b1110  # 14


def test_static_integer_value_bitwise_xor() -> None:
    """BinaryExpression '^' is evaluated at lines 496-497."""
    p = _parser_at("1")
    expr = BinaryExpression(
        left=IntegerLiteral(value=0b1100),
        operator="^",
        right=IntegerLiteral(value=0b1010),
    )
    result = p._static_integer_value(expr)
    assert result == 0b0110  # 6


# ---------------------------------------------------------------------------
# Lines 523->525 - _integer_remainder: same-sign branch (branch NOT taken)
# ---------------------------------------------------------------------------


def test_integer_remainder_both_positive() -> None:
    """Both operands positive: line 523's condition is False, branches to 525."""
    assert _integer_remainder(7, 3) == 1


def test_integer_remainder_both_negative() -> None:
    """Both operands negative: line 523's condition is False, branches to 525."""
    # abs(-7)//abs(-3) = 2, same sign -> quotient stays 2, result = -7 - 2*(-3) = -1
    assert _integer_remainder(-7, -3) == -1


def test_integer_remainder_mixed_signs_positive_left() -> None:
    """Left positive, right negative: line 523-524 branch IS taken."""
    # abs(7)//abs(-3) = 2, signs differ -> quotient = -2, result = 7 - (-2)*(-3) = 1
    assert _integer_remainder(7, -3) == 1


def test_integer_remainder_mixed_signs_negative_left() -> None:
    """Left negative, right positive: line 523-524 branch IS taken."""
    # abs(-7)//abs(3) = 2, signs differ -> quotient = -2, result = -7 - (-2)*3 = -1
    assert _integer_remainder(-7, 3) == -1


# ---------------------------------------------------------------------------
# Line 542 - _shift_left_int64: right >= 64 returns 0
# ---------------------------------------------------------------------------


def test_shift_left_int64_shift_by_64_returns_zero() -> None:
    """Shifting left by exactly 64 bits returns 0 (line 542)."""
    assert _shift_left_int64(1, 64) == 0


def test_shift_left_int64_shift_by_more_than_64_returns_zero() -> None:
    """Shifting left by more than 64 bits returns 0 (line 542)."""
    assert _shift_left_int64(1, 100) == 0


def test_shift_left_int64_shift_by_less_than_64_normalizes() -> None:
    """Shifting left by fewer than 64 bits normalizes to int64 range."""
    result = _shift_left_int64(1, 1)
    assert result == 2


# ---------------------------------------------------------------------------
# Line 548 - _shift_right_int64: right >= 64 returns 0
# ---------------------------------------------------------------------------


def test_shift_right_int64_shift_by_64_returns_zero() -> None:
    """Shifting right by exactly 64 bits returns 0 (line 548)."""
    assert _shift_right_int64(1, 64) == 0


def test_shift_right_int64_shift_by_more_than_64_returns_zero() -> None:
    """Shifting right by more than 64 bits returns 0 (line 548)."""
    assert _shift_right_int64(0xFFFF_FFFF_FFFF_FFFF, 128) == 0


def test_shift_right_int64_shift_by_less_than_64_produces_correct_value() -> None:
    """Shifting right by fewer than 64 bits yields the expected result."""
    assert _shift_right_int64(8, 3) == 1


# ---------------------------------------------------------------------------
# Integration: full-rule parse exercises of-restriction and bitwise operators
# ---------------------------------------------------------------------------


def test_full_rule_string_set_at_restriction_parses_correctly() -> None:
    """A string-set 'of' expression with an 'at' restriction is valid syntax."""
    source = 'rule test { strings: $a = "hello" condition: 1 of ($a) at 0 }'
    condition = _rule_condition(source)
    assert isinstance(condition, AtExpression)
    assert isinstance(condition.string_id, OfExpression)


def test_full_rule_string_set_in_restriction_parses_correctly() -> None:
    """A string-set 'of' expression with an 'in' restriction is valid syntax."""
    source = 'rule test { strings: $a = "hello" condition: 1 of ($a) in (0..10) }'
    condition = _rule_condition(source)
    assert isinstance(condition, InExpression)


def test_full_rule_bitwise_and_as_of_quantifier() -> None:
    """Bitwise & operator parses and produces a valid of-expression quantifier."""
    source = 'rule test { strings: $a = "x" condition: (5 & 3) of ($*) }'
    condition = _rule_condition(source)
    assert isinstance(condition, OfExpression)
    # The parser unwraps the outer parentheses; quantifier is the BinaryExpression
    assert isinstance(condition.quantifier, BinaryExpression)
    assert condition.quantifier.operator == "&"


def test_normalize_int64_wraps_overflow_to_negative() -> None:
    """_normalize_int64 wraps values above INT64_MAX to negative two's complement."""
    int64_max = (1 << 63) - 1
    # INT64_MAX + 1 should wrap to INT64_MIN
    result = _normalize_int64(int64_max + 1)
    assert result == -(1 << 63)


def test_normalize_int64_preserves_positive_values() -> None:
    """_normalize_int64 leaves values within [0, INT64_MAX] unchanged."""
    assert _normalize_int64(0) == 0
    assert _normalize_int64(1) == 1
    assert _normalize_int64((1 << 63) - 1) == (1 << 63) - 1


def test_static_integer_value_shift_left_result() -> None:
    """Left shift with right < 64 returns correctly normalized int64 value."""
    p = _parser_at("1")
    expr = BinaryExpression(
        left=IntegerLiteral(value=1),
        operator="<<",
        right=IntegerLiteral(value=3),
    )
    result = p._static_integer_value(expr)
    assert result == 8


def test_static_integer_value_shift_right_result() -> None:
    """Right shift with right < 64 returns correctly normalized int64 value."""
    p = _parser_at("1")
    expr = BinaryExpression(
        left=IntegerLiteral(value=16),
        operator=">>",
        right=IntegerLiteral(value=2),
    )
    result = p._static_integer_value(expr)
    assert result == 4


def test_static_integer_value_shift_left_exactly_64_returns_zero() -> None:
    """Left shift by exactly 64 returns 0 through _static_integer_value."""
    p = _parser_at("1")
    expr = BinaryExpression(
        left=IntegerLiteral(value=1),
        operator="<<",
        right=IntegerLiteral(value=64),
    )
    result = p._static_integer_value(expr)
    assert result == 0
