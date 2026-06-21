"""Regression tests targeting uncovered lines in fluent_condition_builder.py.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Missing lines before this file: 63, 81-82, 84, 231-232
- Line 63:    at_most_n_of(0, ...) -> build_of_expression("none", string_set)
- Lines 81-82: between_n_and_m_of with min_n > max_m -> ValidationError
- Line 84:    between_n_and_m_of with min_n == 0 -> delegates to at_most_n_of
- Lines 231-232: _validate_quantifier_count with count < 0 -> ValidationError
"""

from __future__ import annotations

import pytest

from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import StringLiteral, UnaryExpression
from yaraast.builder.fluent_condition_builder import FluentConditionBuilder
from yaraast.codegen.generator import CodeGenerator
from yaraast.errors import ValidationError


def test_at_most_n_of_zero_produces_none_of_expression() -> None:
    """at_most_n_of(0, ...) must emit 'none of (...)' via build_of_expression("none", ...).

    Covers line 63: return FluentConditionBuilder(build_of_expression("none", string_set))
    """
    expr = FluentConditionBuilder().at_most_n_of(0, "$a", "$b").build()

    assert isinstance(expr, OfExpression)
    assert isinstance(expr.quantifier, StringLiteral)
    assert expr.quantifier.value == "none"

    gen = CodeGenerator()
    assert gen.visit(expr) == "none of ($a, $b)"


def test_at_most_n_of_zero_with_them_keyword() -> None:
    """at_most_n_of(0, 'them') uses the 'them' identifier and still emits 'none of them'.

    Additional branch for the "none of" path with a non-set string_set.
    """
    expr = FluentConditionBuilder().at_most_n_of(0, "them").build()

    assert isinstance(expr, OfExpression)
    assert isinstance(expr.quantifier, StringLiteral)
    assert expr.quantifier.value == "none"

    gen = CodeGenerator()
    assert gen.visit(expr) == "none of them"


def test_between_n_and_m_of_raises_when_min_exceeds_max() -> None:
    """between_n_and_m_of must raise ValidationError when min_n > max_m.

    Covers lines 81-82:
        msg = f"Minimum count {min_n} cannot exceed maximum {max_m}"
        raise ValidationError(msg)
    """
    with pytest.raises(ValidationError, match="Minimum count 3 cannot exceed maximum 2"):
        FluentConditionBuilder().between_n_and_m_of(3, 2, "$a", "$b")


def test_between_n_and_m_of_min_exceeds_max_various_values() -> None:
    """Parametric boundary checks for the min > max guard in between_n_and_m_of.

    Exercises lines 81-82 with different concrete values to confirm the error
    message includes both numbers.
    """
    with pytest.raises(ValidationError, match="Minimum count 5 cannot exceed maximum 1"):
        FluentConditionBuilder().between_n_and_m_of(5, 1, "$a")

    with pytest.raises(ValidationError, match="Minimum count 10 cannot exceed maximum 9"):
        FluentConditionBuilder().between_n_and_m_of(10, 9, "$a", "$b", "$c")


def test_between_n_and_m_of_zero_min_delegates_to_at_most_n_of() -> None:
    """between_n_and_m_of(0, M, ...) must delegate to at_most_n_of(M, ...).

    Covers line 84: return self.at_most_n_of(max_m, *strings)

    The output must be identical to calling at_most_n_of(M, ...) directly
    since between_n_and_m_of short-circuits when min_n == 0.
    """
    result_via_between = FluentConditionBuilder().between_n_and_m_of(0, 2, "$a", "$b").build()
    result_via_at_most = FluentConditionBuilder().at_most_n_of(2, "$a", "$b").build()

    gen = CodeGenerator()
    assert gen.visit(result_via_between) == gen.visit(result_via_at_most)
    assert gen.visit(result_via_between) == "not 3 of ($a, $b)"


def test_between_n_and_m_of_zero_min_with_single_string() -> None:
    """between_n_and_m_of(0, 1, '$a') must emit 'not 2 of ($a)'.

    Additional coverage of line 84 with a minimal string set.
    """
    expr = FluentConditionBuilder().between_n_and_m_of(0, 1, "$a").build()

    assert isinstance(expr, UnaryExpression)
    assert expr.operator == "not"

    gen = CodeGenerator()
    assert gen.visit(expr) == "not 2 of ($a)"


def test_between_n_and_m_of_zero_min_zero_max_produces_none_of() -> None:
    """between_n_and_m_of(0, 0, ...) delegates to at_most_n_of(0, ...) -> 'none of (...)'.

    Combined path: line 84 delegates to at_most_n_of which then executes line 63.
    """
    expr = FluentConditionBuilder().between_n_and_m_of(0, 0, "$a", "$b").build()

    assert isinstance(expr, OfExpression)
    assert isinstance(expr.quantifier, StringLiteral)
    assert expr.quantifier.value == "none"

    gen = CodeGenerator()
    assert gen.visit(expr) == "none of ($a, $b)"


def test_validate_quantifier_count_raises_for_negative_via_at_least_n_of() -> None:
    """at_least_n_of with a negative count must raise ValidationError.

    Covers lines 231-232 in _validate_quantifier_count:
        msg = f"{name} count must be non-negative, got {count}"
        raise ValidationError(msg)

    _validate_quantifier_count is called with name="Minimum" from at_least_n_of.
    """
    with pytest.raises(ValidationError, match="Minimum count must be non-negative, got -1"):
        FluentConditionBuilder().at_least_n_of(-1, "$a")


def test_validate_quantifier_count_raises_for_negative_via_at_most_n_of() -> None:
    """at_most_n_of with a negative count must raise ValidationError.

    Covers lines 231-232: _validate_quantifier_count called with name="Maximum".
    """
    with pytest.raises(ValidationError, match="Maximum count must be non-negative, got -1"):
        FluentConditionBuilder().at_most_n_of(-1, "$a")


def test_validate_quantifier_count_raises_for_negative_via_between() -> None:
    """between_n_and_m_of with a negative min_n must raise ValidationError.

    Covers lines 231-232 via _validate_quantifier_count("Minimum", min_n).
    The negative check fires before the min > max guard (line 78 before 80).
    """
    with pytest.raises(ValidationError, match="Minimum count must be non-negative, got -2"):
        FluentConditionBuilder().between_n_and_m_of(-2, 3, "$a")


def test_validate_quantifier_count_raises_for_negative_max_via_between() -> None:
    """between_n_and_m_of with negative max_m must raise ValidationError.

    Covers lines 231-232 via _validate_quantifier_count("Maximum", max_m).
    Called after min_n validation passes (min_n=0, max_m=-1).
    """
    with pytest.raises(ValidationError, match="Maximum count must be non-negative, got -1"):
        FluentConditionBuilder().between_n_and_m_of(0, -1, "$a")
