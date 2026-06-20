"""Coverage for constant-folding range-bound validation and identifier checks.

``RangeExpression.validate_structure`` folds constant integer expressions for
its bounds (``yaraast.ast.expressions._constant_range_integer_value``) to reject
negative or inverted ranges. These tests drive every folded operator plus the
identifier validation error path.
"""

from __future__ import annotations

import pytest

from yaraast.ast.expressions import (
    BinaryExpression,
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    RangeExpression,
    UnaryExpression,
)


def _lit(value: int) -> IntegerLiteral:
    return IntegerLiteral(value=value)


def _binop(left: object, operator: str, right: object) -> BinaryExpression:
    return BinaryExpression(left=left, operator=operator, right=right)


@pytest.mark.parametrize("operator", ["+", "-", "*", "%", "&", "|", "^", "<<", ">>"])
def test_range_bound_folds_each_integer_operator(operator: str) -> None:
    # high folds to a non-negative value >= low (0), so validation passes.
    expr = RangeExpression(low=_lit(0), high=_binop(_lit(8), operator, _lit(2)))
    expr.validate_structure()


def test_range_bound_folds_nested_paren_and_unary() -> None:
    high = ParenthesesExpression(
        expression=_binop(UnaryExpression(operator="-", operand=_lit(4)), "+", _lit(20))
    )
    RangeExpression(low=_lit(0), high=high).validate_structure()


@pytest.mark.parametrize(
    ("low", "message"),
    [
        (UnaryExpression(operator="-", operand=_lit(5)), "cannot be negative"),
        (UnaryExpression(operator="~", operand=_lit(0)), "cannot be negative"),
    ],
)
def test_range_low_bound_negative_is_rejected(low: object, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        RangeExpression(low=low, high=_lit(10)).validate_structure()


def test_range_low_exceeds_high_is_rejected() -> None:
    with pytest.raises(ValueError, match="cannot exceed high bound"):
        RangeExpression(
            low=_lit(20), high=ParenthesesExpression(expression=_lit(5))
        ).validate_structure()


def test_range_modulo_by_zero_is_not_folded() -> None:
    # right operand 0 makes the bound non-constant, so no range error is raised.
    RangeExpression(low=_lit(0), high=_binop(_lit(8), "%", _lit(0))).validate_structure()


def test_invalid_identifier_is_rejected() -> None:
    with pytest.raises(ValueError, match="Invalid identifier"):
        Identifier(name="123bad!").validate_structure()


def test_dollar_prefixed_identifier_is_accepted() -> None:
    Identifier(name="$abc").validate_structure()
