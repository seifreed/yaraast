"""More tests for condition builder (no mocks)."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.conditions import ForExpression, InExpression
from yaraast.ast.expressions import BinaryExpression, BooleanLiteral, ParenthesesExpression
from yaraast.builder.condition_builder import ConditionBuilder
from yaraast.errors import ValidationError


def test_condition_builder_basic_ops() -> None:
    expr = ConditionBuilder().string("$a").at(0).and_(ConditionBuilder().filesize().gt(10)).build()
    assert isinstance(expr, BinaryExpression)

    expr = ConditionBuilder().string("$a").in_range(0, 10).build()
    assert isinstance(expr, InExpression)


def test_condition_builder_group_and_for() -> None:
    grouped = ConditionBuilder().integer(1).eq(1).group().build()
    assert isinstance(grouped, ParenthesesExpression)

    iterable = ConditionBuilder().range(0, 3)
    body = ConditionBuilder().identifier("i").lt(2)
    loop = ConditionBuilder().for_any("i", iterable, body).build()
    assert isinstance(loop, ForExpression)


def test_condition_builder_keeps_boolean_values_distinct_from_integers() -> None:
    comparison = ConditionBuilder().identifier("enabled").eq(True).build()

    assert isinstance(comparison, BinaryExpression)
    assert isinstance(comparison.right, BooleanLiteral)
    assert comparison.right.value is True

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        ConditionBuilder().integer(cast(Any, True))


def test_condition_builder_errors_on_empty() -> None:
    with pytest.raises(ValidationError):
        ConditionBuilder().and_(ConditionBuilder().true())

    with pytest.raises(ValidationError):
        ConditionBuilder().group()

    with pytest.raises(ValidationError):
        ConditionBuilder().build()

    with pytest.raises(TypeError):
        ConditionBuilder().integer(1)._to_expression(cast(Any, 3.14))
