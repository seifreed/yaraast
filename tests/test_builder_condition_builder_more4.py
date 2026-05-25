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

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        ConditionBuilder().integer(cast(Any, "1"))


def test_condition_builder_n_of_rejects_boolean_quantifier() -> None:
    with pytest.raises(TypeError, match="Invalid integer literal value"):
        ConditionBuilder().n_of(cast(Any, True), "$a", "$b")

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        ConditionBuilder().n_of(cast(Any, 1.5), "$a", "$b")


def test_condition_builder_rejects_empty_string_sets() -> None:
    with pytest.raises(ValidationError, match="At least one string identifier is required"):
        ConditionBuilder().any_of()

    with pytest.raises(ValidationError, match="At least one string identifier is required"):
        ConditionBuilder().all_of()

    with pytest.raises(ValidationError, match="At least one string identifier is required"):
        ConditionBuilder().n_of(1)


def test_condition_builder_rejects_mixed_them_string_sets() -> None:
    with pytest.raises(ValidationError, match="'them' cannot be mixed"):
        ConditionBuilder().any_of("them", "$a")

    with pytest.raises(ValidationError, match="'them' cannot be mixed"):
        ConditionBuilder().all_of("$a", "them")

    with pytest.raises(ValidationError, match="'them' cannot be mixed"):
        ConditionBuilder().n_of(1, "$a", "them")


def test_condition_builder_rejects_boolean_offsets_and_range_bounds() -> None:
    with pytest.raises(TypeError, match="Invalid integer literal value"):
        ConditionBuilder().string("$a").at(cast(Any, True))

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        ConditionBuilder().string("$a").in_range(cast(Any, False), 10)

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        ConditionBuilder().range(0, cast(Any, True))


def test_condition_builder_errors_on_empty() -> None:
    with pytest.raises(ValidationError):
        ConditionBuilder().and_(ConditionBuilder().true())

    with pytest.raises(ValidationError):
        ConditionBuilder().group()

    with pytest.raises(ValidationError):
        ConditionBuilder().build()

    with pytest.raises(TypeError):
        ConditionBuilder().integer(1)._to_expression(cast(Any, 3.14))
