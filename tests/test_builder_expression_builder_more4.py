"""More tests for expression builder utilities (no mocks)."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.conditions import ForExpression, OfExpression
from yaraast.ast.expressions import ArrayAccess, BinaryExpression, IntegerLiteral, UnaryExpression
from yaraast.builder.expression_builder import ExpressionBuilder
from yaraast.errors import ValidationError


def test_expression_builder_combinators() -> None:
    expr = ExpressionBuilder.and_(
        ExpressionBuilder.true(),
        ExpressionBuilder.false(),
    )
    assert isinstance(expr, BinaryExpression)

    expr = ExpressionBuilder.or_(
        ExpressionBuilder.identifier("a"),
        ExpressionBuilder.identifier("b"),
    )
    assert isinstance(expr, BinaryExpression)

    expr = ExpressionBuilder.not_(ExpressionBuilder.true())
    assert isinstance(expr, UnaryExpression)


def test_expression_builder_quantifiers_and_loops() -> None:
    expr = ExpressionBuilder.any_of("$a", "$b")
    assert isinstance(expr, OfExpression)

    expr = ExpressionBuilder.n_of(2, "$a", "$b", "$c")
    assert isinstance(expr, OfExpression)

    loop = ExpressionBuilder.for_any("i", ExpressionBuilder.range(0, 2), ExpressionBuilder.true())
    assert isinstance(loop, ForExpression)


def test_expression_builder_rejects_booleans_as_integer_values() -> None:
    with pytest.raises(TypeError, match="Invalid integer literal value"):
        ExpressionBuilder.integer(cast(Any, True))

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        ExpressionBuilder.range(cast(Any, True), 2)


def test_expression_builder_rejects_non_integer_literal_values() -> None:
    with pytest.raises(TypeError, match="Invalid integer literal value"):
        ExpressionBuilder.integer(cast(Any, "1"))

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        ExpressionBuilder.range(0, cast(Any, 2.5))

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        ExpressionBuilder.array_access(ExpressionBuilder.identifier("arr"), cast(Any, "0"))


def test_expression_builder_rejects_empty_string_sets() -> None:
    with pytest.raises(ValidationError, match="At least one string identifier is required"):
        ExpressionBuilder.string_set()

    with pytest.raises(ValidationError, match="At least one string identifier is required"):
        ExpressionBuilder.any_of()

    with pytest.raises(ValidationError, match="At least one string identifier is required"):
        ExpressionBuilder.n_of(1)


def test_expression_builder_rejects_mixed_them_string_sets() -> None:
    with pytest.raises(ValidationError, match="'them' cannot be mixed"):
        ExpressionBuilder.any_of("them", "$a")

    with pytest.raises(ValidationError, match="'them' cannot be mixed"):
        ExpressionBuilder.all_of("$a", "them")

    with pytest.raises(ValidationError, match="'them' cannot be mixed"):
        ExpressionBuilder.n_of(1, "$a", "them")


def test_expression_builder_accessors_and_errors() -> None:
    arr = ExpressionBuilder.array_access(ExpressionBuilder.identifier("arr"), 1)
    assert isinstance(arr, ArrayAccess)
    assert isinstance(arr.index, IntegerLiteral)

    with pytest.raises(ValidationError):
        ExpressionBuilder.and_()

    with pytest.raises(ValidationError):
        ExpressionBuilder.or_()
