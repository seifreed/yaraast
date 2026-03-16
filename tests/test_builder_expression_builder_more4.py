"""More tests for expression builder utilities (no mocks)."""

from __future__ import annotations

import pytest

from yaraast.ast.conditions import ForExpression, OfExpression
from yaraast.ast.expressions import ArrayAccess, BinaryExpression, IntegerLiteral, UnaryExpression
from yaraast.builder.expression_builder import ExpressionBuilder


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


def test_expression_builder_accessors_and_errors() -> None:
    arr = ExpressionBuilder.array_access(ExpressionBuilder.identifier("arr"), 1)
    assert isinstance(arr, ArrayAccess)
    assert isinstance(arr.index, IntegerLiteral)

    with pytest.raises(ValueError):
        ExpressionBuilder.and_()

    with pytest.raises(ValueError):
        ExpressionBuilder.or_()
