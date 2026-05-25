"""More tests for expression builder utilities (no mocks)."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.conditions import ForExpression, OfExpression
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    Identifier,
    IntegerLiteral,
    UnaryExpression,
)
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


@pytest.mark.parametrize("variable", ["bad-key", "for", "1bad", ""])
def test_expression_builder_rejects_invalid_loop_variables(variable: str) -> None:
    iterable = ExpressionBuilder.range(0, 2)
    body = ExpressionBuilder.true()

    with pytest.raises(ValidationError, match="Invalid loop variable identifier"):
        ExpressionBuilder.for_any(variable, iterable, body)

    with pytest.raises(ValidationError, match="Invalid loop variable identifier"):
        ExpressionBuilder.for_all(variable, iterable, body)


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


def test_expression_builder_rejects_invalid_double_values() -> None:
    with pytest.raises(TypeError, match="Double literal value must be numeric"):
        ExpressionBuilder.double(cast(Any, True))

    with pytest.raises(TypeError, match="Double literal value must be numeric"):
        ExpressionBuilder.double(cast(Any, "1.5"))

    with pytest.raises(ValueError, match="Double literal value must be finite"):
        ExpressionBuilder.double(float("nan"))

    with pytest.raises(ValueError, match="Double literal value must be finite"):
        ExpressionBuilder.double(float("inf"))


def test_expression_builder_rejects_invalid_string_literal_values() -> None:
    invalid_values = (True, 123, ["x"])

    for value in invalid_values:
        with pytest.raises(TypeError, match="String literal value must be a string"):
            ExpressionBuilder.string_literal(cast(Any, value))


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


@pytest.mark.parametrize("identifier", ["$bad-key", "$bad space", "$", ""])
def test_expression_builder_rejects_invalid_string_references(identifier: str) -> None:
    with pytest.raises(ValidationError, match="Invalid string reference"):
        ExpressionBuilder.string(identifier)

    with pytest.raises(ValidationError, match="Invalid string reference"):
        ExpressionBuilder.string_set("$a", identifier)

    with pytest.raises(ValidationError, match="Invalid string reference"):
        ExpressionBuilder.any_of("$a", identifier)

    with pytest.raises(ValidationError, match="Invalid string reference"):
        ExpressionBuilder.all_of(identifier)

    with pytest.raises(ValidationError, match="Invalid string reference"):
        ExpressionBuilder.n_of(1, identifier)

    with pytest.raises(ValidationError, match="Invalid string reference"):
        ExpressionBuilder.at(identifier, 0)

    with pytest.raises(ValidationError, match="Invalid string reference"):
        ExpressionBuilder.in_(identifier, 0, 1)


def test_expression_builder_treats_all_them_as_special_string_set() -> None:
    expr = ExpressionBuilder.any_of("them")

    assert isinstance(expr, OfExpression)
    assert isinstance(expr.string_set, Identifier)
    assert expr.string_set.name == "them"

    expr = ExpressionBuilder.n_of(1, "them", "them")
    assert isinstance(expr.string_set, Identifier)
    assert expr.string_set.name == "them"


def test_expression_builder_accessors_and_errors() -> None:
    arr = ExpressionBuilder.array_access(ExpressionBuilder.identifier("arr"), 1)
    assert isinstance(arr, ArrayAccess)
    assert isinstance(arr.index, IntegerLiteral)

    with pytest.raises(ValidationError):
        ExpressionBuilder.and_()

    with pytest.raises(ValidationError):
        ExpressionBuilder.or_()


@pytest.mark.parametrize("function", ["bad-key", "math..entropy", "for.fn", ""])
def test_expression_builder_rejects_invalid_function_names(function: str) -> None:
    with pytest.raises(ValidationError, match="Invalid function identifier"):
        ExpressionBuilder.function_call(function)


@pytest.mark.parametrize("member", ["bad-key", "for", "1bad", ""])
def test_expression_builder_rejects_invalid_member_names(member: str) -> None:
    with pytest.raises(ValidationError, match="Invalid member identifier"):
        ExpressionBuilder.member_access(ExpressionBuilder.identifier("pe"), member)
