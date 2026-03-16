"""More tests for fluent condition builder (no mocks)."""

from __future__ import annotations

from yaraast.ast.conditions import AtExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    Identifier,
    IntegerLiteral,
    SetExpression,
    UnaryExpression,
)
from yaraast.builder.fluent_condition_builder import FluentConditionBuilder


def test_fluent_condition_quantifiers_and_strings() -> None:
    builder = FluentConditionBuilder().any_of_them()
    expr = builder.build()
    assert isinstance(expr, OfExpression)

    expr = FluentConditionBuilder().all_of_them().build()
    assert isinstance(expr, OfExpression)

    expr = FluentConditionBuilder().not_them().build()
    assert isinstance(expr, UnaryExpression)

    expr = FluentConditionBuilder().string_count_gt("$a", 2).build()
    assert isinstance(expr, BinaryExpression)


def test_fluent_condition_offsets_and_ranges() -> None:
    expr = FluentConditionBuilder().string_matches("$a").at(0).build()
    assert isinstance(expr, AtExpression)

    expr = FluentConditionBuilder().string_in_last_kb("$a").build()
    assert isinstance(expr, InExpression)


def test_fluent_condition_filesize_and_entropy() -> None:
    expr = FluentConditionBuilder().filesize_between(1, 10).build()
    assert isinstance(expr, BinaryExpression)

    expr = FluentConditionBuilder().high_entropy().build()
    assert isinstance(expr, BinaryExpression)

    expr = FluentConditionBuilder().entropy_gt(0, 1024, 7.0).build()
    assert isinstance(expr, BinaryExpression)

    # at_least_n_of should chain OR expressions
    expr = FluentConditionBuilder().at_least_n_of(1, "$a", "$b").build()
    assert isinstance(expr, BinaryExpression)


def test_fluent_condition_helpers_return_literals() -> None:
    expr = FluentConditionBuilder()._create_n_of(1, "$a", "$b")
    assert isinstance(expr, OfExpression)
    assert isinstance(expr.quantifier, IntegerLiteral)
    assert isinstance(expr.string_set, SetExpression | Identifier)
