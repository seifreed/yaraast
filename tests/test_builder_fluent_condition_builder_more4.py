"""More tests for fluent condition builder (no mocks)."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.conditions import AtExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    Identifier,
    IntegerLiteral,
    SetExpression,
    UnaryExpression,
)
from yaraast.builder.fluent_condition_builder import FluentConditionBuilder
from yaraast.codegen.generator import CodeGenerator
from yaraast.errors import ValidationError


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

    # at_least_n_of should use YARA's threshold quantifier directly.
    expr = FluentConditionBuilder().at_least_n_of(1, "$a", "$b").build()
    assert isinstance(expr, OfExpression)


def test_fluent_condition_exact_and_upper_bound_quantifiers() -> None:
    generator = CodeGenerator()

    one = FluentConditionBuilder().one_of("$a", "$b").build()
    assert generator.visit(one) == "1 of ($a, $b) and not 2 of ($a, $b)"

    at_most = FluentConditionBuilder().at_most_n_of(1, "$a", "$b", "$c").build()
    assert generator.visit(at_most) == "not 2 of ($a, $b, $c)"

    between = FluentConditionBuilder().between_n_and_m_of(1, 2, "$a", "$b", "$c").build()
    assert generator.visit(between) == "1 of ($a, $b, $c) and not 3 of ($a, $b, $c)"


def test_fluent_condition_builder_rejects_empty_string_sets() -> None:
    with pytest.raises(ValidationError, match="At least one string identifier is required"):
        FluentConditionBuilder().one_of()

    with pytest.raises(ValidationError, match="At least one string identifier is required"):
        FluentConditionBuilder().at_most_n_of(1)


def test_fluent_condition_builder_rejects_mixed_them_string_sets() -> None:
    with pytest.raises(ValidationError, match="'them' cannot be mixed"):
        FluentConditionBuilder().one_of("them", "$a")

    with pytest.raises(ValidationError, match="'them' cannot be mixed"):
        FluentConditionBuilder().at_least_n_of(1, "$a", "them")


def test_fluent_condition_helpers_return_literals() -> None:
    expr = FluentConditionBuilder()._create_n_of(1, "$a", "$b")
    assert isinstance(expr, OfExpression)
    assert isinstance(expr.quantifier, IntegerLiteral)
    assert isinstance(expr.string_set, SetExpression | Identifier)


def test_fluent_condition_builder_rejects_boolean_integer_arguments() -> None:
    builder = FluentConditionBuilder()

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        builder.string_at_offset("$a", cast(Any, True))

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        builder.pe_section_count_eq(cast(Any, True))

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        builder.at_least_n_of(cast(Any, True), "$a", "$b")

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        builder.filesize_gt(cast(Any, "10"))

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        builder.entropy_gt(0, cast(Any, 3.5), 7.0)
