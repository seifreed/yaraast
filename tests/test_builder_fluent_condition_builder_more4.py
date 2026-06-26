"""More tests for fluent condition builder (no mocks)."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.conditions import AtExpression, OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    Identifier,
    IntegerLiteral,
    SetExpression,
    UnaryExpression,
)
from yaraast.builder.condition_builder import ConditionBuilder
from yaraast.builder.fluent_condition_builder import FluentConditionBuilder
from yaraast.codegen.generator import CodeGenerator
from yaraast.errors import ValidationError


def test_fluent_condition_quantifiers_and_strings() -> None:
    expr = ConditionBuilder().any_of("them").build()
    assert isinstance(expr, OfExpression)

    expr = ConditionBuilder().all_of("them").build()
    assert isinstance(expr, OfExpression)

    expr = ConditionBuilder().any_of("them").not_().build()
    assert isinstance(expr, UnaryExpression)

    expr = ConditionBuilder().string_count("$a").gt(2).build()
    assert isinstance(expr, BinaryExpression)


def test_fluent_condition_offsets_and_ranges() -> None:
    expr = FluentConditionBuilder().string_matches("$a").at(0).build()
    assert isinstance(expr, AtExpression)

    expr = FluentConditionBuilder().string_at_offset("$a", 1024).build()
    assert isinstance(expr, AtExpression)


def test_fluent_condition_filesize_and_entropy() -> None:
    expr = FluentConditionBuilder().filesize_between(1, 10).build()
    assert isinstance(expr, BinaryExpression)

    expr = FluentConditionBuilder().high_entropy().build()
    assert isinstance(expr, BinaryExpression)

    expr = FluentConditionBuilder().entropy_gt(0, 1024, 7.0).build()
    assert isinstance(expr, BinaryExpression)

    expr = FluentConditionBuilder().n_of(1, "$a", "$b").build()
    assert isinstance(expr, OfExpression)


def test_fluent_condition_exact_and_upper_bound_quantifiers() -> None:
    generator = CodeGenerator()

    one = FluentConditionBuilder().one_of("$a", "$b").build()
    assert generator.visit(one) == "1 of ($a, $b)"

    exact = FluentConditionBuilder().n_of(2, "$a", "$b", "$c").build()
    assert generator.visit(exact) == "2 of ($a, $b, $c)"


def test_fluent_condition_builder_rejects_empty_string_sets() -> None:
    with pytest.raises(ValidationError, match="At least one string identifier is required"):
        FluentConditionBuilder().one_of()

    with pytest.raises(ValidationError, match="At least one string identifier is required"):
        FluentConditionBuilder().n_of(1)


def test_fluent_condition_builder_rejects_mixed_them_string_sets() -> None:
    with pytest.raises(ValidationError, match="'them' cannot be mixed"):
        FluentConditionBuilder().one_of("them", "$a")

    with pytest.raises(ValidationError, match="'them' cannot be mixed"):
        FluentConditionBuilder().n_of(1, "$a", "them")


def test_fluent_condition_builder_rejects_invalid_string_count_identifiers() -> None:
    builder = FluentConditionBuilder()

    with pytest.raises(ValidationError, match="Invalid string reference"):
        builder.string_count_eq("#", 1)

    with pytest.raises(ValidationError, match="Invalid string reference"):
        ConditionBuilder().string_count("bad-key").gt(1)


def test_fluent_condition_helpers_return_literals() -> None:
    builder = FluentConditionBuilder()

    assert not hasattr(builder, "_create_n_of")
    expr = builder.one_of("$a", "$b").build()
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
        builder.n_of(cast(Any, True), "$a", "$b")

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        builder.filesize_gt(cast(Any, "10"))

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        builder.entropy_gt(0, cast(Any, 3.5), 7.0)


def test_fluent_condition_builder_rejects_invalid_entropy_thresholds() -> None:
    builder = FluentConditionBuilder()

    with pytest.raises(TypeError, match="Double literal value must be numeric"):
        builder.entropy_gt(0, 1024, cast(Any, True))

    with pytest.raises(TypeError, match="Double literal value must be numeric"):
        builder.entropy_gt(0, 1024, cast(Any, "7.0"))

    with pytest.raises(ValueError, match="Double literal value must be finite"):
        builder.entropy_gt(0, 1024, float("nan"))

    with pytest.raises(ValueError, match="Double literal value must be finite"):
        builder.entropy_gt(0, 1024, float("inf"))


def test_fluent_condition_builder_rejects_invalid_pe_string_arguments() -> None:
    builder = FluentConditionBuilder()

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        builder.pe_section_count_eq(cast(Any, True))
