"""More tests for condition builder (no mocks)."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.conditions import ForExpression, InExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    ParenthesesExpression,
    StringLiteral,
)
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


def test_condition_builder_rejects_invalid_logical_operands() -> None:
    builder = ConditionBuilder().true()

    with pytest.raises(ValidationError, match="Empty condition builder"):
        builder.and_(ConditionBuilder())

    with pytest.raises(ValidationError, match="Empty condition builder"):
        builder.or_(ConditionBuilder())

    with pytest.raises(TypeError, match="Logical operand must be a ConditionBuilder or Expression"):
        builder.and_(cast(Any, 1))

    with pytest.raises(TypeError, match="Logical operand must be a ConditionBuilder or Expression"):
        builder.or_(cast(Any, True))


def test_condition_builder_accepts_falsy_present_expressions() -> None:
    class FalsyBooleanLiteral(BooleanLiteral):
        def __bool__(self) -> bool:
            return False

    falsy_builder = ConditionBuilder(FalsyBooleanLiteral(value=False))

    assert isinstance(falsy_builder.build(), FalsyBooleanLiteral)

    logical = falsy_builder.and_(ConditionBuilder().true()).build()
    assert isinstance(logical, BinaryExpression)
    assert isinstance(logical.left, FalsyBooleanLiteral)

    converted_operand = ConditionBuilder().true().or_(falsy_builder).build()
    assert isinstance(converted_operand, BinaryExpression)
    assert isinstance(converted_operand.right, FalsyBooleanLiteral)


@pytest.mark.parametrize("member", ["bad-key", "for", "1bad", ""])
def test_condition_builder_rejects_invalid_member_names(member: str) -> None:
    with pytest.raises(ValidationError, match="Invalid member identifier"):
        ConditionBuilder().member_access(ConditionBuilder().identifier("pe"), member)


@pytest.mark.parametrize("variable", ["bad-key", "for", "1bad", ""])
def test_condition_builder_rejects_invalid_loop_variables(variable: str) -> None:
    iterable = ConditionBuilder().range(0, 3)
    body = ConditionBuilder().true()

    with pytest.raises(ValidationError, match="Invalid loop variable identifier"):
        ConditionBuilder().for_any(variable, iterable, body)

    with pytest.raises(ValidationError, match="Invalid loop variable identifier"):
        ConditionBuilder().for_all(variable, iterable, body)


def test_condition_builder_keeps_boolean_values_distinct_from_integers() -> None:
    comparison = ConditionBuilder().identifier("enabled").eq(True).build()

    assert isinstance(comparison, BinaryExpression)
    assert isinstance(comparison.right, BooleanLiteral)
    assert comparison.right.value is True

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        ConditionBuilder().integer(cast(Any, True))

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        ConditionBuilder().integer(cast(Any, "1"))


@pytest.mark.parametrize("identifier", ["", "bad-key", "for", "1bad", object()])
def test_condition_builder_rejects_invalid_generic_identifiers(identifier: Any) -> None:
    expected_error = TypeError if not isinstance(identifier, str) else ValidationError
    with pytest.raises(expected_error, match="Invalid identifier identifier"):
        ConditionBuilder().identifier(cast(Any, identifier))


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


def test_condition_builder_rejects_invalid_count_offset_length_identifiers() -> None:
    invalid_cases = (
        (ConditionBuilder().string_count, "#"),
        (ConditionBuilder().string_count, "##a"),
        (ConditionBuilder().string_count, "bad-key"),
        (ConditionBuilder().string_offset, "@"),
        (ConditionBuilder().string_offset, "@@a"),
        (ConditionBuilder().string_length, "!"),
        (ConditionBuilder().string_length, "!!a"),
    )

    for method, identifier in invalid_cases:
        with pytest.raises(ValidationError, match="Invalid string reference"):
            method(identifier)


def test_condition_builder_match_factory_validates_string_reference() -> None:
    with pytest.raises(ValidationError, match="Invalid string reference"):
        ConditionBuilder.match("$bad-key")

    with pytest.raises(TypeError, match="Invalid string reference"):
        ConditionBuilder.match(cast(Any, 123))


@pytest.mark.parametrize("identifier", ["$bad-key", "$bad space", "$"])
def test_condition_builder_rejects_invalid_string_references_during_conversion(
    identifier: str,
) -> None:
    builder = ConditionBuilder().identifier("x")

    with pytest.raises(ValidationError, match="Invalid string reference"):
        builder.eq(identifier)

    with pytest.raises(ValidationError, match="Invalid string reference"):
        builder._to_expression(identifier)


def test_condition_builder_rejects_boolean_offsets_and_range_bounds() -> None:
    with pytest.raises(TypeError, match="Invalid integer literal value"):
        ConditionBuilder().string("$a").at(cast(Any, True))

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        ConditionBuilder().string("$a").in_range(cast(Any, False), 10)

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        ConditionBuilder().range(0, cast(Any, True))

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        ConditionBuilder().array_access(ConditionBuilder().identifier("arr"), cast(Any, True))

    with pytest.raises(TypeError, match=r"Cannot convert .* to integer expression"):
        ConditionBuilder().array_access(ConditionBuilder().identifier("arr"), cast(Any, "0"))


def test_condition_builder_rejects_invalid_numeric_operands() -> None:
    builder = ConditionBuilder().filesize()

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        builder.gt(cast(Any, True))

    with pytest.raises(TypeError, match=r"Cannot convert .* to integer expression"):
        builder.lt(cast(Any, "10"))

    arithmetic = ConditionBuilder().integer(1)

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        arithmetic.add(cast(Any, True))

    with pytest.raises(TypeError, match=r"Cannot convert .* to integer expression"):
        arithmetic.sub(cast(Any, "1"))


def test_condition_builder_rejects_invalid_string_operator_patterns() -> None:
    builder = ConditionBuilder().identifier("filename")

    dollar_pattern = builder.contains("$a").build()
    assert isinstance(dollar_pattern, BinaryExpression)
    assert isinstance(dollar_pattern.right, StringLiteral)
    assert dollar_pattern.right.value == "$a"

    with pytest.raises(TypeError, match="String pattern must be"):
        builder.contains(cast(Any, 123))

    with pytest.raises(TypeError, match="String pattern must be"):
        builder.matches(cast(Any, True))


def test_condition_builder_errors_on_empty() -> None:
    with pytest.raises(ValidationError):
        ConditionBuilder().and_(ConditionBuilder().true())

    with pytest.raises(ValidationError):
        ConditionBuilder().group()

    with pytest.raises(ValidationError):
        ConditionBuilder().build()

    with pytest.raises(TypeError):
        ConditionBuilder().integer(1)._to_expression(cast(Any, 3.14))
