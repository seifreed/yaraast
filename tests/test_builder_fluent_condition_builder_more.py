"""Real tests for fluent condition builder helpers (no mocks)."""

from __future__ import annotations

import pytest

from yaraast.ast.expressions import BooleanLiteral
from yaraast.builder.condition_builder import ConditionBuilder
from yaraast.builder.fluent_condition_builder import FluentConditionBuilder
from yaraast.errors import ValidationError


def test_fluent_condition_quantifiers() -> None:
    expr = ConditionBuilder().any_of("them").build()
    assert "any" in str(expr)

    expr2 = ConditionBuilder().all_of("them").build()
    assert "all" in str(expr2)

    expr3 = ConditionBuilder().any_of("them").not_().build()
    assert "not" in str(expr3)


def test_fluent_condition_at_least_zero_validates_string_set() -> None:
    expr = FluentConditionBuilder().at_least_n_of(0, "$a").build()
    assert isinstance(expr, BooleanLiteral)
    assert expr.value is True

    with pytest.raises(ValidationError, match="At least one string identifier is required"):
        FluentConditionBuilder().at_least_n_of(0)

    with pytest.raises(ValidationError, match="Invalid string reference"):
        FluentConditionBuilder().at_least_n_of(0, "")


def test_fluent_condition_string_helpers() -> None:
    builder = FluentConditionBuilder()
    expr = builder.string_count_eq("$a", 2).build()
    assert "==" in str(expr)

    expr2 = builder.string_at_entrypoint("$a").build()
    assert "entrypoint" in str(expr2)

    expr3 = builder.string_in_first_kb("$a").build()
    assert "1024" in str(expr3)
