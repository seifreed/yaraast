"""Real tests for fluent condition builder helpers (no mocks)."""

from __future__ import annotations

from yaraast.builder.condition_builder import ConditionBuilder
from yaraast.builder.fluent_condition_builder import FluentConditionBuilder


def test_fluent_condition_quantifiers() -> None:
    expr = ConditionBuilder().any_of("them").build()
    assert "any" in str(expr)

    expr2 = ConditionBuilder().all_of("them").build()
    assert "all" in str(expr2)

    expr3 = ConditionBuilder().any_of("them").not_().build()
    assert "not" in str(expr3)


def test_fluent_condition_string_helpers() -> None:
    builder = FluentConditionBuilder()
    expr = builder.string_count_eq("$a", 2).build()
    assert "==" in str(expr)

    expr2 = ConditionBuilder().entrypoint().build()
    assert "entrypoint" in str(expr2)

    expr3 = builder.string_at_offset("$a", 0).build()
    assert "0" in str(expr3)
