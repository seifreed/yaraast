"""Real tests for fluent condition builder helpers (no mocks)."""

from __future__ import annotations

from yaraast.builder.condition_builder import ConditionBuilder


def test_fluent_condition_quantifiers() -> None:
    expr = ConditionBuilder().any_of("them").build()
    assert "any" in str(expr)

    expr2 = ConditionBuilder().all_of("them").build()
    assert "all" in str(expr2)

    expr3 = ConditionBuilder().any_of("them").not_().build()
    assert "not" in str(expr3)


def test_fluent_condition_string_helpers() -> None:
    expr = ConditionBuilder().string_count("$a").eq(2).build()
    assert "==" in str(expr)

    expr2 = ConditionBuilder().entrypoint().build()
    assert "entrypoint" in str(expr2)

    expr3 = ConditionBuilder().string("$a").at(0).build()
    assert "0" in str(expr3)
