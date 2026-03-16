"""Real tests for fluent condition builder helpers (no mocks)."""

from __future__ import annotations

from yaraast.builder.fluent_condition_builder import FluentConditionBuilder


def test_fluent_condition_quantifiers() -> None:
    builder = FluentConditionBuilder()
    expr = builder.any_of_them().build()
    assert "any" in str(expr)

    expr2 = builder.all_of_them().build()
    assert "all" in str(expr2)

    expr3 = builder.not_them().build()
    assert "not" in str(expr3)


def test_fluent_condition_string_helpers() -> None:
    builder = FluentConditionBuilder()
    expr = builder.string_count_eq("$a", 2).build()
    assert "==" in str(expr)

    expr2 = builder.string_at_entrypoint("$a").build()
    assert "entrypoint" in str(expr2)

    expr3 = builder.string_in_first_kb("$a").build()
    assert "1024" in str(expr3)
