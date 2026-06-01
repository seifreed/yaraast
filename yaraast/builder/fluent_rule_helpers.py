"""Helpers for fluent rule builder."""

from __future__ import annotations

from yaraast.ast.expressions import Expression
from yaraast.builder.condition_builder import ConditionBuilder
from yaraast.builder.fluent_condition_builder import FluentConditionBuilder
from yaraast.builder.fluent_string_builder import FluentStringBuilder


def apply_last_string_modifier(
    string_builders: list[FluentStringBuilder],
    method: str,
    *args: object,
) -> None:
    if not string_builders:
        return
    getattr(string_builders[-1], method)(*args)


def combine_condition(
    existing: Expression | None,
    new_builder: ConditionBuilder,
) -> ConditionBuilder:
    if existing is not None:
        return FluentConditionBuilder(existing).and_(new_builder)
    return new_builder
