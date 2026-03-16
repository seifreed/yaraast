"""Helpers for fluent rule builder."""

from __future__ import annotations

from yaraast.builder.fluent_condition_builder import FluentConditionBuilder


def apply_last_string_modifier(string_builders, method: str, *args) -> None:
    if not string_builders:
        return
    getattr(string_builders[-1], method)(*args)


def combine_condition(existing, new_builder: FluentConditionBuilder):
    if existing:
        return FluentConditionBuilder(existing).and_(new_builder)
    return new_builder
