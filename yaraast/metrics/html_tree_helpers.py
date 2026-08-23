"""Helpers for HTML tree generation."""

from __future__ import annotations

from typing import Any

from yaraast.ast.rules import Rule


def rule_details(rule: Rule) -> str:
    return f"{len(rule.strings)} strings, {len(rule.meta)} meta"


def rule_children(generator: Any, rule: Rule) -> list[dict[str, Any]]:
    children: list[dict[str, Any]] = []

    if rule.modifiers:
        generator._append_section(
            children,
            generator._simple_node(
                "Modifiers",
                "modifiers",
                value=", ".join(str(m) for m in rule.modifiers),
            ),
        )

    generator._append_section(children, generator._children_section("Tags", "tags", rule.tags))
    generator._append_section(children, generator._meta_section(rule.meta))

    generator._append_section(
        children,
        generator._children_section("Strings", "strings-section", rule.strings),
    )
    generator._append_section(children, generator._condition_section(rule.condition))

    return children
