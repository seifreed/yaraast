"""Helpers for HTML tree generation."""

from __future__ import annotations


def rule_details(rule) -> str:
    return f"{len(rule.strings)} strings, {len(rule.meta)} meta"


def rule_children(generator, rule) -> list:
    children: list = []

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
