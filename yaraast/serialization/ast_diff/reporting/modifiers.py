"""Reporting helpers for modifier diffs."""

from __future__ import annotations


def emit_modifiers_diff(
    base_path: str,
    result,
    diff_node,
    diff_type,
    old_mods: set,
    new_mods: set,
) -> None:
    """Record modifiers diff."""
    result.differences.append(
        diff_node(
            path=f"{base_path}/modifiers",
            diff_type=diff_type.MODIFIED,
            old_value=list(old_mods),
            new_value=list(new_mods),
            node_type="RuleModifiers",
        ),
    )
