"""Modifier diff helpers."""

from __future__ import annotations

__all__ = ["emit_modifiers_diff", "modifier_payloads"]


def modifier_payloads(old_rule, new_rule) -> tuple[set, set]:
    """Return comparable modifier payloads."""
    return {str(m) for m in old_rule.modifiers}, {str(m) for m in new_rule.modifiers}


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
