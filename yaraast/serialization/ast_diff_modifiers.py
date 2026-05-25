"""Modifier diff helpers."""

from __future__ import annotations

from collections import Counter

__all__ = ["emit_modifiers_diff", "modifier_payloads"]


def modifier_payloads(old_rule, new_rule) -> tuple[Counter[str], Counter[str]]:
    """Return comparable modifier payloads."""
    return Counter(str(m) for m in old_rule.modifiers), Counter(str(m) for m in new_rule.modifiers)


def _sorted_modifier_values(modifiers) -> list[str]:
    if hasattr(modifiers, "elements"):
        return sorted(modifiers.elements())
    return sorted(modifiers)


def emit_modifiers_diff(
    base_path: str,
    result,
    diff_node,
    diff_type,
    old_mods,
    new_mods,
) -> None:
    """Record modifiers diff."""
    result.differences.append(
        diff_node(
            path=f"{base_path}/modifiers",
            diff_type=diff_type.MODIFIED,
            old_value=_sorted_modifier_values(old_mods),
            new_value=_sorted_modifier_values(new_mods),
            node_type="RuleModifiers",
        ),
    )
