"""Modifier diff helpers."""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

from yaraast.ast.rules import Rule

if TYPE_CHECKING:
    from yaraast.serialization.ast_diff import DiffNode, DiffResult, DiffType

__all__ = ["emit_modifiers_diff", "modifier_payloads"]


def modifier_payloads(old_rule: Rule, new_rule: Rule) -> tuple[Counter[str], Counter[str]]:
    """Return comparable modifier payloads."""
    return Counter(str(m) for m in old_rule.modifiers), Counter(str(m) for m in new_rule.modifiers)


def _sorted_modifier_values(modifiers: Counter[str]) -> list[str]:
    return sorted(modifiers.elements())


def emit_modifiers_diff(
    base_path: str,
    result: DiffResult,
    diff_node: type[DiffNode],
    diff_type: type[DiffType],
    old_mods: Counter[str],
    new_mods: Counter[str],
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
