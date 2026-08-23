"""Condition diff helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast.ast.rules import Rule
from yaraast.serialization.ast_diff_hasher import AstHasher

if TYPE_CHECKING:
    from yaraast.serialization.ast_diff import DiffNode, DiffResult, DiffType

__all__ = ["condition_hashes", "emit_condition_diff"]


def condition_hashes(old_rule: Rule, new_rule: Rule, hasher: AstHasher) -> tuple[str, str]:
    """Hash conditions for comparison."""
    old_condition_hash = hasher.visit(old_rule.condition) if old_rule.condition is not None else ""
    new_condition_hash = hasher.visit(new_rule.condition) if new_rule.condition is not None else ""
    return old_condition_hash, new_condition_hash


def emit_condition_diff(
    base_path: str,
    result: DiffResult,
    diff_node: type[DiffNode],
    diff_type: type[DiffType],
    old_condition_hash: str,
    new_condition_hash: str,
) -> None:
    """Record condition diff."""
    result.differences.append(
        diff_node(
            path=f"{base_path}/condition",
            diff_type=diff_type.MODIFIED,
            old_value=old_condition_hash,
            new_value=new_condition_hash,
            node_type="RuleCondition",
        ),
    )
