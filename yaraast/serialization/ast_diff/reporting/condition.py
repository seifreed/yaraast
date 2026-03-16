"""Reporting helpers for condition diffs."""

from __future__ import annotations


def condition_hashes(old_rule, new_rule, hasher) -> tuple[str, str]:
    """Hash conditions for comparison."""
    old_condition_hash = hasher.visit(old_rule.condition) if old_rule.condition else ""
    new_condition_hash = hasher.visit(new_rule.condition) if new_rule.condition else ""
    return old_condition_hash, new_condition_hash


def emit_condition_diff(
    base_path: str,
    result,
    diff_node,
    diff_type,
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
