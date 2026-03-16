"""Reporting helpers for meta diffs."""

from __future__ import annotations


def emit_meta_diff(
    base_path: str,
    result,
    diff_node,
    diff_type,
    old_meta: dict,
    new_meta: dict,
) -> None:
    """Record meta diff."""
    result.differences.append(
        diff_node(
            path=f"{base_path}/meta",
            diff_type=diff_type.MODIFIED,
            old_value=old_meta,
            new_value=new_meta,
            node_type="RuleMeta",
        ),
    )
