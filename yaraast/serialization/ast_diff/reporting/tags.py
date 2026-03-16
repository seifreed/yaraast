"""Reporting helpers for tag diffs."""

from __future__ import annotations


def emit_tags_diff(
    base_path: str,
    result,
    diff_node,
    diff_type,
    old_tags: set,
    new_tags: set,
) -> None:
    """Record tags diff."""
    result.differences.append(
        diff_node(
            path=f"{base_path}/tags",
            diff_type=diff_type.MODIFIED,
            old_value=list(old_tags),
            new_value=list(new_tags),
            node_type="RuleTags",
        ),
    )
