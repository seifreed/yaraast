"""Tag diff helpers."""

from __future__ import annotations

__all__ = ["emit_tags_diff", "tag_payloads"]


def tag_payloads(old_rule, new_rule) -> tuple[set, set]:
    """Return comparable tag payloads."""
    return {tag.name for tag in old_rule.tags}, {tag.name for tag in new_rule.tags}


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
