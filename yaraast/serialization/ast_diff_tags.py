"""Tag diff helpers."""

from __future__ import annotations

from collections import Counter

__all__ = ["emit_tags_diff", "tag_payloads"]


def tag_payloads(old_rule, new_rule) -> tuple[Counter[str], Counter[str]]:
    """Return comparable tag payloads."""
    return Counter(tag.name for tag in old_rule.tags), Counter(tag.name for tag in new_rule.tags)


def _sorted_tag_values(tags) -> list[str]:
    if hasattr(tags, "elements"):
        return sorted(tags.elements())
    return sorted(tags)


def emit_tags_diff(
    base_path: str,
    result,
    diff_node,
    diff_type,
    old_tags,
    new_tags,
) -> None:
    """Record tags diff."""
    result.differences.append(
        diff_node(
            path=f"{base_path}/tags",
            diff_type=diff_type.MODIFIED,
            old_value=_sorted_tag_values(old_tags),
            new_value=_sorted_tag_values(new_tags),
            node_type="RuleTags",
        ),
    )
