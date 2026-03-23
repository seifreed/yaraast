"""Meta diff helpers."""

from __future__ import annotations

__all__ = ["emit_meta_diff", "meta_payloads"]


def _meta_to_dict(meta) -> dict:
    """Convert meta (list[MetaEntry]) to a comparable dict."""
    return {getattr(m, "key", str(i)): getattr(m, "value", m) for i, m in enumerate(meta)}


def meta_payloads(old_rule, new_rule) -> tuple[dict, dict]:
    """Return comparable meta payloads."""
    return _meta_to_dict(old_rule.meta), _meta_to_dict(new_rule.meta)


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
