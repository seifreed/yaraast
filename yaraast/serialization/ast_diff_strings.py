"""String diff helpers."""

from __future__ import annotations

__all__ = [
    "emit_string_added",
    "emit_string_modified",
    "emit_string_removed",
    "string_maps",
]


def string_maps(old_strings, new_strings) -> tuple[dict, dict]:
    """Map string identifiers for comparison."""
    return {s.identifier: s for s in old_strings}, {s.identifier: s for s in new_strings}


def emit_string_added(base_path: str, result, diff_node, diff_type, identifier: str) -> None:
    """Record added string."""
    result.differences.append(
        diff_node(
            path=f"{base_path}/{identifier}",
            diff_type=diff_type.ADDED,
            new_value=identifier,
            node_type="StringDefinition",
        ),
    )


def emit_string_removed(base_path: str, result, diff_node, diff_type, identifier: str) -> None:
    """Record removed string."""
    result.differences.append(
        diff_node(
            path=f"{base_path}/{identifier}",
            diff_type=diff_type.REMOVED,
            old_value=identifier,
            node_type="StringDefinition",
        ),
    )


def emit_string_modified(
    base_path: str,
    result,
    diff_node,
    diff_type,
    identifier: str,
    old_hash: str,
    new_hash: str,
) -> None:
    """Record modified string."""
    result.differences.append(
        diff_node(
            path=f"{base_path}/{identifier}",
            diff_type=diff_type.MODIFIED,
            old_value=old_hash,
            new_value=new_hash,
            node_type="StringDefinition",
        ),
    )
