"""Reporting helpers for string diffs."""

from __future__ import annotations


def emit_string_added(
    base_path: str,
    result,
    diff_node,
    diff_type,
    identifier: str,
) -> None:
    """Record added string."""
    result.differences.append(
        diff_node(
            path=f"{base_path}/{identifier}",
            diff_type=diff_type.ADDED,
            new_value=identifier,
            node_type="StringDefinition",
        ),
    )


def emit_string_removed(
    base_path: str,
    result,
    diff_node,
    diff_type,
    identifier: str,
) -> None:
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
