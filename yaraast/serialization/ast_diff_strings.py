"""String diff helpers."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from yaraast.ast.strings import StringDefinition

if TYPE_CHECKING:
    from yaraast.serialization.ast_diff import DiffNode, DiffResult, DiffType

__all__ = [
    "emit_string_added",
    "emit_string_modified",
    "emit_string_removed",
    "string_maps",
]


def string_maps(
    old_strings: Sequence[StringDefinition], new_strings: Sequence[StringDefinition]
) -> tuple[dict[str, list[StringDefinition]], dict[str, list[StringDefinition]]]:
    """Map string identifiers to all matching definitions."""
    return _strings_by_identifier(old_strings), _strings_by_identifier(new_strings)


def _strings_by_identifier(
    strings: Sequence[StringDefinition],
) -> dict[str, list[StringDefinition]]:
    grouped: dict[str, list[StringDefinition]] = {}
    for string_def in strings:
        grouped.setdefault(string_def.identifier, []).append(string_def)
    return grouped


def emit_string_added(
    base_path: str,
    result: DiffResult,
    diff_node: type[DiffNode],
    diff_type: type[DiffType],
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
    result: DiffResult,
    diff_node: type[DiffNode],
    diff_type: type[DiffType],
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
    result: DiffResult,
    diff_node: type[DiffNode],
    diff_type: type[DiffType],
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
