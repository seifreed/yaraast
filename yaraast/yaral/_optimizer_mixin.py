"""Shared type contract for YARA-L optimizer mixins."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any


class OptimizerMixinBase:
    """Declare state and methods supplied by the complete optimizer."""

    if TYPE_CHECKING:
        stats: Any
        indexed_fields: set[str]

        def visit(self, node: Any) -> Any: ...

        def _field_path_to_string(self, field_path: Any) -> str: ...

        def _field_path_parts(self, field_path: Any) -> list[str]: ...

        def _should_index_field(self, assignment: Any) -> bool: ...

        def _is_outcome_var_used(self, name: str) -> bool: ...

        def _are_equal_conditions(self, first: Any, second: Any) -> bool: ...
