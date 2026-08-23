"""Shared type contract for YARA-L validator mixins."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar


class ValidatorMixinBase:
    """Declare state and methods supplied by the complete validator."""

    if TYPE_CHECKING:
        VALID_UDM_FIELDS: ClassVar[dict[str, list[str]]]
        VALID_AGGREGATIONS: ClassVar[list[str]]
        VALID_TIME_UNITS: ClassVar[list[str]]
        defined_events: set[str]
        used_events: set[str]
        defined_match_vars: set[str]
        used_match_vars: set[str]
        defined_outcome_vars: set[str]
        current_rule: str | None

        def visit(self, node: Any) -> Any: ...

        def _add_error(self, section: str, message: str, suggestion: str = "") -> None: ...

        def _add_warning(self, section: str, message: str, suggestion: str = "") -> None: ...

        def _validate_meta_section(self, node: Any) -> None: ...

        def _validate_match_section(self, node: Any) -> None: ...

        def _validate_condition_section(self, node: Any) -> None: ...

        def _validate_outcome_section(self, node: Any) -> None: ...

        def _validate_options_section(self, node: Any) -> None: ...
