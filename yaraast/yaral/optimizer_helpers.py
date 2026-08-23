"""Helper mixin for YARA-L optimizer."""

from __future__ import annotations

from typing import Any

from yaraast.yaral._optimizer_mixin import OptimizerMixinBase
from yaraast.yaral.ast_nodes import EventAssignment, UDMFieldPath


class YaraLOptimizerHelpersMixin(OptimizerMixinBase):
    """Shared helper methods for optimizer."""

    def _field_path_to_string(self, field_path: UDMFieldPath | str) -> str:
        if isinstance(field_path, UDMFieldPath):
            return field_path.path
        return str(field_path)

    def _field_path_parts(self, field_path: UDMFieldPath | str) -> list[str]:
        if isinstance(field_path, UDMFieldPath):
            raw_parts = field_path.parts
        else:
            raw_parts = str(field_path).split(".")

        parts = []
        for part in raw_parts:
            if part.startswith("["):
                continue
            base_part = part.split("[", 1)[0]
            if base_part:
                parts.append(base_part)
        return parts

    def _should_index_field(self, assignment: EventAssignment) -> bool:
        if assignment.operator == "=":
            return True

        field_str = self._field_path_to_string(assignment.field_path)
        field_parts = self._field_path_parts(assignment.field_path)
        if "timestamp" in field_str and assignment.operator in [">", "<", ">=", "<="]:
            return True

        high_cardinality_fields = [
            "hostname",
            "ip",
            "user_id",
            "session_id",
            "event_id",
        ]
        return any(field in field_parts for field in high_cardinality_fields)

    def _is_outcome_var_used(self, var_name: str) -> bool:
        return var_name in ["risk_score", "severity", "confidence"]

    def _are_equal_conditions(self, expr1: Any, expr2: Any) -> bool:
        return str(expr1) == str(expr2)
