"""Helper mixin for YARA-L optimizer."""

from __future__ import annotations

from typing import Any

from yaraast.yaral.ast_nodes import EventAssignment, UDMFieldPath


class YaraLOptimizerHelpersMixin:
    """Shared helper methods for optimizer."""

    def _field_path_to_string(self, field_path: UDMFieldPath) -> str:
        if hasattr(field_path, "parts"):
            return ".".join(field_path.parts)
        return str(field_path)

    def _should_index_field(self, assignment: EventAssignment) -> bool:
        if assignment.operator == "=":
            return True

        field_str = self._field_path_to_string(assignment.field_path)
        field_parts = field_str.split(".")
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

    def _are_contradictory(self, assign1: EventAssignment, assign2: EventAssignment) -> bool:
        if assign1.operator == "=" and assign2.operator == "!=" and assign1.value == assign2.value:
            return True
        if assign1.operator == "!=" and assign2.operator == "=" and assign1.value == assign2.value:
            return True

        if (
            assign1.operator == ">"
            and assign2.operator == "<"
            and isinstance(assign1.value, int | float)
            and isinstance(assign2.value, int | float)
        ):
            return assign1.value >= assign2.value

        return False

    def _are_redundant(self, assign1: EventAssignment, assign2: EventAssignment) -> bool:
        if assign1.operator == assign2.operator and assign1.value == assign2.value:
            return True

        if (
            assign1.operator == ">="
            and assign2.operator == ">"
            and isinstance(assign1.value, int | float)
            and isinstance(assign2.value, int | float)
        ):
            return assign1.value >= assign2.value

        return False

    def _is_more_restrictive(self, assign1: EventAssignment, assign2: EventAssignment) -> bool:
        if assign1.operator == "=" and assign2.operator != "=":
            return True

        if (
            assign1.operator in [">", ">="]
            and assign2.operator in [">", ">="]
            and isinstance(assign1.value, int | float)
            and isinstance(assign2.value, int | float)
        ):
            return assign1.value > assign2.value

        return False

    def _is_match_var_used(self, var_name: str) -> bool:
        return True

    def _is_outcome_var_used(self, var_name: str) -> bool:
        return var_name in ["risk_score", "severity", "confidence"]

    def _is_always_true(self, expr: Any) -> bool:
        return bool(hasattr(expr, "value") and expr.value is True)

    def _is_always_false(self, expr: Any) -> bool:
        return bool(hasattr(expr, "value") and expr.value is False)

    def _are_equal_conditions(self, expr1: Any, expr2: Any) -> bool:
        return str(expr1) == str(expr2)
