"""Condition section validation mixin for YARA-L."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from yaraast.yaral.ast_nodes import (
        BinaryCondition,
        ConditionalExpression,
        ConditionExpression,
        ConditionSection,
        EventCountCondition,
        EventExistsCondition,
        JoinCondition,
        NOfCondition,
        NullCheckCondition,
        UnaryCondition,
        VariableComparisonCondition,
    )


class ConditionValidationMixin:
    """Validate condition expressions and references."""

    def _validate_condition_section(self, node: ConditionSection) -> None:
        """Validate condition section."""
        if not hasattr(node, "expression") or node.expression is None:
            self._add_error(
                "condition",
                "Condition section cannot be empty",
                "Add condition expression",
            )

    def visit_yaral_condition_section(self, node: ConditionSection) -> None:
        if node.expression is None:
            self._validate_condition_section(node)
            return
        self.visit(node.expression)

    def visit_yaral_condition_expression(self, node: ConditionExpression) -> None:
        return

    def visit_yaral_binary_condition(self, node: BinaryCondition) -> None:
        self.visit(node.left)
        self.visit(node.right)

    def visit_yaral_unary_condition(self, node: UnaryCondition) -> None:
        if node.operand is not None:
            self.visit(node.operand)

    def visit_yaral_event_count_condition(self, node: EventCountCondition) -> None:
        self.used_events.add(node.event.lstrip("$"))

    def visit_yaral_event_exists_condition(self, node: EventExistsCondition) -> None:
        self.used_events.add(node.event.lstrip("$"))

    def visit_yaral_variable_comparison_condition(self, node: VariableComparisonCondition) -> None:
        return

    def visit_yaral_join_condition(self, node: JoinCondition) -> None:
        return

    def visit_yaral_n_of_condition(self, node: NOfCondition) -> None:
        for event in node.events:
            self.used_events.add(event.lstrip("$"))

    def visit_yaral_null_check_condition(self, node: NullCheckCondition) -> None:
        field = node.field
        if hasattr(field, "event") and field.event is not None:
            self.used_events.add(field.event.name.lstrip("$"))
            self.visit(field)
            return
        if isinstance(field, str) and field.startswith("$"):
            event_name, _separator, _field_path = field.partition(".")
            self.used_events.add(event_name.lstrip("$"))

    def visit_yaral_conditional_expression(self, node: ConditionalExpression) -> None:
        if hasattr(node.condition, "accept"):
            self.visit(node.condition)

    def visit_yaral_arithmetic_expression(self, node) -> None:
        if hasattr(node.left, "accept"):
            self.visit(node.left)
        if hasattr(node.right, "accept"):
            self.visit(node.right)
