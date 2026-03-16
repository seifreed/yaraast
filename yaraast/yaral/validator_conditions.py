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
        UnaryCondition,
        VariableComparisonCondition,
    )


class ConditionValidationMixin:
    """Validate condition expressions and references."""

    def _validate_condition_section(self, node: ConditionSection) -> None:
        """Validate condition section."""
        if not hasattr(node, "expression") or not node.expression:
            self._add_error(
                "condition",
                "Condition section cannot be empty",
                "Add condition expression",
            )

    def visit_yaral_condition_section(self, node: ConditionSection) -> None:
        self.visit(node.expression)

    def visit_yaral_condition_expression(self, node: ConditionExpression) -> None:
        return

    def visit_yaral_binary_condition(self, node: BinaryCondition) -> None:
        self.visit(node.left)
        self.visit(node.right)

    def visit_yaral_unary_condition(self, node: UnaryCondition) -> None:
        self.visit(node.operand)

    def visit_yaral_event_count_condition(self, node: EventCountCondition) -> None:
        self.used_events.add(node.event)

    def visit_yaral_event_exists_condition(self, node: EventExistsCondition) -> None:
        self.used_events.add(node.event)

    def visit_yaral_variable_comparison_condition(self, node: VariableComparisonCondition) -> None:
        return

    def visit_yaral_join_condition(self, node: JoinCondition) -> None:
        return

    def visit_yaral_conditional_expression(self, node: ConditionalExpression) -> None:
        if hasattr(node.condition, "accept"):
            self.visit(node.condition)

    def visit_yaral_arithmetic_expression(self, node) -> None:
        if hasattr(node.left, "accept"):
            self.visit(node.left)
        if hasattr(node.right, "accept"):
            self.visit(node.right)
