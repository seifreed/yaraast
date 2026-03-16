"""Condition optimization mixin for YARA-L optimizer."""

from __future__ import annotations

from typing import Any

from yaraast.yaral.ast_nodes import (
    BinaryCondition,
    ConditionExpression,
    ConditionSection,
    EventExistsCondition,
    UnaryCondition,
)


class YaraLOptimizerConditionsMixin:
    """Condition optimization methods."""

    def _optimize_condition_section(self, condition: ConditionSection) -> ConditionSection:
        if not condition or not condition.expression:
            return condition

        optimized_expr = self._optimize_condition_expression(condition.expression)
        return ConditionSection(expression=optimized_expr)

    def _optimize_condition_expression(self, expr: ConditionExpression) -> ConditionExpression:
        if isinstance(expr, BinaryCondition):
            return self._optimize_binary_condition(expr)

        if (
            hasattr(expr, "operator")
            and expr.operator == "not"
            and hasattr(expr, "operand")
            and hasattr(expr.operand, "operator")
            and expr.operand.operator == "not"
        ):
            self.stats.conditions_simplified += 1
            return expr.operand.operand

        return expr

    def _optimize_binary_condition(self, cond: BinaryCondition) -> BinaryCondition:
        optimized_left = self._optimize_condition_expression(cond.left) if cond.left else cond.left
        optimized_right = (
            self._optimize_condition_expression(cond.right) if cond.right else cond.right
        )

        if cond.operator == "and":
            return self._optimize_and_condition(optimized_left, optimized_right)
        if cond.operator == "or":
            return self._optimize_or_condition(optimized_left, optimized_right)

        return BinaryCondition(
            left=optimized_left,
            operator=cond.operator,
            right=optimized_right,
        )

    def _optimize_and_condition(self, left: Any, right: Any) -> Any:
        if self._is_always_true(right):
            self.stats.conditions_simplified += 1
            return left
        if self._is_always_true(left):
            self.stats.conditions_simplified += 1
            return right

        if self._is_always_false(right) or self._is_always_false(left):
            self.stats.conditions_simplified += 1
            return self._create_false_condition()

        if self._are_equal_conditions(left, right):
            self.stats.conditions_simplified += 1
            return left

        return BinaryCondition(left=left, operator="and", right=right)

    def _optimize_or_condition(self, left: Any, right: Any) -> Any:
        if self._is_always_false(right):
            self.stats.conditions_simplified += 1
            return left
        if self._is_always_false(left):
            self.stats.conditions_simplified += 1
            return right

        if self._is_always_true(right) or self._is_always_true(left):
            self.stats.conditions_simplified += 1
            return self._create_true_condition()

        if self._are_equal_conditions(left, right):
            self.stats.conditions_simplified += 1
            return left

        return BinaryCondition(left=left, operator="or", right=right)

    def _create_true_condition(self) -> ConditionExpression:
        return EventExistsCondition(event="true")

    def _create_false_condition(self) -> ConditionExpression:
        return UnaryCondition(operator="not", operand=EventExistsCondition(event="true"))
