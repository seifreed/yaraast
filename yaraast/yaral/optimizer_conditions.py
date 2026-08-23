"""Condition optimization mixin for YARA-L optimizer."""

from __future__ import annotations

from yaraast.yaral._optimizer_mixin import OptimizerMixinBase
from yaraast.yaral.ast_nodes import (
    BinaryCondition,
    ConditionExpression,
    ConditionSection,
    UnaryCondition,
)


class YaraLOptimizerConditionsMixin(OptimizerMixinBase):
    """Condition optimization methods."""

    def _optimize_condition_section(
        self, condition: ConditionSection | None
    ) -> ConditionSection | None:
        if condition is None or condition.expression is None:
            return condition

        optimized_expr = self._optimize_condition_expression(condition.expression)
        return ConditionSection(expression=optimized_expr)

    def _optimize_condition_expression(self, expr: ConditionExpression) -> ConditionExpression:
        if isinstance(expr, BinaryCondition):
            return self._optimize_binary_condition(expr)

        if isinstance(expr, UnaryCondition) and isinstance(expr.operand, UnaryCondition):
            self.stats.conditions_simplified += 1
            return expr.operand.operand if expr.operand.operand is not None else expr

        return expr

    def _optimize_binary_condition(self, cond: BinaryCondition) -> ConditionExpression:
        optimized_left = self._optimize_condition_expression(cond.left)
        optimized_right = self._optimize_condition_expression(cond.right)

        if cond.operator == "and":
            return self._optimize_and_condition(optimized_left, optimized_right)
        if cond.operator == "or":
            return self._optimize_or_condition(optimized_left, optimized_right)

        return BinaryCondition(
            left=optimized_left,
            operator=cond.operator,
            right=optimized_right,
        )

    def _optimize_and_condition(
        self, left: ConditionExpression, right: ConditionExpression
    ) -> ConditionExpression:
        if self._are_equal_conditions(left, right):
            self.stats.conditions_simplified += 1
            return left

        return BinaryCondition(left=left, operator="and", right=right)

    def _optimize_or_condition(
        self, left: ConditionExpression, right: ConditionExpression
    ) -> ConditionExpression:
        if self._are_equal_conditions(left, right):
            self.stats.conditions_simplified += 1
            return left

        return BinaryCondition(left=left, operator="or", right=right)
