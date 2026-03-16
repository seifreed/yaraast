"""Outcome section validation mixin for YARA-L."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from yaraast.yaral.ast_nodes import (
        AggregationFunction,
        OutcomeAssignment,
        OutcomeExpression,
        OutcomeSection,
    )


class OutcomeValidationMixin:
    """Validate outcome assignments and aggregations."""

    def _validate_outcome_section(self, node: OutcomeSection) -> None:
        """Validate outcome section."""
        assignments = node.assignments if hasattr(node, "assignments") else []

        if hasattr(node, "variables"):
            for var_name in node.variables:
                self._register_outcome_variable(var_name)

        for assignment in assignments:
            self._register_outcome_variable(assignment.variable)

    def _register_outcome_variable(self, var_name: str) -> None:
        if var_name in self.defined_outcome_vars:
            self._add_error(
                "outcome",
                f"Duplicate outcome variable: {var_name}",
                "Use unique outcome variable names",
            )
        self.defined_outcome_vars.add(var_name)

        reserved = ["risk_score", "severity", "confidence", "priority"]
        if var_name not in reserved and not var_name.startswith("$"):
            self._add_error(
                "outcome",
                f"Outcome variable '{var_name}' must start with $ or use a reserved name",
                f"Reserved names: {', '.join(reserved)}",
            )

    def visit_yaral_outcome_section(self, node: OutcomeSection) -> None:
        for assignment in node.assignments:
            self.visit(assignment)

    def visit_yaral_outcome_assignment(self, node: OutcomeAssignment) -> None:
        self.defined_outcome_vars.add(node.variable)
        if hasattr(node.expression, "accept"):
            self.visit(node.expression)

    def visit_yaral_outcome_expression(self, node: OutcomeExpression) -> None:
        return

    def visit_yaral_aggregation_function(self, node: AggregationFunction) -> None:
        if node.function not in self.VALID_AGGREGATIONS:
            self._add_warning(
                "outcome",
                f"Unknown aggregation function: {node.function}",
                f"Valid functions: {', '.join(self.VALID_AGGREGATIONS)}",
            )
