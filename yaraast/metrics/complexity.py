"""AST-based complexity analysis for YARA rules."""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast.ast.conditions import ForExpression, ForOfExpression, OfExpression
from yaraast.metrics._visitor_base import MetricsVisitorBase
from yaraast.metrics.complexity_analysis_helpers import analyze_rule, calculate_derived_metrics
from yaraast.metrics.complexity_model import ComplexityMetrics

if TYPE_CHECKING:

    from yaraast.ast.base import YaraFile
    from yaraast.ast.expressions import BinaryExpression, UnaryExpression
    from yaraast.ast.rules import Rule


class ComplexityAnalyzer(MetricsVisitorBase):
    """Analyzes AST complexity metrics using heuristic thresholds."""

    def __init__(self) -> None:
        super().__init__(default=None)
        self.metrics = ComplexityMetrics()
        self._current_rule: Rule | None = None
        self._condition_depths: list[int] = []
        self._current_depth = 0
        self._string_usage: dict[str, set[str]] = {}
        self._rule_strings: dict[str, set[str]] = {}

    def analyze(self, ast: YaraFile) -> ComplexityMetrics:
        """Analyze AST and return complexity metrics."""
        self.metrics = ComplexityMetrics()
        self._condition_depths.clear()
        self._current_depth = 0
        self._string_usage = {}
        self._rule_strings = {}

        # File-level metrics
        self.metrics.total_rules = len(ast.rules)
        self.metrics.total_imports = len(ast.imports)
        self.metrics.total_includes = len(ast.includes)

        # Module usage from imports
        for imp in ast.imports:
            self.metrics.module_usage[imp.module] = self.metrics.module_usage.get(imp.module, 0) + 1

        # Analyze each rule
        for rule in ast.rules:
            analyze_rule(self, rule)

        # Post-analysis calculations
        calculate_derived_metrics(self)

        return self.metrics

    # Visitor methods
    def visit_binary_expression(self, node: BinaryExpression) -> None:
        """Visit binary expression and track complexity."""
        self._current_depth += 1
        self._condition_depths.append(self._current_depth)
        self.metrics.total_binary_ops += 1

        self.visit(node.left)
        self.visit(node.right)
        self._current_depth -= 1

    def visit_unary_expression(self, node: UnaryExpression) -> None:
        """Visit unary expression."""
        self.metrics.total_unary_ops += 1
        self.visit(node.operand)

    def visit_for_expression(self, node: ForExpression) -> None:
        """Visit for expression."""
        self._current_depth += 1
        self._condition_depths.append(self._current_depth)
        self.metrics.for_expressions += 1

        self.visit(node.iterable)
        self.visit(node.body)
        self._current_depth -= 1

    def visit_for_of_expression(self, node: ForOfExpression) -> None:
        """Visit for-of expression."""
        self._current_depth += 1
        self._condition_depths.append(self._current_depth)
        self.metrics.for_of_expressions += 1

        self.visit(node.string_set)
        if node.condition:
            self.visit(node.condition)
        self._current_depth -= 1

    def visit_of_expression(self, node: OfExpression) -> None:
        """Visit of expression."""
        self.metrics.of_expressions += 1

        if hasattr(node.quantifier, "accept"):
            self.visit(node.quantifier)
        if hasattr(node.string_set, "accept"):
            self.visit(node.string_set)

    def visit_string_identifier(self, node) -> None:
        """Track string usage."""
        if self._current_rule:
            self._string_usage.setdefault(self._current_rule.name, set()).add(node.name)

    def visit_parentheses_expression(self, node) -> None:
        self.visit(node.expression)

    def visit_set_expression(self, node) -> None:
        for elem in node.elements:
            self.visit(elem)

    def visit_range_expression(self, node) -> None:
        self.visit(node.low)
        self.visit(node.high)

    def visit_function_call(self, node) -> None:
        for arg in node.arguments:
            self.visit(arg)

    def visit_array_access(self, node) -> None:
        self.visit(node.array)
        self.visit(node.index)

    def visit_member_access(self, node) -> None:
        self.visit(node.object)

    def visit_at_expression(self, node) -> None:
        self.visit(node.offset)

    def visit_in_expression(self, node) -> None:
        self.visit(node.range)

    def visit_dictionary_access(self, node) -> None:
        self.visit(node.object)

    def visit_defined_expression(self, node) -> None:
        self.visit(node.expression)

    def visit_string_operator_expression(self, node) -> None:
        self.visit(node.left)
        self.visit(node.right)
