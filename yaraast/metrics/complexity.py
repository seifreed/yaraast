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

        self._visit_ast_value(node.quantifier)
        self.visit(node.iterable)
        self.visit(node.body)
        self._current_depth -= 1

    def visit_for_of_expression(self, node: ForOfExpression) -> None:
        """Visit for-of expression."""
        self._current_depth += 1
        self._condition_depths.append(self._current_depth)
        self.metrics.for_of_expressions += 1

        self._visit_ast_value(node.quantifier)
        self._visit_ast_value(node.string_set)
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

    def _visit_ast_value(self, value) -> None:
        if hasattr(value, "accept"):
            self.visit(value)
        elif isinstance(value, list):
            for item in value:
                self._visit_ast_value(item)

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
        self._visit_ast_value(node.subject)
        self.visit(node.range)

    def visit_dictionary_access(self, node) -> None:
        self.visit(node.object)
        self._visit_ast_value(node.key)

    def visit_defined_expression(self, node) -> None:
        self.visit(node.expression)

    def visit_string_operator_expression(self, node) -> None:
        self.visit(node.left)
        self.visit(node.right)

    def visit_with_statement(self, node) -> None:
        self._current_depth += 1
        self._condition_depths.append(self._current_depth)
        for declaration in node.declarations:
            self.visit(declaration)
        self.visit(node.body)
        self._current_depth -= 1

    def visit_with_declaration(self, node) -> None:
        self._visit_ast_value(node.value)

    def visit_array_comprehension(self, node) -> None:
        self._current_depth += 1
        self._condition_depths.append(self._current_depth)
        self._visit_ast_value(node.expression)
        self._visit_ast_value(node.iterable)
        self._visit_ast_value(node.condition)
        self._current_depth -= 1

    def visit_dict_comprehension(self, node) -> None:
        self._current_depth += 1
        self._condition_depths.append(self._current_depth)
        self._visit_ast_value(node.key_expression)
        self._visit_ast_value(node.value_expression)
        self._visit_ast_value(node.iterable)
        self._visit_ast_value(node.condition)
        self._current_depth -= 1

    def visit_tuple_expression(self, node) -> None:
        self._visit_ast_value(node.elements)

    def visit_tuple_indexing(self, node) -> None:
        self._visit_ast_value(node.tuple_expr)
        self._visit_ast_value(node.index)

    def visit_list_expression(self, node) -> None:
        self._visit_ast_value(node.elements)

    def visit_dict_expression(self, node) -> None:
        self._visit_ast_value(node.items)

    def visit_dict_item(self, node) -> None:
        self._visit_ast_value(node.key)
        self._visit_ast_value(node.value)

    def visit_slice_expression(self, node) -> None:
        self._visit_ast_value(node.target)
        self._visit_ast_value(node.start)
        self._visit_ast_value(node.stop)
        self._visit_ast_value(node.step)

    def visit_lambda_expression(self, node) -> None:
        self._visit_ast_value(node.body)

    def visit_pattern_match(self, node) -> None:
        self._current_depth += 1
        self._condition_depths.append(self._current_depth)
        self._visit_ast_value(node.value)
        self._visit_ast_value(node.cases)
        self._visit_ast_value(node.default)
        self._current_depth -= 1

    def visit_match_case(self, node) -> None:
        self._visit_ast_value(node.pattern)
        self._visit_ast_value(node.result)

    def visit_spread_operator(self, node) -> None:
        self._visit_ast_value(node.expression)
