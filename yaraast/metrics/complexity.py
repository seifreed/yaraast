"""AST-based complexity analysis for YARA rules."""

from __future__ import annotations

from fnmatch import fnmatchcase
from typing import TYPE_CHECKING

from yaraast.ast.conditions import ForExpression, ForOfExpression, OfExpression
from yaraast.ast.expressions import (
    Identifier,
    ParenthesesExpression,
    SetExpression,
    StringIdentifier,
    StringLiteral,
    StringWildcard,
)
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
        self._local_scopes: list[set[str]] = []

    def analyze(self, ast: YaraFile) -> ComplexityMetrics:
        """Analyze AST and return complexity metrics."""
        self.metrics = ComplexityMetrics()
        self._current_rule = None
        self._condition_depths.clear()
        self._current_depth = 0
        self._string_usage = {}
        self._rule_strings = {}
        self._local_scopes.clear()

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
        self._push_local_scope(node.variable)
        try:
            self.visit(node.body)
        finally:
            self._pop_local_scope()
            self._current_depth -= 1

    def visit_for_of_expression(self, node: ForOfExpression) -> None:
        """Visit for-of expression."""
        self._current_depth += 1
        self._condition_depths.append(self._current_depth)
        self.metrics.for_of_expressions += 1

        self._visit_ast_value(node.quantifier)
        self._visit_string_set_value(node.string_set)
        if node.condition:
            self.visit(node.condition)
        self._current_depth -= 1

    def visit_of_expression(self, node: OfExpression) -> None:
        """Visit of expression."""
        self.metrics.of_expressions += 1

        self._visit_ast_value(node.quantifier)
        self._visit_string_set_value(node.string_set)

    def _visit_ast_value(self, value) -> None:
        if hasattr(value, "accept"):
            self.visit(value)
        elif isinstance(value, list | tuple | set | frozenset):
            for item in value:
                self._visit_ast_value(item)

    def _normalize_string_id(self, string_id: str) -> str:
        return string_id if string_id.startswith("$") else f"${string_id.lstrip('#@!')}"

    def _mark_string_usage(self, string_id: str) -> None:
        if self._current_rule:
            normalized = self._normalize_string_id(string_id)
            self._string_usage.setdefault(self._current_rule.name, set()).add(normalized)

    def _mark_string_identifier_usage(self, string_id: str) -> None:
        if self._is_local(string_id):
            return
        self._mark_string_usage(string_id)

    def _mark_all_current_rule_strings(self) -> None:
        if not self._current_rule:
            return
        for string_def in self._current_rule.strings:
            self._mark_string_usage(string_def.identifier)

    def _mark_wildcard_usage(self, pattern: str) -> None:
        if not self._current_rule:
            self._mark_string_usage(pattern)
            return

        if pattern == "$*":
            self._mark_all_current_rule_strings()
            return

        normalized_pattern = self._normalize_string_id(pattern)
        matched = False
        for string_def in self._current_rule.strings:
            if getattr(string_def, "is_anonymous", False):
                continue
            if fnmatchcase(self._normalize_string_id(string_def.identifier), normalized_pattern):
                self._mark_string_usage(string_def.identifier)
                matched = True

        if not matched:
            self._mark_string_usage(pattern)

    def _mark_string_set_text(self, text: str) -> None:
        if text == "them":
            self._mark_all_current_rule_strings()
            return

        normalized = self._normalize_string_id(text)
        if "*" in normalized:
            self._mark_wildcard_usage(normalized)
            return

        self._mark_string_usage(normalized)

    def _visit_string_set_value(self, string_set) -> None:
        if isinstance(string_set, str):
            self._mark_string_set_text(string_set)
            return
        if isinstance(string_set, list | tuple | set | frozenset):
            for item in string_set:
                self._visit_string_set_value(item)
            return
        if isinstance(string_set, Identifier) and string_set.name == "them":
            self._mark_all_current_rule_strings()
            return
        if isinstance(string_set, StringLiteral):
            self._mark_string_set_text(string_set.value)
            return
        if isinstance(string_set, StringIdentifier):
            self._mark_string_set_text(string_set.name)
            return
        if isinstance(string_set, StringWildcard):
            self._mark_string_set_text(string_set.pattern)
            return
        if isinstance(string_set, ParenthesesExpression):
            self._visit_string_set_value(string_set.expression)
            return
        if isinstance(string_set, SetExpression):
            for element in string_set.elements:
                self._visit_string_set_value(element)
            return
        self._visit_ast_value(string_set)

    def visit_string_identifier(self, node) -> None:
        """Track string usage."""
        self._mark_string_identifier_usage(node.name)

    def visit_string_wildcard(self, node) -> None:
        self._mark_string_set_text(node.pattern)

    def visit_string_count(self, node) -> None:
        self._mark_string_usage(node.string_id)

    def visit_string_offset(self, node) -> None:
        self._mark_string_usage(node.string_id)
        self._visit_ast_value(getattr(node, "index", None))

    def visit_string_length(self, node) -> None:
        self._mark_string_usage(node.string_id)
        self._visit_ast_value(getattr(node, "index", None))

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
        self._mark_string_usage(node.string_id)
        self.visit(node.offset)

    def visit_in_expression(self, node) -> None:
        if isinstance(node.subject, str):
            self._mark_string_usage(node.subject)
        else:
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
        self._push_local_scope()
        try:
            for declaration in node.declarations:
                self.visit(declaration)
            self.visit(node.body)
        finally:
            self._pop_local_scope()
            self._current_depth -= 1

    def visit_with_declaration(self, node) -> None:
        self._visit_ast_value(node.value)
        self._define_local(node.identifier)

    def visit_array_comprehension(self, node) -> None:
        self._current_depth += 1
        self._condition_depths.append(self._current_depth)
        self._visit_ast_value(node.iterable)
        self._push_local_scope(node.variable)
        try:
            self._visit_ast_value(node.condition)
            self._visit_ast_value(node.expression)
        finally:
            self._pop_local_scope()
            self._current_depth -= 1

    def visit_dict_comprehension(self, node) -> None:
        self._current_depth += 1
        self._condition_depths.append(self._current_depth)
        self._visit_ast_value(node.iterable)
        names = [node.key_variable]
        if node.value_variable:
            names.append(node.value_variable)
        self._push_local_scope(*names)
        try:
            self._visit_ast_value(node.condition)
            self._visit_ast_value(node.key_expression)
            self._visit_ast_value(node.value_expression)
        finally:
            self._pop_local_scope()
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
        self._push_local_scope(*node.parameters)
        try:
            self._visit_ast_value(node.body)
        finally:
            self._pop_local_scope()

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

    def _is_local(self, name: str) -> bool:
        return any(name in scope for scope in reversed(self._local_scopes))

    def _push_local_scope(self, *names: str) -> None:
        scope: set[str] = set()
        for name in names:
            scope.update(self._local_name_variants(name))
        self._local_scopes.append(scope)

    def _pop_local_scope(self) -> None:
        self._local_scopes.pop()

    def _define_local(self, name: str) -> None:
        if self._local_scopes:
            self._local_scopes[-1].update(self._local_name_variants(name))

    @staticmethod
    def _local_name_variants(name: str) -> set[str]:
        names = [part.strip() for part in name.split(",")]
        return {local_name for local_name in names if local_name}
