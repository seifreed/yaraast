"""AST-based optimization analyzer.

Analyzes YARA rules for optimization opportunities using AST structure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from yaraast.analysis.optimization_helpers import extract_comparison
from yaraast.analysis.optimization_rule_analysis import (
    analyze_condition_patterns,
    analyze_cross_rule_patterns,
    analyze_string_definitions,
    check_hex_consolidation,
    check_overlapping_patterns,
    find_similar_rules,
    visit_binary_expression,
)
from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import BinaryExpression, StringIdentifier
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexString
from yaraast.visitor.base import BaseVisitor


def _expression_text(value: Any) -> str | None:
    if isinstance(value, str):
        return value

    raw_value = getattr(value, "value", None)
    if raw_value is not None:
        return str(raw_value)

    name = getattr(value, "name", None)
    if name is not None:
        return str(name)

    return None


@dataclass
class OptimizationSuggestion:
    """An optimization suggestion."""

    rule_name: str
    optimization_type: str
    description: str
    impact: str  # 'low', 'medium', 'high'
    code_before: str | None = None
    code_after: str | None = None

    def format(self) -> str:
        """Format suggestion for display."""
        impact_icon = {"low": "○", "medium": "◐", "high": "●"}.get(self.impact, "•")
        return f"{impact_icon} [{self.optimization_type}] {self.rule_name}: {self.description}"


@dataclass
class OptimizationReport:
    """Report of heuristic optimization opportunities."""

    suggestions: list[OptimizationSuggestion] = field(default_factory=list)
    statistics: dict[str, Any] = field(default_factory=dict)

    def add_suggestion(
        self,
        rule: str,
        opt_type: str,
        desc: str,
        impact: str = "low",
        before: str | None = None,
        after: str | None = None,
    ) -> None:
        """Add optimization suggestion."""
        self.suggestions.append(
            OptimizationSuggestion(rule, opt_type, desc, impact, before, after),
        )

    @property
    def is_heuristic(self) -> bool:
        """Whether this report contains heuristic guidance rather than semantic validation."""
        return True

    @property
    def high_impact_count(self) -> int:
        """Count of high impact optimizations."""
        return sum(1 for s in self.suggestions if s.impact == "high")


class OptimizationAnalyzer(BaseVisitor[None]):
    """Analyze AST for heuristic optimization opportunities."""

    def __init__(self) -> None:
        self.report = OptimizationReport()
        self._current_rule: Rule | None = None
        self._string_refs: dict[str, list[Any]] = {}
        self._condition_depth = 0
        self._max_condition_depth = 0
        self._local_scopes: list[set[str]] = []

    def analyze(self, ast: YaraFile) -> OptimizationReport:
        """Analyze AST for optimizations."""
        self.report = OptimizationReport()
        self._local_scopes.clear()

        # Analyze all rules
        for rule in ast.rules:
            self._analyze_rule(rule)

        # Cross-rule analysis
        self._analyze_cross_rule_patterns(ast.rules)

        # Statistics
        self.report.statistics["total_suggestions"] = len(self.report.suggestions)
        self.report.statistics["by_impact"] = {
            "high": self.report.high_impact_count,
            "medium": sum(1 for s in self.report.suggestions if s.impact == "medium"),
            "low": sum(1 for s in self.report.suggestions if s.impact == "low"),
        }
        self.report.statistics["heuristic"] = True
        self.report.statistics["analysis_kind"] = "heuristic"

        return self.report

    def _analyze_rule(self, rule: Rule) -> None:
        """Analyze single rule for optimizations."""
        self._current_rule = rule
        self._string_refs.clear()
        self._local_scopes.clear()

        # Analyze strings
        if rule.strings:
            self._analyze_string_definitions(rule)

        # Analyze condition
        if rule.condition:
            self._condition_depth = 0
            self._max_condition_depth = 0
            self.visit(rule.condition)
            self._analyze_condition_patterns(rule)

    def _analyze_string_definitions(self, rule: Rule) -> None:
        """Analyze string definitions for optimization."""
        analyze_string_definitions(self, rule)

    def _check_hex_consolidation(
        self,
        rule: Rule,
        hex_strings: list[HexString],
    ) -> None:
        """Check if hex strings can be consolidated."""
        check_hex_consolidation(self, rule, hex_strings)

    def _check_overlapping_patterns(self, rule: Rule, strings: list[Any]) -> None:
        """Check for patterns that might overlap."""
        check_overlapping_patterns(self, rule, strings)

    def _analyze_condition_patterns(self, rule: Rule) -> None:
        """Analyze condition for optimization patterns."""
        analyze_condition_patterns(self, rule)

    def visit_binary_expression(self, node: BinaryExpression) -> None:
        """Analyze binary expressions."""
        visit_binary_expression(self, node)

    def visit_string_identifier(self, node: StringIdentifier) -> None:
        """Track string references."""
        if self._is_local(node.name):
            return
        self._string_refs.setdefault(node.name, []).append(node)

    def visit_of_expression(self, node: OfExpression) -> None:
        """Analyze 'of' expressions."""
        # Check for 'any of them' which could be more specific
        if (
            _expression_text(node.quantifier) == "any"
            and _expression_text(node.string_set) == "them"
            and self._current_rule
            and len(self._current_rule.strings) > 10
        ):
            self.report.add_suggestion(
                self._current_rule.name,
                "specificity",
                "'any of them' with many strings - consider grouping strings "
                "or being more specific",
                "low",
            )
        super().visit_of_expression(node)

    def visit_for_expression(self, node: Any) -> None:
        """Visit YARA-X for expression with scoped loop variable."""
        self._visit_ast_value(node.quantifier)
        self.visit(node.iterable)
        self._push_local_scope(node.variable)
        try:
            self.visit(node.body)
        finally:
            self._pop_local_scope()

    def visit_with_statement(self, node: Any) -> None:
        """Visit YARA-X with statement with scoped declarations."""
        self._push_local_scope()
        try:
            for declaration in node.declarations:
                self.visit(declaration)
            self.visit(node.body)
        finally:
            self._pop_local_scope()

    def visit_with_declaration(self, node: Any) -> None:
        """Visit YARA-X with declaration after evaluating its value."""
        self._visit_ast_value(node.value)
        self._define_local(node.identifier)

    def visit_array_comprehension(self, node: Any) -> None:
        """Visit YARA-X array comprehension with scoped loop variable."""
        self._visit_ast_value(node.iterable)
        self._push_local_scope(node.variable)
        try:
            self._visit_ast_value(node.condition)
            self._visit_ast_value(node.expression)
        finally:
            self._pop_local_scope()

    def visit_dict_comprehension(self, node: Any) -> None:
        """Visit YARA-X dict comprehension with scoped loop variables."""
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

    def visit_lambda_expression(self, node: Any) -> None:
        """Visit YARA-X lambda expression with scoped parameters."""
        self._push_local_scope(*node.parameters)
        try:
            self._visit_ast_value(node.body)
        finally:
            self._pop_local_scope()

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

    def _extract_comparison(self, expression: Any) -> dict[str, Any] | None:
        comparison = extract_comparison(expression)
        if comparison is None:
            return None
        if self._is_local_comparison_var(str(comparison["var"])):
            return None
        return comparison

    def _is_local_comparison_var(self, name: str) -> bool:
        if name.startswith("#"):
            return self._is_local(f"${name[1:]}")
        return self._is_local(name)

    @staticmethod
    def _local_name_variants(name: str) -> set[str]:
        names = [part.strip() for part in name.split(",")]
        return {local_name for local_name in names if local_name}

    def _visit_ast_value(self, value: Any) -> None:
        if hasattr(value, "accept"):
            self.visit(value)
        elif isinstance(value, list | tuple | set | frozenset):
            for item in value:
                self._visit_ast_value(item)

    def _analyze_cross_rule_patterns(self, rules: list[Rule]) -> None:
        """Analyze patterns across multiple rules."""
        analyze_cross_rule_patterns(self, rules)

    def _find_similar_rules(self, rules: list[Rule]) -> None:
        """Find rules with similar structure that could be combined."""
        find_similar_rules(self, rules)

    # Helper methods

    # Helper methods live in optimization_helpers for a smaller public surface.
