"""AST-based optimization analyzer.

Analyzes YARA rules for optimization opportunities using AST structure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from yaraast.analysis.optimization_rule_analysis import (
    analyze_condition_patterns as helper_analyze_condition_patterns,
)
from yaraast.analysis.optimization_rule_analysis import (
    analyze_cross_rule_patterns as helper_analyze_cross_rule_patterns,
)
from yaraast.analysis.optimization_rule_analysis import (
    analyze_string_definitions as helper_analyze_string_definitions,
)
from yaraast.analysis.optimization_rule_analysis import (
    check_hex_consolidation as helper_check_hex_consolidation,
)
from yaraast.analysis.optimization_rule_analysis import (
    check_overlapping_patterns as helper_check_overlapping_patterns,
)
from yaraast.analysis.optimization_rule_analysis import (
    find_similar_rules as helper_find_similar_rules,
)
from yaraast.analysis.optimization_rule_analysis import (
    visit_binary_expression as helper_visit_binary_expression,
)
from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import BinaryExpression, StringIdentifier
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexString
from yaraast.visitor.base import BaseVisitor


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

    def analyze(self, ast: YaraFile) -> OptimizationReport:
        """Analyze AST for optimizations."""
        self.report = OptimizationReport()

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
        helper_analyze_string_definitions(self, rule)

    def _check_hex_consolidation(
        self,
        rule: Rule,
        hex_strings: list[HexString],
    ) -> None:
        """Check if hex strings can be consolidated."""
        helper_check_hex_consolidation(self, rule, hex_strings)

    def _check_overlapping_patterns(self, rule: Rule, strings: list[Any]) -> None:
        """Check for patterns that might overlap."""
        helper_check_overlapping_patterns(self, rule, strings)

    def _analyze_condition_patterns(self, rule: Rule) -> None:
        """Analyze condition for optimization patterns."""
        helper_analyze_condition_patterns(self, rule)

    def visit_binary_expression(self, node: BinaryExpression) -> None:
        """Analyze binary expressions."""
        helper_visit_binary_expression(self, node)

    def visit_string_identifier(self, node: StringIdentifier) -> None:
        """Track string references."""
        self._string_refs.setdefault(node.name, []).append(node)

    def visit_of_expression(self, node: OfExpression) -> None:
        """Analyze 'of' expressions."""
        # Check for 'any of them' which could be more specific
        if (
            (
                hasattr(node.quantifier, "name")
                and node.quantifier.name == "any"
                and hasattr(node.string_set, "name")
                and node.string_set.name == "them"
            )
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

    def _analyze_cross_rule_patterns(self, rules: list[Rule]) -> None:
        """Analyze patterns across multiple rules."""
        helper_analyze_cross_rule_patterns(self, rules)

    def _find_similar_rules(self, rules: list[Rule]) -> None:
        """Find rules with similar structure that could be combined."""
        helper_find_similar_rules(self, rules)

    # Helper methods

    # Helper methods live in optimization_helpers for a smaller public surface.
