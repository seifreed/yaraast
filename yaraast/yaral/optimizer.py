"""YARA-L optimizer for query performance."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from yaraast.yaral.ast_nodes import (
    BinaryCondition,
    ConditionSection,
    EventExistsCondition,
    EventsSection,
    MatchSection,
    OutcomeSection,
    YaraLFile,
    YaraLRule,
)
from yaraast.yaral.optimizer_conditions import YaraLOptimizerConditionsMixin
from yaraast.yaral.optimizer_events import YaraLOptimizerEventsMixin
from yaraast.yaral.optimizer_helpers import YaraLOptimizerHelpersMixin
from yaraast.yaral.optimizer_outcome import YaraLOptimizerOutcomeMixin
from yaraast.yaral.visitor_base import YaraLVisitor

if TYPE_CHECKING:
    from yaraast.yaral.ast_nodes import (
        AggregationFunction,
        ArithmeticExpression,
        BinaryCondition,
        CIDRExpression,
        ConditionalExpression,
        ConditionExpression,
        ConditionSection,
        EventAssignment,
        EventCountCondition,
        EventExistsCondition,
        EventsSection,
        EventStatement,
        EventVariable,
        FunctionCall,
        JoinCondition,
        MatchSection,
        MatchVariable,
        OptionsSection,
        OutcomeAssignment,
        OutcomeExpression,
        OutcomeSection,
        ReferenceList,
        RegexPattern,
        UDMFieldPath,
        VariableComparisonCondition,
        YaraLFile,
        YaraLRule,
    )


@dataclass
class OptimizationStats:
    """Statistics about optimizations performed."""

    rules_optimized: int = 0
    conditions_simplified: int = 0
    events_optimized: int = 0
    redundant_checks_removed: int = 0
    indexes_suggested: int = 0
    time_windows_optimized: int = 0
    joins_optimized: int = 0

    def __str__(self) -> str:
        return (
            f"Optimizations: {self.rules_optimized} rules, "
            f"{self.conditions_simplified} conditions simplified, "
            f"{self.events_optimized} events optimized, "
            f"{self.redundant_checks_removed} redundant checks removed"
        )


class YaraLOptimizer(
    YaraLOptimizerHelpersMixin,
    YaraLOptimizerEventsMixin,
    YaraLOptimizerConditionsMixin,
    YaraLOptimizerOutcomeMixin,
    YaraLVisitor[Any],
):
    """Optimizer for YARA-L rules to improve query performance."""

    def __init__(self) -> None:
        self.stats = OptimizationStats()
        self.indexed_fields = set()
        self.current_rule = None

    def optimize(self, ast: YaraLFile) -> tuple[YaraLFile, OptimizationStats]:
        """Optimize YARA-L file and return optimized AST with stats."""
        self.stats = OptimizationStats()
        optimized_ast = self.visit(ast)
        return optimized_ast, self.stats

    def visit_yaral_file(self, node: YaraLFile) -> YaraLFile:
        optimized_rules = []

        for rule in node.rules:
            optimized_rule = self.visit(rule)
            if optimized_rule != rule:
                self.stats.rules_optimized += 1
            optimized_rules.append(optimized_rule)

        return YaraLFile(rules=optimized_rules)

    def visit_yaral_rule(self, node: YaraLRule) -> YaraLRule:
        self.current_rule = node.name
        self.indexed_fields.clear()

        optimized_events = None
        if node.events:
            optimized_events = self.visit(node.events)

        optimized_match = None
        if node.match:
            optimized_match = self._optimize_match_section(node.match)

        optimized_condition = None
        if node.condition:
            optimized_condition = self._optimize_condition_section(node.condition)

        optimized_outcome = None
        if node.outcome:
            optimized_outcome = self._optimize_outcome_section(node.outcome)

        return YaraLRule(
            name=node.name,
            meta=node.meta,
            events=optimized_events,
            match=optimized_match,
            condition=optimized_condition,
            outcome=optimized_outcome,
            options=self._optimize_options(node.options),
        )

    def visit_yaral_events_section(self, node: EventsSection) -> EventsSection:
        return self.visit_events_section(node)

    def visit_yaral_event_statement(self, node: EventStatement) -> EventStatement:
        return self.visit_event_statement(node)

    def visit_yaral_event_assignment(self, node: EventAssignment) -> EventAssignment:
        return self.visit_event_assignment(node)

    def visit_yaral_event_variable(self, node: EventVariable) -> EventVariable:
        return node

    def visit_yaral_udm_field_path(self, node: UDMFieldPath) -> UDMFieldPath:
        return node

    def visit_yaral_reference_list(self, node: ReferenceList) -> ReferenceList:
        return node

    def visit_yaral_match_section(self, node: MatchSection) -> MatchSection:
        return node

    def visit_yaral_match_variable(self, node: MatchVariable) -> MatchVariable:
        return node

    def visit_yaral_time_window(self, node) -> Any:
        return node

    def visit_yaral_condition_section(self, node: ConditionSection) -> ConditionSection:
        return self._optimize_condition_section(node)

    def visit_yaral_condition_expression(self, node: ConditionExpression) -> ConditionExpression:
        return node

    def visit_yaral_binary_condition(self, node: BinaryCondition) -> ConditionExpression:
        return self._optimize_binary_condition(node)

    def visit_yaral_unary_condition(self, node) -> ConditionExpression:
        return node

    def visit_yaral_event_count_condition(self, node: EventCountCondition) -> ConditionExpression:
        return node

    def visit_yaral_event_exists_condition(self, node: EventExistsCondition) -> ConditionExpression:
        return node

    def visit_yaral_variable_comparison_condition(
        self, node: VariableComparisonCondition
    ) -> ConditionExpression:
        return node

    def visit_yaral_join_condition(self, node: JoinCondition) -> ConditionExpression:
        return node

    def visit_yaral_outcome_section(self, node: OutcomeSection) -> OutcomeSection:
        return node

    def visit_yaral_outcome_assignment(self, node: OutcomeAssignment) -> OutcomeAssignment:
        return node

    def visit_yaral_outcome_expression(self, node: OutcomeExpression) -> OutcomeExpression:
        return node

    def visit_yaral_aggregation_function(self, node: AggregationFunction) -> OutcomeExpression:
        return node

    def visit_yaral_conditional_expression(self, node: ConditionalExpression) -> OutcomeExpression:
        return node

    def visit_yaral_arithmetic_expression(self, node: ArithmeticExpression) -> OutcomeExpression:
        return node

    def visit_yaral_options_section(self, node: OptionsSection) -> OptionsSection:
        return node

    def visit_yaral_regex_pattern(self, node: RegexPattern) -> RegexPattern:
        return node

    def visit_yaral_cidr_expression(self, node: CIDRExpression) -> CIDRExpression:
        return node

    def visit_yaral_function_call(self, node: FunctionCall) -> FunctionCall:
        return node
