"""More tests for YARA-L optimizer (no mocks)."""

from __future__ import annotations

from dataclasses import dataclass

from yaraast.yaral.ast_nodes import (
    BinaryCondition,
    ConditionExpression,
    ConditionSection,
    EventExistsCondition,
    MatchSection,
    MatchVariable,
    TimeWindow,
    UnaryCondition,
    YaraLFile,
    YaraLRule,
)
from yaraast.yaral.optimizer import YaraLOptimizer


@dataclass
class BooleanCondition(ConditionExpression):
    value: bool


def test_yaral_optimizer_double_negation() -> None:
    condition = ConditionSection(
        expression=UnaryCondition(
            operator="not",
            operand=UnaryCondition(
                operator="not",
                operand=EventExistsCondition(event="e"),
            ),
        )
    )
    rule = YaraLRule(name="r1", condition=condition)
    ast = YaraLFile(rules=[rule])

    optimized, stats = YaraLOptimizer().optimize(ast)
    assert stats.conditions_simplified >= 1
    assert optimized.rules[0].condition is not None


def test_yaral_optimizer_boolean_simplification_and_window() -> None:
    condition = ConditionSection(
        expression=BinaryCondition(
            operator="and",
            left=EventExistsCondition(event="e"),
            right=BooleanCondition(value=True),
        )
    )
    match = MatchSection(variables=[MatchVariable(variable="e", time_window=TimeWindow(1440, "m"))])
    rule = YaraLRule(name="r2", condition=condition, match=match)
    ast = YaraLFile(rules=[rule])

    optimized, stats = YaraLOptimizer().optimize(ast)
    assert stats.conditions_simplified >= 1
    optimized_match = optimized.rules[0].match
    assert optimized_match is not None
    assert optimized_match.variables[0].time_window.unit == "d"
