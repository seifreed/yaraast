"""More tests for YARA-L optimizer (no mocks)."""

from __future__ import annotations

from yaraast.ast.expressions import BooleanLiteral
from yaraast.yaral.ast_nodes import (
    BinaryCondition,
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
            right=BooleanLiteral(value=True),
        )
    )
    match = MatchSection(variables=[MatchVariable(variable="e", time_window=TimeWindow(1440, "m"))])
    rule = YaraLRule(name="r2", condition=condition, match=match)
    ast = YaraLFile(rules=[rule])

    optimized, stats = YaraLOptimizer().optimize(ast)
    assert stats.conditions_simplified >= 1
    assert optimized.rules[0].match.variables[0].time_window.unit == "d"
