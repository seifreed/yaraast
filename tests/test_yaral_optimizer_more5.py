"""More tests for YARA-L optimizer (no mocks)."""

from __future__ import annotations

from yaraast.yaral.ast_nodes import (
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


def test_yaral_optimizer_time_window() -> None:
    match = MatchSection(variables=[MatchVariable(variable="e", time_window=TimeWindow(1440, "m"))])
    rule = YaraLRule(name="r2", match=match)
    ast = YaraLFile(rules=[rule])

    optimized, stats = YaraLOptimizer().optimize(ast)
    assert stats.time_windows_optimized >= 1
    optimized_match = optimized.rules[0].match
    assert optimized_match is not None
    assert optimized_match.variables[0].time_window.unit == "d"
