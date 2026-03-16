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
    YaraLFile,
    YaraLRule,
)
from yaraast.yaral.optimizer import YaraLOptimizer


def test_optimizer_simplifies_boolean_and_time_window() -> None:
    condition = ConditionSection(
        expression=BinaryCondition(
            operator="and",
            left=EventExistsCondition(event="e"),
            right=BooleanLiteral(value=True),
        ),
    )
    match = MatchSection(variables=[MatchVariable(variable="e", time_window=TimeWindow(3600, "s"))])
    rule = YaraLRule(name="opt", events=None, condition=condition, match=match)
    ast = YaraLFile(rules=[rule])

    optimized, stats = YaraLOptimizer().optimize(ast)
    assert stats.conditions_simplified >= 1
    assert stats.time_windows_optimized >= 1

    optimized_match = optimized.rules[0].match
    assert optimized_match.variables[0].time_window.unit == "h"
