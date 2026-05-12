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
    YaraLFile,
    YaraLRule,
)
from yaraast.yaral.optimizer import YaraLOptimizer


@dataclass
class BooleanCondition(ConditionExpression):
    value: bool


def test_optimizer_simplifies_boolean_and_time_window() -> None:
    condition = ConditionSection(
        expression=BinaryCondition(
            operator="and",
            left=EventExistsCondition(event="e"),
            right=BooleanCondition(value=True),
        ),
    )
    match = MatchSection(variables=[MatchVariable(variable="e", time_window=TimeWindow(3600, "s"))])
    rule = YaraLRule(name="opt", events=None, condition=condition, match=match)
    ast = YaraLFile(rules=[rule])

    optimized, stats = YaraLOptimizer().optimize(ast)
    assert stats.conditions_simplified >= 1
    assert stats.time_windows_optimized >= 1

    optimized_match = optimized.rules[0].match
    assert optimized_match is not None
    assert optimized_match.variables[0].time_window.unit == "h"
