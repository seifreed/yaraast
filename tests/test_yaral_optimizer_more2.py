"""Extra tests for YARA-L optimizer internals (no mocks)."""

from __future__ import annotations

from typing import Any, cast

from yaraast.yaral.ast_nodes import (
    BinaryCondition,
    ConditionSection,
    EventExistsCondition,
    MatchSection,
    MatchVariable,
    OutcomeSection,
    TimeWindow,
    YaraLFile,
    YaraLRule,
)
from yaraast.yaral.optimizer import YaraLOptimizer


def test_optimizer_rejects_invalid_yaral_file_structure() -> None:
    ast = YaraLFile(rules=cast(Any, [object()]))

    try:
        YaraLOptimizer().optimize(ast)
    except TypeError as exc:
        assert "YaraLFile rules must contain YaraLRule nodes" in str(exc)
    else:
        raise AssertionError("expected invalid YaraLFile structure")


def test_optimizer_condition_simplify_and_match_window() -> None:
    optimizer = YaraLOptimizer()

    condition = ConditionSection(
        expression=BinaryCondition(
            operator="and",
            left=EventExistsCondition(event="e"),
            right=EventExistsCondition(event="e"),
        )
    )
    optimized_cond = optimizer._optimize_condition_section(condition)
    assert optimized_cond is not None
    assert optimizer.stats.conditions_simplified >= 1
    assert optimized_cond.expression is not None

    match = MatchSection(variables=[MatchVariable(variable="e", time_window=TimeWindow(7200, "s"))])
    optimized_match = optimizer._optimize_match_section(match)
    assert optimized_match is not None
    assert optimized_match.variables[0].time_window.unit == "h"


def test_optimizer_simplifies_falsy_present_condition_expression() -> None:
    class FalsyBinaryCondition(BinaryCondition):
        def __bool__(self) -> bool:
            return False

    optimizer = YaraLOptimizer()
    condition = ConditionSection(
        expression=FalsyBinaryCondition(
            operator="and",
            left=EventExistsCondition(event="e"),
            right=EventExistsCondition(event="e"),
        )
    )

    optimized = optimizer._optimize_condition_section(condition)

    assert optimized is not None
    assert isinstance(optimized.expression, EventExistsCondition)
    assert optimizer.stats.conditions_simplified >= 1


def test_optimizer_visits_falsy_present_binary_condition_operands() -> None:
    from yaraast.yaral.ast_nodes import UnaryCondition

    class FalsyUnaryCondition(UnaryCondition):
        def __bool__(self) -> bool:
            return False

    optimizer = YaraLOptimizer()
    condition = BinaryCondition(
        operator="and",
        left=FalsyUnaryCondition(
            operator="not",
            operand=UnaryCondition(operator="not", operand=EventExistsCondition(event="e")),
        ),
        right=EventExistsCondition(event="other"),
    )

    optimized = optimizer._optimize_binary_condition(condition)

    assert isinstance(optimized, BinaryCondition)
    assert isinstance(optimized.left, EventExistsCondition)
    assert optimized.left.event == "e"
    assert optimizer.stats.conditions_simplified >= 1


def test_optimizer_options_and_outcome() -> None:
    optimizer = YaraLOptimizer()
    rule = YaraLRule(
        name="opt_rule",
        events=None,
        match=None,
        condition=None,
        outcome=OutcomeSection(assignments=[]),
        options=None,
    )
    ast = YaraLFile(rules=[rule])
    optimized, _stats = optimizer.optimize(ast)

    assert optimized.rules[0].outcome is not None
