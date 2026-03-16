"""Extra tests for YARA-L optimizer internals (no mocks)."""

from __future__ import annotations

from yaraast.yaral.ast_nodes import (
    BinaryCondition,
    ConditionSection,
    EventAssignment,
    EventExistsCondition,
    EventVariable,
    MatchSection,
    MatchVariable,
    OutcomeSection,
    TimeWindow,
    UDMFieldPath,
    YaraLFile,
    YaraLRule,
)
from yaraast.yaral.optimizer import YaraLOptimizer


def _assignment(event_name: str, parts: list[str], operator: str, value) -> EventAssignment:
    return EventAssignment(
        event_var=EventVariable(name=event_name),
        field_path=UDMFieldPath(parts=parts),
        operator=operator,
        value=value,
    )


def test_optimizer_reorders_and_indexes() -> None:
    optimizer = YaraLOptimizer()
    assignments = [
        _assignment("$e", ["metadata", "timestamp"], ">", 5),
        _assignment("$e", ["metadata", "event_type"], "=", "LOGIN"),
        _assignment("$e", ["principal", "hostname"], "=", "host"),
    ]

    reordered = optimizer._reorder_assignments(assignments)
    assert reordered[0].field_path.parts[-1] in {"event_type", "hostname"}

    for assignment in reordered:
        if optimizer._should_index_field(assignment):
            optimizer.indexed_fields.add(optimizer._field_path_to_string(assignment.field_path))

    assert any("event_type" in f for f in optimizer.indexed_fields)


def test_optimizer_removes_contradictions() -> None:
    optimizer = YaraLOptimizer()
    assignments = [
        _assignment("$e", ["metadata", "event_type"], "=", "LOGIN"),
        _assignment("$e", ["metadata", "event_type"], "!=", "LOGIN"),
    ]

    optimized = optimizer._remove_redundant_assignments(assignments)
    assert len(optimized) == 1
    assert optimizer.stats.redundant_checks_removed >= 1


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
    assert optimizer.stats.conditions_simplified >= 1
    assert optimized_cond.expression is not None

    match = MatchSection(variables=[MatchVariable(variable="e", time_window=TimeWindow(7200, "s"))])
    optimized_match = optimizer._optimize_match_section(match)
    assert optimized_match.variables[0].time_window.unit == "h"


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
