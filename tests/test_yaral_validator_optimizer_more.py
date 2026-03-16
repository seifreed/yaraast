"""Additional tests for YARA-L validator and optimizer."""

from __future__ import annotations

from yaraast.yaral.ast_nodes import (
    BinaryCondition,
    ConditionSection,
    EventAssignment,
    EventExistsCondition,
    EventsSection,
    EventVariable,
    MatchSection,
    MatchVariable,
    MetaEntry,
    MetaSection,
    OptionsSection,
    OutcomeAssignment,
    OutcomeSection,
    TimeWindow,
    UDMFieldPath,
    UnaryCondition,
    YaraLFile,
    YaraLRule,
)
from yaraast.yaral.optimizer import YaraLOptimizer
from yaraast.yaral.validator import YaraLValidator


def test_yaral_validator_flags_multiple_issues() -> None:
    event_var = EventVariable(name="$e")
    bad_assignment = EventAssignment(
        event_var=event_var,
        field_path=UDMFieldPath(parts=["unknown", "field"]),
        operator="==",
        value="LOGIN",
    )
    regex_warning_assignment = EventAssignment(
        event_var=event_var,
        field_path=UDMFieldPath(parts=["metadata", "event_type"]),
        operator="=~",
        value="LOGIN",
    )

    rule1 = YaraLRule(
        name="1bad",
        meta=MetaSection(entries=[MetaEntry(key="severity", value="urgent")]),
        events=EventsSection(statements=[bad_assignment, regex_warning_assignment]),
        match=MatchSection(
            variables=[MatchVariable(variable="user", time_window=TimeWindow(-1, "x"))]
        ),
        condition=ConditionSection(expression=EventExistsCondition(event="e")),
        outcome=OutcomeSection(
            assignments=[
                OutcomeAssignment(variable="score", expression=1),
                OutcomeAssignment(variable="score", expression=2),
            ]
        ),
        options=OptionsSection(options={"unknown_option": True}),
    )

    rule2 = YaraLRule(
        name="1bad",
        events=EventsSection(statements=[bad_assignment]),
        condition=ConditionSection(expression=EventExistsCondition(event="missing")),
    )

    errors, warnings = YaraLValidator().validate(YaraLFile(rules=[rule1, rule2]))

    error_messages = [err.message for err in errors]
    warning_messages = [warn.message for warn in warnings]

    assert any("Duplicate rule name" in msg for msg in error_messages)
    assert any(
        "Rule name '1bad' must start with letter or underscore" in msg for msg in error_messages
    )
    assert any("Invalid operator" in msg for msg in error_messages)
    assert any("Invalid time unit" in msg for msg in error_messages)
    assert any("Time window duration must be positive" in msg for msg in error_messages)
    assert any("Unknown UDM namespace" in msg for msg in warning_messages)
    assert any("Regex operator" in msg for msg in warning_messages)
    assert any("Unknown option" in msg for msg in warning_messages)
    assert any("Missing recommended meta field" in msg for msg in warning_messages)


def test_yaral_optimizer_simplifies_conditions_and_time_window() -> None:
    optimizer = YaraLOptimizer()

    condition = ConditionSection(
        expression=BinaryCondition(
            operator="and",
            left=EventExistsCondition(event="e"),
            right=EventExistsCondition(event="e"),
        )
    )
    double_negation = ConditionSection(
        expression=UnaryCondition(
            operator="not",
            operand=UnaryCondition(operator="not", operand=EventExistsCondition(event="e")),
        )
    )

    match = MatchSection(
        variables=[MatchVariable(variable="user", time_window=TimeWindow(7200, "s"))]
    )

    rule = YaraLRule(
        name="opt",
        events=EventsSection(statements=[]),
        match=match,
        condition=condition,
        outcome=OutcomeSection(assignments=[]),
    )

    optimized, stats = optimizer.optimize(YaraLFile(rules=[rule]))

    assert stats.conditions_simplified >= 1
    assert stats.time_windows_optimized >= 1
    optimized_match = optimized.rules[0].match
    assert optimized_match is not None
    assert optimized_match.variables[0].time_window.unit == "h"

    # Verify double negation path via direct call
    optimized_double = optimizer._optimize_condition_section(double_negation)
    assert isinstance(optimized_double.expression, EventExistsCondition)
