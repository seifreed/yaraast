"""Tests for YARA-L generator, validator, and optimizer."""

from __future__ import annotations

from yaraast.yaral.ast_nodes import (
    AggregationFunction,
    ArithmeticExpression,
    BinaryCondition,
    ConditionSection,
    EventAssignment,
    EventCountCondition,
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
    UDMFieldAccess,
    UDMFieldPath,
    YaraLFile,
    YaraLRule,
)
from yaraast.yaral.generator import YaraLGenerator
from yaraast.yaral.optimizer import YaraLOptimizer
from yaraast.yaral.validator import YaraLValidator


def test_yaral_generator_builds_sections() -> None:
    event_var = EventVariable(name="$e")
    field_path = UDMFieldPath(parts=["metadata", "event_type"])
    events = EventAssignment(
        event_var=event_var,
        field_path=field_path,
        operator="=",
        value="LOGIN",
        modifiers=["nocase"],
    )

    match = MatchSection(
        variables=[MatchVariable(variable="user", time_window=TimeWindow(5, "m", "every"))],
    )

    condition = ConditionSection(
        expression=BinaryCondition(
            operator="and",
            left=EventCountCondition(event="e", operator=">", count=1),
            right=EventExistsCondition(event="e"),
        )
    )

    outcome = OutcomeSection(
        assignments=[
            OutcomeAssignment(
                variable="$count",
                expression=AggregationFunction(
                    function="count",
                    arguments=[UDMFieldAccess(event=event_var, field=field_path)],
                ),
            ),
            OutcomeAssignment(
                variable="$calc",
                expression=ArithmeticExpression(operator="+", left=1, right=2),
            ),
        ]
    )

    options = OptionsSection(options={"case_sensitive": False, "engine": "test"})

    meta = MetaSection(
        entries=[MetaEntry(key="author", value="unit"), MetaEntry(key="severity", value="high")]
    )

    rule = YaraLRule(
        name="demo",
        meta=meta,
        events=EventsSection(statements=[events]),
        match=match,
        condition=condition,
        outcome=outcome,
        options=options,
    )

    yaral_file = YaraLFile(rules=[rule])

    generated = YaraLGenerator().generate(yaral_file)
    assert "rule demo" in generated
    assert "meta:" in generated
    assert "events:" in generated
    assert "match:" in generated
    assert "condition:" in generated
    assert "outcome:" in generated
    assert "options:" in generated
    assert "over every 5m" in generated


def test_yaral_validator_warns_and_errors() -> None:
    event_var = EventVariable(name="$e")
    field_path = UDMFieldPath(parts=["unknown", "field"])
    events = EventAssignment(
        event_var=event_var,
        field_path=field_path,
        operator="=",
        value="LOGIN",
    )

    rule = YaraLRule(
        name="",
        meta=MetaSection(entries=[]),
        events=EventsSection(statements=[events]),
        match=MatchSection(
            variables=[MatchVariable(variable="user", time_window=TimeWindow(5, "x"))]
        ),
        condition=ConditionSection(expression=EventExistsCondition(event="missing")),
    )

    yaral_file = YaraLFile(rules=[rule])
    errors, warnings = YaraLValidator().validate(yaral_file)

    assert errors
    assert warnings


def test_yaral_optimizer_simplifies_conditions() -> None:
    condition = ConditionSection(
        expression=BinaryCondition(
            operator="and",
            left=EventExistsCondition(event="e"),
            right=EventExistsCondition(event="e"),
        )
    )
    rule = YaraLRule(name="opt", condition=condition)
    yaral_file = YaraLFile(rules=[rule])

    optimizer = YaraLOptimizer()
    optimized, stats = optimizer.optimize(yaral_file)

    assert stats.conditions_simplified >= 1
    assert optimized.rules[0].condition is not None
