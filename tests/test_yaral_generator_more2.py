"""Real tests for YARA-L generator (no mocks)."""

from __future__ import annotations

from yaraast.yaral.ast_nodes import (
    AggregationFunction,
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
    OutcomeAssignment,
    OutcomeSection,
    TimeWindow,
    UDMFieldPath,
    YaraLFile,
    YaraLRule,
)
from yaraast.yaral.generator import YaraLGenerator


def test_generator_full_rule() -> None:
    meta = MetaSection(entries=[MetaEntry(key="author", value="unit")])
    events = EventsSection(
        statements=[
            EventAssignment(
                event_var=EventVariable(name="$e"),
                field_path=UDMFieldPath(parts=["metadata", "event_type"]),
                operator="=",
                value="LOGIN",
                modifiers=["nocase"],
            )
        ]
    )
    match = MatchSection(variables=[MatchVariable(variable="e", time_window=TimeWindow(5, "m"))])
    condition = ConditionSection(expression=EventExistsCondition(event="e"))
    outcome = OutcomeSection(
        assignments=[
            OutcomeAssignment(variable="$score", expression=AggregationFunction("count", ["$e"]))
        ]
    )

    rule = YaraLRule(
        name="gen_rule",
        meta=meta,
        events=events,
        match=match,
        condition=condition,
        outcome=outcome,
    )

    code = YaraLGenerator().generate(YaraLFile(rules=[rule]))

    assert "rule gen_rule" in code
    assert "meta:" in code
    assert "events:" in code
    assert "match:" in code
    assert "condition:" in code
    assert "outcome:" in code
    assert "nocase" in code
    assert "count($e)" in code


def test_generator_binary_condition_and_match() -> None:
    condition = ConditionSection(
        expression=BinaryCondition(
            operator="and",
            left=EventExistsCondition(event="e"),
            right=EventExistsCondition(event="f"),
        )
    )
    rule = YaraLRule(
        name="binary_rule",
        events=EventsSection(statements=[]),
        match=MatchSection(variables=[MatchVariable(variable="e", time_window=TimeWindow(1, "h"))]),
        condition=condition,
    )

    code = YaraLGenerator().generate(YaraLFile(rules=[rule]))
    assert "($e and $f)" in code
    assert "$e over 1h" in code
