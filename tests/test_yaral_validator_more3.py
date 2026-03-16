"""More tests for YARA-L validator (no mocks)."""

from __future__ import annotations

from yaraast.yaral.ast_nodes import (
    ConditionSection,
    EventAssignment,
    EventExistsCondition,
    EventsSection,
    EventVariable,
    UDMFieldPath,
    YaraLFile,
    YaraLRule,
)
from yaraast.yaral.validator import YaraLValidator


def test_validator_rule_name_and_required_sections() -> None:
    bad_rule = YaraLRule(name="1bad")
    errors, warnings = YaraLValidator().validate(YaraLFile(rules=[bad_rule]))

    assert errors
    assert any("Rule must have an events section" in err.message for err in errors)
    assert any("Rule must have a condition section" in err.message for err in errors)
    assert not warnings


def test_validator_event_assignment_checks() -> None:
    events = EventsSection(
        statements=[
            EventAssignment(
                event_var=EventVariable(name="$e"),
                field_path=UDMFieldPath(parts=["unknown", "field"]),
                operator="==",
                value="x",
            ),
            EventAssignment(
                event_var=EventVariable(name="$e"),
                field_path=UDMFieldPath(parts=["metadata", "event_type"]),
                operator="=~",
                value="not_regex",
            ),
        ],
    )
    rule = YaraLRule(
        name="rule1",
        events=events,
        condition=ConditionSection(expression=EventExistsCondition(event="e")),
    )
    errors, warnings = YaraLValidator().validate(YaraLFile(rules=[rule]))

    assert any("Invalid operator" in err.message for err in errors)
    assert any("Unknown UDM namespace" in warn.message for warn in warnings)
    assert any("Regex operator" in warn.message for warn in warnings)
