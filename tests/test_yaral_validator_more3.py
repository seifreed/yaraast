"""More tests for YARA-L validator (no mocks)."""

from __future__ import annotations

from textwrap import dedent

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
from yaraast.yaral.enhanced_parser import EnhancedYaraLParser
from yaraast.yaral.parser import YaraLParser
from yaraast.yaral.validator import YaraLValidator


def test_validator_rule_name_and_required_sections() -> None:
    bad_rule = YaraLRule(name="1bad")
    errors, warnings = YaraLValidator().validate(YaraLFile(rules=[bad_rule]))

    assert errors
    assert any("Rule must have an events section" in err.message for err in errors)
    assert any("Rule must have a condition section" in err.message for err in errors)
    assert not warnings


def test_validate_returns_stable_error_and_warning_snapshots() -> None:
    validator = YaraLValidator()
    bad_rule = YaraLRule(name="1bad")
    valid_rule = YaraLRule(
        name="valid_rule",
        events=EventsSection(
            statements=[
                EventAssignment(
                    event_var=EventVariable(name="$e"),
                    field_path=UDMFieldPath(parts=["metadata", "event_type"]),
                    operator="=",
                    value="LOGIN",
                )
            ]
        ),
        condition=ConditionSection(expression=EventExistsCondition(event="$e")),
    )

    first_errors, first_warnings = validator.validate(YaraLFile(rules=[bad_rule]))
    second_errors, second_warnings = validator.validate(YaraLFile(rules=[valid_rule]))

    assert first_errors
    assert any("Rule must have an events section" in err.message for err in first_errors)
    assert first_warnings == []
    assert second_errors == []
    assert second_warnings == []
    assert any("Rule must have a condition section" in err.message for err in first_errors)


def test_validator_accepts_bracketed_udm_fields_and_dollar_event_conditions() -> None:
    parser = EnhancedYaraLParser("""
        rule bracketed_valid {
            events:
                $e.metadata["event_type"] = "LOGIN"
            condition:
                $e
        }
        """)
    ast = parser.parse()

    errors, warnings = YaraLValidator().validate(ast)

    assert parser.errors == []
    assert errors == []
    assert not any("Unknown field" in warning.message for warning in warnings)
    assert not any("Unused event variable" in warning.message for warning in warnings)


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


def test_validator_accepts_repeated_event_constraints_in_and_regex() -> None:
    code = dedent(
        """
        rule valid_event_operators {
            events:
                $e.metadata.event_type = "LOGIN"
                $e.principal.ip in %trusted_ips%
                $e.target.hostname regex /host-.*/
            condition:
                $e
        }
        """,
    )

    ast = YaraLParser(code).parse()
    errors, warnings = YaraLValidator().validate(ast)

    assert errors == []
    assert not any("Duplicate event variable" in warning.message for warning in warnings)
