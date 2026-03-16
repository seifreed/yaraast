from __future__ import annotations

from dataclasses import dataclass, field

from yaraast.yaral.ast_nodes import (
    EventAssignment,
    EventsSection,
    EventStatement,
    EventVariable,
    ReferenceList,
    UDMFieldAccess,
    UDMFieldPath,
)
from yaraast.yaral.validator import YaraLValidator


@dataclass
class LegacyEventStatement:
    event: EventVariable | None = None
    assignments: list = field(default_factory=list)


def test_validator_events_section_empty_and_statement_without_assignments() -> None:
    validator = YaraLValidator()
    validator.current_rule = "r1"

    validator.visit_events_section(EventsSection())
    assert any("Events section cannot be empty" in err.message for err in validator.errors)

    validator.errors.clear()
    validator.warnings.clear()
    validator.visit_event_statement(LegacyEventStatement(event=EventVariable(name="$e")))
    assert any("has no field assignments" in warn.message for warn in validator.warnings)


def test_validator_event_variable_assignment_and_field_paths() -> None:
    validator = YaraLValidator()
    validator.current_rule = "r2"

    validator.visit_event_variable(EventVariable(name="bad"))
    validator.visit_event_variable(EventVariable(name="$dup"))
    validator.visit_event_variable(EventVariable(name="$dup"))

    assert any("must start with $" in err.message for err in validator.errors)
    assert any("Duplicate event variable" in err.message for err in validator.errors)

    validator.errors.clear()
    validator.warnings.clear()

    assignment = EventAssignment(
        event_var=EventVariable(name="$e"),
        field_path=UDMFieldPath(parts=["mystery", "field"]),
        operator="contains",
        value=123,
    )
    validator.visit_event_assignment(assignment)
    assert any("Invalid operator" in err.message for err in validator.errors)
    assert any("Unknown UDM namespace" in warn.message for warn in validator.warnings)

    validator.errors.clear()
    validator.warnings.clear()
    validator.visit_event_assignment(
        EventAssignment(
            event_var=EventVariable(name="$e2"),
            field_path=UDMFieldPath(parts=["metadata", "unknown_field"]),
            operator="=~",
            value="not_a_regex",
        )
    )
    assert any("Unknown field 'unknown_field'" in warn.message for warn in validator.warnings)
    assert any(
        "Regex operator =~ should be used with regex pattern" in warn.message
        for warn in validator.warnings
    )


def test_validator_event_path_access_and_reference_list_wrappers() -> None:
    validator = YaraLValidator()
    validator.current_rule = "r3"

    validator._validate_udm_field_path(UDMFieldPath(parts=[]))
    assert any("Empty UDM field path" in err.message for err in validator.errors)

    validator.errors.clear()
    validator.warnings.clear()
    validator.visit_yaral_events_section(EventsSection(statements=[]))
    validator.visit_yaral_event_statement(LegacyEventStatement(event=EventVariable(name="$e")))
    validator.visit_yaral_event_assignment(
        EventAssignment(
            event_var=EventVariable(name="$ok"),
            field_path=UDMFieldPath(parts=["metadata", "event_type"]),
            operator="=",
            value="LOGIN",
        )
    )
    validator.visit_yaral_event_variable(EventVariable(name="$ok2"))
    validator.visit_yaral_udm_field_path(UDMFieldPath(parts=["principal.ip"]))
    validator.visit_yaral_udm_field_access(
        UDMFieldAccess(
            event=EventVariable(name="$e"),
            field=UDMFieldPath(parts=["principal", "unknown_field"]),
        )
    )
    validator.visit_yaral_reference_list(ReferenceList(name="%list%"))

    assert any("Unknown field 'unknown_field'" in warn.message for warn in validator.warnings)
    assert "principal" in validator.VALID_UDM_FIELDS


def test_validator_event_statement_without_event_attribute_is_ignored() -> None:
    validator = YaraLValidator()
    validator.current_rule = "r4"
    validator.visit_event_statement(EventStatement())
    assert validator.errors == []
    assert any(
        "Event unknown has no field assignments" in warn.message for warn in validator.warnings
    )

    validator.warnings.clear()
    validator.visit_event_statement(
        LegacyEventStatement(
            event=EventVariable(name="$ok"),
            assignments=[
                EventAssignment(
                    event_var=EventVariable(name="$ok"),
                    field_path=UDMFieldPath(parts=["metadata", "event_type"]),
                    operator="=",
                    value="LOGIN",
                )
            ],
        )
    )
    assert validator.warnings == []
