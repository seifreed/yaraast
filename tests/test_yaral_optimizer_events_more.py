"""Coverage for current YARA-L event optimizer behavior."""

from __future__ import annotations

from yaraast.yaral.ast_nodes import (
    EventAssignment,
    EventsSection,
    EventStatement,
    EventVariable,
    JoinCondition,
    UDMFieldPath,
)
from yaraast.yaral.optimizer import YaraLOptimizer


def _assign(field_parts: list[str], operator: str, value: str | int) -> EventAssignment:
    return EventAssignment(
        event_var=EventVariable(name="$e"),
        field_path=UDMFieldPath(parts=field_parts),
        operator=operator,
        value=value,
    )


def test_visit_events_section_tracks_indexable_assignments_without_reordering() -> None:
    optimizer = YaraLOptimizer()
    indexed = _assign(["metadata", "event_type"], "=", "LOGIN")
    untouched = _assign(["metadata", "description"], "contains", "login")
    raw = EventStatement(text="re.regex($e.target.url, `login`)")
    join = JoinCondition(left_event="$e", right_event="$other")
    section = EventsSection(statements=[indexed, raw, join, untouched])

    assert optimizer.visit_events_section(section) is section
    assert section.statements == [indexed, raw, join, untouched]
    assert optimizer.indexed_fields == {"metadata.event_type"}
    assert optimizer.stats.indexes_suggested == 1


def test_event_visitors_return_current_ast_nodes() -> None:
    optimizer = YaraLOptimizer()
    raw = EventStatement(text="$e")
    assignment = _assign(["principal", "ip"], "!=", "127.0.0.1")

    assert optimizer.visit_event_statement(raw) is raw
    assert optimizer.visit_event_assignment(assignment) is assignment
    assert optimizer.indexed_fields == {"principal.ip"}
