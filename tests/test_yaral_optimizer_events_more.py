"""More coverage for YARA-L event optimizer mixin behavior."""

from __future__ import annotations

from dataclasses import dataclass

from yaraast.yaral.ast_nodes import (
    EventAssignment,
    EventsSection,
    EventStatement,
    EventVariable,
    UDMFieldPath,
)
from yaraast.yaral.optimizer import YaraLOptimizer


@dataclass
class _Evt:
    name: str


@dataclass
class _Stmt:
    event: _Evt
    assignments: list[EventAssignment]


def _assign(field_parts: list[str], op: str, value: str | int) -> EventAssignment:
    return EventAssignment(
        event_var=EventVariable(name="$e"),
        field_path=UDMFieldPath(parts=field_parts),
        operator=op,
        value=value,
    )


def test_visit_events_section_short_circuit_for_event_assignment_nodes() -> None:
    opt = YaraLOptimizer()
    stmt = _assign(["metadata", "event_type"], "=", "LOGIN")
    section = EventsSection(statements=[stmt])

    assert opt.visit_events_section(section) is section


def test_optimize_event_statement_and_selectivity_scoring_paths() -> None:
    opt = YaraLOptimizer()
    assignments = [
        _assign(["metadata", "event_type"], "=", "LOGIN"),
        _assign(["principal", "hostname"], "!=", "badhost"),
        _assign(["principal", "user"], ">", 7),
        _assign(["metadata", "timestamp"], "=~", "/abc/"),
    ]
    stmt = _Stmt(event=_Evt("evt"), assignments=assignments)

    optimized_stmt = opt._optimize_event_statement(stmt)
    assert optimized_stmt is stmt
    assert "metadata.event_type" in opt.indexed_fields
    assert "principal.hostname" in opt.indexed_fields
    assert opt.stats.indexes_suggested >= 2

    # Direct score checks for branches in _calculate_selectivity_score
    assert opt._calculate_selectivity_score(assignments[0]) > opt._calculate_selectivity_score(
        assignments[2]
    )
    assert opt._calculate_selectivity_score(_assign(["principal", "ip"], "!~", "/abc/")) > 0
    assert opt._calculate_selectivity_score(_assign(["metadata", "other"], "contains", 1)) == 0.0
    assert opt._calculate_selectivity_score(_assign(["principal", "user"], "contains", 1)) > 0

    plain_stmt = EventStatement()
    assert opt.visit_event_statement(plain_stmt) is plain_stmt
    assert opt.visit_event_assignment(assignments[0]) is assignments[0]
    empty_stmt = _Stmt(event=_Evt("evt"), assignments=[])
    assert opt._optimize_event_statement(empty_stmt) is empty_stmt


def test_remove_redundant_assignments_and_similarity_grouping() -> None:
    opt = YaraLOptimizer()

    a1 = _assign(["principal", "ip"], "=", "1.2.3.4")
    a2 = _assign(["principal", "ip"], "!=", "1.2.3.4")  # contradictory
    a3 = _assign(["principal", "ip"], "!=", "1.2.3.4")  # redundant with a2
    a4 = _assign(["principal", "hostname"], "=", "h1")

    filtered = opt._remove_redundant_assignments([a1, a2, a3, a4])
    assert a4 in filtered
    assert opt.stats.redundant_checks_removed >= 2

    opt2 = YaraLOptimizer()
    replaced = opt2._remove_redundant_assignments(
        [
            _assign(["principal", "ip"], "!=", "1.1.1.1"),
            _assign(["principal", "ip"], "=", "1.1.1.1"),
        ]
    )
    assert len(replaced) == 1
    assert replaced[0].operator == "="

    keep_both = opt._remove_redundant_assignments(
        [
            _assign(["principal", "ip"], "=", "1.1.1.1"),
            _assign(["principal", "ip"], "=", "2.2.2.2"),
        ]
    )
    assert len(keep_both) == 2

    opt3 = YaraLOptimizer()
    exact_redundant = opt3._remove_redundant_assignments(
        [
            _assign(["principal", "hostname"], "=", "h1"),
            _assign(["principal", "hostname"], "=", "h1"),
        ]
    )
    assert len(exact_redundant) == 1
    assert opt3.stats.redundant_checks_removed == 1

    s1 = _Stmt(event=_Evt("login"), assignments=[a1, a4])
    s2 = _Stmt(event=_Evt("login"), assignments=[_assign(["principal", "ip"], "=", "2.2.2.2")])
    s3 = _Stmt(event=_Evt("dns"), assignments=[_assign(["principal", "ip"], "=", "3.3.3.3")])
    s4 = _Stmt(event=_Evt("login"), assignments=[])

    assert opt._are_similar_events(s1, s2) is True
    assert opt._are_similar_events(s1, s3) is False
    assert opt._are_similar_events(s4, s2) is False

    grouped = opt._group_event_statements([s1, s2, s3])
    assert len(grouped) == 2
    assert len(grouped[0]) == 2


def test_combine_event_statements_edge_cases_and_compat_wrapper() -> None:
    opt = YaraLOptimizer()
    s1 = _Stmt(event=_Evt("x"), assignments=[_assign(["principal", "ip"], "=", "1.1.1.1")])
    s2 = _Stmt(event=_Evt("x"), assignments=[_assign(["principal", "hostname"], "=", "h")])
    s3 = _Stmt(event=_Evt("x"), assignments=[_assign(["principal", "ip"], "=", "2.2.2.2")])

    assert opt._combine_event_statements([]) is None
    assert opt._combine_event_statements([s1]) is s1

    combined = opt._combine_event_statements([s1, s2, s3])
    assert combined is not None
    assert combined.event.name == "x"
    assert len(combined.assignments) == 2

    s4 = _Stmt(event=_Evt("x"), assignments=[])
    combined2 = opt._combine_event_statements([s1, s4])
    assert combined2 is not None
    assert len(combined2.assignments) == 1


def test_visit_events_section_grouping_branch_tracks_stats() -> None:
    opt = YaraLOptimizer()
    s1 = _Stmt(event=_Evt("x"), assignments=[_assign(["principal", "ip"], "=", "1.1.1.1")])
    s2 = _Stmt(event=_Evt("x"), assignments=[_assign(["principal", "ip"], "=", "2.2.2.2")])

    section = opt.visit_events_section(EventsSection(statements=[s1, s2]))
    assert len(section.statements) == 1

    assert opt.stats.events_optimized == 1

    single = opt.visit_events_section(
        EventsSection(statements=[_Stmt(event=_Evt("y"), assignments=[])])
    )
    assert len(single.statements) == 1
