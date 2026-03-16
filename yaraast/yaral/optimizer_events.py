"""Event optimization mixin for YARA-L optimizer."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from yaraast.yaral.ast_nodes import EventAssignment, EventsSection, EventStatement


@dataclass
class LegacyEventStatement(EventStatement):
    """Compatibility wrapper for optimizer paths that still use grouped event statements."""

    event: Any = None
    assignments: list[EventAssignment] | None = None


class YaraLOptimizerEventsMixin:
    """Event optimization methods."""

    def visit_events_section(self, node: EventsSection) -> EventsSection:
        if node.statements and hasattr(node.statements[0], "event_var"):
            return node

        optimized_statements = []
        event_groups = self._group_event_statements(node.statements)

        for group in event_groups:
            if len(group) > 1:
                combined = self._combine_event_statements(group)
                optimized_statements.append(combined)
                self.stats.events_optimized += len(group) - 1
            else:
                optimized = self._optimize_event_statement(group[0])
                optimized_statements.append(optimized)

        return EventsSection(statements=optimized_statements)

    def visit_event_statement(self, node: EventStatement) -> EventStatement:
        return self._optimize_event_statement(node)

    def visit_event_assignment(self, node: EventAssignment) -> EventAssignment:
        return node

    def _optimize_event_statement(self, stmt: EventStatement) -> EventStatement:
        if not hasattr(stmt, "assignments") or not hasattr(stmt, "event"):
            return stmt
        if not stmt.assignments:
            return stmt

        optimized_assignments = self._reorder_assignments(stmt.assignments)
        optimized_assignments = self._remove_redundant_assignments(optimized_assignments)

        for assignment in optimized_assignments:
            if self._should_index_field(assignment):
                self.indexed_fields.add(self._field_path_to_string(assignment.field_path))
                self.stats.indexes_suggested += 1

        return stmt

    def _reorder_assignments(self, assignments: list[EventAssignment]) -> list[EventAssignment]:
        scored = []
        for assignment in assignments:
            score = self._calculate_selectivity_score(assignment)
            scored.append((score, assignment))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [assignment for _, assignment in scored]

    def _calculate_selectivity_score(self, assignment: EventAssignment) -> float:
        score = 0.0

        if assignment.operator == "=":
            score += 10.0
        elif assignment.operator == "!=":
            score += 8.0
        elif assignment.operator in [">", "<", ">=", "<="]:
            score += 5.0
        elif assignment.operator in ["=~", "!~"]:
            score += 3.0

        field_str = self._field_path_to_string(assignment.field_path)
        field_parts = field_str.split(".")
        if "event_type" in field_str:
            score += 5.0
        elif "hostname" in field_parts or "ip" in field_parts:
            score += 4.0
        elif "user" in field_parts:
            score += 3.0
        elif "timestamp" in field_parts:
            score += 2.0

        if isinstance(assignment.value, str) and not assignment.value.startswith("/"):
            score += 2.0

        return score

    def _remove_redundant_assignments(
        self, assignments: list[EventAssignment]
    ) -> list[EventAssignment]:
        optimized = []
        seen_fields: dict[str, EventAssignment] = {}

        for assignment in assignments:
            field_str = self._field_path_to_string(assignment.field_path)

            if field_str in seen_fields:
                prev_assignment = seen_fields[field_str]
                if self._are_contradictory(prev_assignment, assignment):
                    if self._is_more_restrictive(assignment, prev_assignment):
                        optimized = [a for a in optimized if a != prev_assignment]
                        optimized.append(assignment)
                        seen_fields[field_str] = assignment
                    self.stats.redundant_checks_removed += 1
                elif self._are_redundant(prev_assignment, assignment):
                    self.stats.redundant_checks_removed += 1
                else:
                    optimized.append(assignment)
            else:
                optimized.append(assignment)
                seen_fields[field_str] = assignment

        return optimized

    def _group_event_statements(self, statements: list) -> list[list]:
        groups = []

        for stmt in statements:
            added = False
            for group in groups:
                if self._are_similar_events(stmt, group[0]):
                    group.append(stmt)
                    added = True
                    break

            if not added:
                groups.append([stmt])

        return groups

    def _are_similar_events(self, stmt1: EventStatement, stmt2: EventStatement) -> bool:
        if (
            hasattr(stmt1, "event")
            and hasattr(stmt2, "event")
            and stmt1.event
            and stmt2.event
            and stmt1.event.name != stmt2.event.name
        ):
            return False

        fields1 = set()
        fields2 = set()

        if hasattr(stmt1, "assignments"):
            for assignment in stmt1.assignments:
                fields1.add(self._field_path_to_string(assignment.field_path))

        if hasattr(stmt2, "assignments"):
            for assignment in stmt2.assignments:
                fields2.add(self._field_path_to_string(assignment.field_path))

        overlap = len(fields1 & fields2)
        return overlap > 0 and overlap >= min(len(fields1), len(fields2)) * 0.5

    def _combine_event_statements(self, group: list[EventStatement]) -> EventStatement | None:
        if not group:
            return None

        if len(group) == 1:
            return group[0]

        base = group[0]
        combined_assignments = list(base.assignments) if hasattr(base, "assignments") else []

        seen_fields = set()
        for assignment in combined_assignments:
            seen_fields.add(self._field_path_to_string(assignment.field_path))

        for stmt in group[1:]:
            if hasattr(stmt, "assignments"):
                for assignment in stmt.assignments:
                    field_str = self._field_path_to_string(assignment.field_path)
                    if field_str not in seen_fields:
                        combined_assignments.append(assignment)
                        seen_fields.add(field_str)

        combined_assignments = self._reorder_assignments(combined_assignments)
        combined_assignments = self._remove_redundant_assignments(combined_assignments)

        return LegacyEventStatement(
            event=base.event,
            assignments=combined_assignments,
        )
