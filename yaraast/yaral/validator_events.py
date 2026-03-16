"""Events section validation mixin for YARA-L."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from yaraast.yaral.ast_nodes import (
        EventAssignment,
        EventsSection,
        EventStatement,
        EventVariable,
        ReferenceList,
        UDMFieldAccess,
        UDMFieldPath,
    )


class EventValidationMixin:
    """Validate events and UDM field paths."""

    def visit_events_section(self, node: EventsSection) -> None:
        """Validate events section."""
        if not node.statements:
            self._add_error(
                "events",
                "Events section cannot be empty",
                "Add at least one event statement",
            )

        for statement in node.statements:
            self.visit(statement)

    def visit_event_statement(self, node: EventStatement) -> None:
        """Validate event statement."""
        event = getattr(node, "event", None)
        if event:
            self.visit(event)

        assignments = getattr(node, "assignments", [])
        if not assignments:
            self._add_warning(
                "events",
                f"Event {event.name if event else 'unknown'} has no field assignments",
                "Add field assignments to constrain the event",
            )

        for assignment in assignments:
            self.visit(assignment)

    def visit_event_variable(self, node: EventVariable) -> None:
        """Validate event variable."""
        if not node.name.startswith("$"):
            self._add_error(
                "events",
                f"Event variable '{node.name}' must start with $",
                "Use format like $e, $e1, $event",
            )

        normalized = node.name.lstrip("$")

        if normalized in self.defined_events:
            self._add_error(
                "events",
                f"Duplicate event variable: {node.name}",
                "Use unique event variable names",
            )

        self.defined_events.add(normalized)

    def visit_event_assignment(self, node: EventAssignment) -> None:
        """Validate event assignment."""
        if hasattr(node, "event_var") and node.event_var:
            self.visit_event_variable(node.event_var)

        if node.field_path:
            self._validate_udm_field_path(node.field_path)

        valid_operators = ["=", "!=", ">", "<", ">=", "<=", "=~", "!~"]
        if node.operator not in valid_operators:
            self._add_error(
                "events",
                f"Invalid operator '{node.operator}' in event assignment",
                f"Use one of: {', '.join(valid_operators)}",
            )

        if node.operator in ["=~", "!~"] and (
            not isinstance(node.value, str)
            or not (node.value.startswith("/") and node.value.endswith("/"))
        ):
            self._add_warning(
                "events",
                f"Regex operator {node.operator} should be used with regex pattern",
                "Use format: /pattern/",
            )

    def _validate_udm_field_path(self, node: UDMFieldPath) -> None:
        """Validate UDM field path."""
        if not node.parts:
            self._add_error("events", "Empty UDM field path")
            return

        parts = node.parts
        if len(parts) == 1 and "." in parts[0]:
            parts = parts[0].split(".")
        namespace = parts[0]
        if namespace not in self.VALID_UDM_FIELDS:
            self._add_warning(
                "events",
                f"Unknown UDM namespace: {namespace}",
                f"Valid namespaces: {', '.join(self.VALID_UDM_FIELDS.keys())}",
            )
        elif len(parts) > 1:
            field = parts[1]
            valid_fields = self.VALID_UDM_FIELDS[namespace]
            if field not in valid_fields:
                self._add_warning(
                    "events",
                    f"Unknown field '{field}' for namespace '{namespace}'",
                    f"Valid fields: {', '.join(valid_fields[:5])}...",
                )

    def visit_yaral_events_section(self, node: EventsSection) -> None:
        self.visit_events_section(node)

    def visit_yaral_event_statement(self, node: EventStatement) -> None:
        self.visit_event_statement(node)

    def visit_yaral_event_assignment(self, node: EventAssignment) -> None:
        self.visit_event_assignment(node)

    def visit_yaral_event_variable(self, node: EventVariable) -> None:
        self.visit_event_variable(node)

    def visit_yaral_udm_field_path(self, node: UDMFieldPath) -> None:
        self._validate_udm_field_path(node)

    def visit_yaral_udm_field_access(self, node: UDMFieldAccess) -> None:
        self._validate_udm_field_path(node.field)

    def visit_yaral_reference_list(self, node: ReferenceList) -> None:
        return
