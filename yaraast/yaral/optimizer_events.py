"""Event optimization mixin for YARA-L optimizer."""

from __future__ import annotations

from yaraast.yaral._optimizer_mixin import OptimizerMixinBase
from yaraast.yaral.ast_nodes import EventAssignment, EventsSection, EventStatement


class YaraLOptimizerEventsMixin(OptimizerMixinBase):
    """Track optimization data for current YARA-L event nodes."""

    def visit_events_section(self, node: EventsSection) -> EventsSection:
        for statement in node.statements:
            if isinstance(statement, EventAssignment):
                self.visit_event_assignment(statement)
        return node

    def visit_event_statement(self, node: EventStatement) -> EventStatement:
        return node

    def visit_event_assignment(self, node: EventAssignment) -> EventAssignment:
        if self._should_index_field(node):
            self.indexed_fields.add(self._field_path_to_string(node.field_path))
            self.stats.indexes_suggested += 1
        return node
