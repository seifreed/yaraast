"""Events parsing for Enhanced YARA-L parser."""

from __future__ import annotations

from yaraast.lexer.tokens import TokenType as BaseTokenType
from yaraast.yaral.ast_nodes import (
    EventAssignment,
    EventsSection,
    EventStatement,
    EventVariable,
    JoinCondition,
)
from yaraast.yaral.tokens import YaraLTokenType


class EnhancedYaraLParserEventsMixin:
    """Mixin for events parsing."""

    def _parse_events_section(self) -> EventsSection:
        """Parse enhanced events section with joins and complex conditions."""
        self._consume_keyword("events")
        self._consume(BaseTokenType.COLON, "Expected ':' after 'events'")

        statements = []

        while not self._check_section_keyword() and not self._check(BaseTokenType.RBRACE):
            if self._check_yaral_type(YaraLTokenType.EVENT_VAR):
                stmts = self._parse_event_statement()
                if isinstance(stmts, list):
                    statements.extend(stmts)
            elif self._check_keyword("join"):
                join = self._parse_join_statement()
                statements.append(join)
            else:
                if self._parse_complex_event_pattern() is None:
                    self._advance()

        return EventsSection(statements=statements)

    def _parse_event_statement(self) -> list[EventStatement] | None:
        """Parse enhanced event statement with multiple conditions."""
        event = None
        assignments: list[EventStatement] = []

        if self._check_yaral_type(YaraLTokenType.EVENT_VAR):
            event_token = self._advance()
            event = EventVariable(name=event_token.value)

        while self._check(BaseTokenType.DOT) or (
            self._check(BaseTokenType.IDENTIFIER) and not self._check_section_keyword()
        ):
            if self._check(BaseTokenType.DOT):
                self._advance()

            field_path = self._parse_udm_field_path()
            operator = self._parse_comparison_operator()
            value = self._parse_event_value()

            if event is None:
                break
            assignments.append(
                EventAssignment(
                    event_var=event,
                    field_path=field_path,
                    operator=operator,
                    value=value,
                )
            )

            if self._check_keyword("and"):
                self._advance()
            elif not self._check(BaseTokenType.DOT):
                break

        return assignments or None

    def _parse_join_statement(self) -> JoinCondition:
        """Parse join statement for correlating events."""
        self._consume_keyword("join")

        left_event = self._consume(BaseTokenType.IDENTIFIER, "Expected left event").value

        self._consume_keyword("on")

        self._parse_join_condition()

        self._consume_keyword("with")

        right_event = self._consume(BaseTokenType.IDENTIFIER, "Expected right event").value

        return JoinCondition(left_event=left_event, right_event=right_event)

    def _parse_complex_event_pattern(self) -> EventStatement | None:
        """Parse complex event patterns with temporal operators."""
        if self._check_keyword("all"):
            return self._parse_all_pattern()
        if self._check_keyword("any"):
            return self._parse_any_pattern()
        if self._check(BaseTokenType.IDENTIFIER):
            peek_ahead = self._peek_ahead(1)
            if peek_ahead and peek_ahead.value in ["followed", "before", "after"]:
                return self._parse_temporal_pattern()

        return None

    def _parse_all_pattern(self) -> EventStatement | None:
        """Parse 'all' pattern for events."""
        self._consume_keyword("all")
        return None

    def _parse_any_pattern(self) -> EventStatement | None:
        """Parse 'any' pattern for events."""
        self._consume_keyword("any")
        return None

    def _parse_temporal_pattern(self) -> EventStatement | None:
        """Parse temporal patterns like 'followed by', 'before', 'after'."""
        return None

    def _parse_join_condition(self):
        """Parse join condition for event correlation."""
        return self._parse_condition_expression()
