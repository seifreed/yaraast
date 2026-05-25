"""Events parsing for Enhanced YARA-L parser."""

from __future__ import annotations

from typing import Any

from yaraast.lexer.tokens import TokenType as BaseTokenType
from yaraast.yaral._parsing_events import (
    _RAW_EVENT_MODULES,
    _join_event_statement_tokens,
    _join_prefixed_event_statement,
    _prefix_event_statement,
)
from yaraast.yaral.ast_nodes import (
    ConditionExpression,
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
            elif (
                self._check(BaseTokenType.INTEGER)
                or self._check(BaseTokenType.DOUBLE)
                or self._check(BaseTokenType.LPAREN)
                or self._is_raw_event_statement_start()
            ):
                raw_statement = self._parse_raw_event_statement()
                if raw_statement is not None:
                    statements.append(raw_statement)
            else:
                complex_pattern = self._parse_complex_event_pattern()
                if complex_pattern is None:
                    self._advance()
                else:
                    statements.append(complex_pattern)

        return EventsSection(statements=statements)

    def _is_raw_event_statement_start(self) -> bool:
        if not self._check(BaseTokenType.IDENTIFIER):
            return False
        identifier = str(self._peek().value)
        return identifier in _RAW_EVENT_MODULES or (
            "." in identifier and identifier.split(".", 1)[0] in _RAW_EVENT_MODULES
        )

    def _parse_raw_event_statement(self) -> EventStatement | None:
        tokens = []
        start_line = self._peek().line if not self._is_at_end() else -1
        paren_depth = 0
        while not self._is_at_end():
            if paren_depth == 0 and (
                self._check_section_keyword() or self._check(BaseTokenType.RBRACE)
            ):
                break
            if self._is_raw_event_statement_boundary(start_line, paren_depth, tokens):
                break

            token = self._peek()
            if token.type == BaseTokenType.LPAREN:
                paren_depth += 1
            elif token.type == BaseTokenType.RPAREN and paren_depth > 0:
                paren_depth -= 1
            tokens.append(self._advance())

        if not tokens:
            return None
        return EventStatement(text=_join_event_statement_tokens(tokens))

    def _is_raw_event_statement_boundary(
        self,
        start_line: int,
        paren_depth: int,
        tokens: list[Any],
    ) -> bool:
        if paren_depth > 0 or not tokens:
            return False

        current_token = self._peek()
        if current_token.line <= start_line or self._previous_token_continues_statement(tokens):
            return False

        if (
            self._check_keyword("join")
            or self._is_raw_event_statement_start()
            or self._is_complex_event_pattern_start()
        ):
            return True

        if self._check(BaseTokenType.INTEGER) or self._check(BaseTokenType.DOUBLE):
            return True

        if self._check(BaseTokenType.LPAREN):
            return True

        if self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
            BaseTokenType.STRING_IDENTIFIER
        ):
            next_token = self._peek_ahead(1)
            return bool(
                next_token
                and next_token.type
                in {
                    BaseTokenType.DOT,
                    BaseTokenType.EQ,
                    BaseTokenType.NEQ,
                    BaseTokenType.GT,
                    BaseTokenType.LT,
                    BaseTokenType.GE,
                    BaseTokenType.LE,
                    BaseTokenType.IN,
                }
            )

        return False

    @staticmethod
    def _previous_token_continues_statement(tokens: list[Any]) -> bool:
        return tokens[-1].type in {
            BaseTokenType.COMMA,
            BaseTokenType.DOT,
            BaseTokenType.EQ,
            BaseTokenType.NEQ,
            BaseTokenType.GT,
            BaseTokenType.LT,
            BaseTokenType.GE,
            BaseTokenType.LE,
            BaseTokenType.IN,
            BaseTokenType.LPAREN,
        }

    def _is_event_var_comparison_start(self) -> bool:
        return (
            self._check(BaseTokenType.NEQ)
            or self._check(BaseTokenType.GT)
            or self._check(BaseTokenType.LT)
            or self._check(BaseTokenType.GE)
            or self._check(BaseTokenType.LE)
            or self._check(BaseTokenType.IN)
            or self._check_keyword("in")
        )

    def _collect_assignment_rhs_tokens(self) -> list[Any]:
        tokens = []
        start_line = self._peek().line if not self._is_at_end() else -1
        while not self._is_at_end():
            current_token = self._peek()
            if self._check_section_keyword() or self._check(BaseTokenType.RBRACE):
                break

            if current_token.line > start_line and (
                self._check_yaral_type(YaraLTokenType.EVENT_VAR)
                or self._check(BaseTokenType.STRING_IDENTIFIER)
            ):
                next_token = self._peek_ahead(1)
                if next_token and next_token.type in {BaseTokenType.EQ, BaseTokenType.DOT}:
                    break

            tokens.append(self._advance())
        return tokens

    def _parse_event_statement(self) -> list[EventStatement] | None:
        """Parse enhanced event statement with multiple conditions."""
        event = None
        assignments: list[EventStatement] = []

        if self._check_yaral_type(YaraLTokenType.EVENT_VAR):
            event_token = self._advance()
            event = EventVariable(name=event_token.value)
            if self._check(BaseTokenType.EQ):
                self._advance()
                if self._is_raw_event_statement_start():
                    raw_statement = self._parse_raw_event_statement()
                    if raw_statement is not None:
                        return [_prefix_event_statement(f"{event.name} =", raw_statement)]
                return [
                    EventStatement(
                        text=_join_prefixed_event_statement(
                            f"{event.name} =",
                            self._collect_assignment_rhs_tokens(),
                        )
                    )
                ]
            if self._is_event_var_comparison_start():
                return [
                    EventStatement(
                        text=_join_prefixed_event_statement(
                            event.name,
                            self._collect_assignment_rhs_tokens(),
                        )
                    )
                ]

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
        if not self._is_complex_event_pattern_start():
            return None
        if self._check_keyword("all"):
            return self._parse_all_pattern()
        if self._check_keyword("any"):
            return self._parse_any_pattern()
        return self._parse_temporal_pattern()

    def _is_complex_event_pattern_start(self) -> bool:
        if self._check_keyword("all") or self._check_keyword("any"):
            return True
        if not self._check(BaseTokenType.IDENTIFIER):
            return False
        peek_ahead = self._peek_ahead(1)
        return bool(peek_ahead and peek_ahead.value in ["followed", "before", "after"])

    def _parse_all_pattern(self) -> EventStatement | None:
        """Parse 'all' pattern for events."""
        return self._parse_raw_event_statement()

    def _parse_any_pattern(self) -> EventStatement | None:
        """Parse 'any' pattern for events."""
        return self._parse_raw_event_statement()

    def _parse_temporal_pattern(self) -> EventStatement | None:
        """Parse temporal patterns like 'followed by', 'before', 'after'."""
        return self._parse_raw_event_statement()

    def _parse_join_condition(self) -> ConditionExpression:
        """Parse join condition for event correlation."""
        return self._parse_condition_expression()
