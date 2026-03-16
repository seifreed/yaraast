"""Condition parsing for Enhanced YARA-L parser."""

from __future__ import annotations

from yaraast.lexer.tokens import TokenType as BaseTokenType
from yaraast.yaral.ast_nodes import (
    BinaryCondition,
    ConditionExpression,
    ConditionSection,
    EventCountCondition,
    EventExistsCondition,
    ReferenceList,
    UnaryCondition,
)
from yaraast.yaral.tokens import YaraLTokenType


class EnhancedYaraLParserConditionsMixin:
    """Mixin for condition parsing."""

    def _parse_condition_section(self) -> ConditionSection:
        """Parse enhanced condition section with complex logic."""
        self._consume_keyword("condition")
        self._consume(BaseTokenType.COLON, "Expected ':' after 'condition'")

        expression = self._parse_condition_expression()
        return ConditionSection(expression=expression)

    def _parse_condition_expression(self) -> ConditionExpression:
        """Parse complex condition expressions with full boolean logic."""
        return self._parse_or_condition()

    def _parse_or_condition(self) -> ConditionExpression:
        """Parse OR conditions."""
        left = self._parse_and_condition()

        while self._check_keyword("or"):
            self._advance()
            right = self._parse_and_condition()
            left = BinaryCondition(left=left, operator="or", right=right)

        return left

    def _parse_and_condition(self) -> ConditionExpression:
        """Parse AND conditions."""
        left = self._parse_not_condition()

        while self._check_keyword("and"):
            self._advance()
            right = self._parse_not_condition()
            left = BinaryCondition(left=left, operator="and", right=right)

        return left

    def _parse_not_condition(self) -> ConditionExpression:
        """Parse NOT conditions."""
        if self._check_keyword("not"):
            self._advance()
            operand = self._parse_not_condition()
            return UnaryCondition(operator="not", operand=operand)

        return self._parse_primary_condition()

    def _parse_primary_condition(self) -> ConditionExpression:
        """Parse primary condition expressions."""
        if self._check(BaseTokenType.LPAREN):
            self._advance()
            expr = self._parse_condition_expression()
            self._consume(BaseTokenType.RPAREN, "Expected ')' after expression")
            return expr

        if self._check(BaseTokenType.STRING_COUNT):
            return self._parse_event_count_condition()

        # N of ($e1, $e2, ...) syntax
        if self._check(BaseTokenType.INTEGER):
            saved = self.current
            count_val = int(self._advance().value)
            if self._check_keyword("of"):
                self._advance()
                return self._parse_n_of_condition(count_val)
            self.current = saved

        if self._check_yaral_type(YaraLTokenType.EVENT_VAR):
            event_name = self._advance().value
            # Check for 'is null' / 'is not null' after event variable
            if self._check_yaral_type(YaraLTokenType.IS):
                return self._parse_null_check(event_name)
            return EventExistsCondition(event=event_name)

        if self._check(BaseTokenType.IDENTIFIER):
            return self._parse_field_comparison()

        raise self._error("Expected condition expression")

    def _parse_n_of_condition(self, count: int) -> ConditionExpression:
        """Parse N of ($e1, $e2, $e3) quantified event matching."""
        from yaraast.yaral.ast_nodes import NOfCondition

        events = []
        if self._match(BaseTokenType.LPAREN):
            while not self._check(BaseTokenType.RPAREN) and not self._is_at_end():
                if self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
                    BaseTokenType.STRING_IDENTIFIER
                ):
                    events.append(self._advance().value)
                else:
                    self._advance()
                if not self._match(BaseTokenType.COMMA):
                    break
            self._consume(BaseTokenType.RPAREN, "Expected ')' after event list")
        return NOfCondition(count=count, events=events)

    def _parse_null_check(self, field_name: str) -> ConditionExpression:
        """Parse 'is null' or 'is not null' condition."""
        from yaraast.yaral.ast_nodes import NullCheckCondition

        self._advance()  # consume 'is'
        negated = False
        if self._check_keyword("not"):
            self._advance()
            negated = True
        if self._check_yaral_type(YaraLTokenType.NULL):
            self._advance()
        return NullCheckCondition(field=field_name, negated=negated)

    def _parse_event_count_condition(self) -> EventCountCondition:
        """Parse event count condition like #e > 5."""
        self._consume(BaseTokenType.STRING_COUNT, "Expected '#'")

        event_name = self._consume(BaseTokenType.IDENTIFIER, "Expected event name").value
        operator = self._parse_numeric_comparison_operator()
        count = int(self._consume(BaseTokenType.INTEGER, "Expected count").value)

        return EventCountCondition(event=event_name, operator=operator, count=count)

    def _parse_numeric_comparison_operator(self) -> str:
        """Parse only numeric comparison operators (no regex/string operators)."""
        if self._check(BaseTokenType.EQ):
            self._advance()
            return "="
        if self._check(BaseTokenType.NEQ):
            self._advance()
            return "!="
        if self._check(BaseTokenType.GT):
            self._advance()
            return ">"
        if self._check(BaseTokenType.LT):
            self._advance()
            return "<"
        if self._check(BaseTokenType.GE):
            self._advance()
            return ">="
        if self._check(BaseTokenType.LE):
            self._advance()
            return "<="
        raise self._error("Expected numeric comparison operator (>, <, >=, <=, =, !=)")

    def _parse_field_comparison(self) -> ConditionExpression:
        """Parse field comparison condition."""
        field = self._parse_udm_field_access()
        operator = self._parse_comparison_operator()
        value = self._parse_event_value()

        return BinaryCondition(left=field, operator=operator, right=value)

    def _parse_reference_check(self) -> ConditionExpression:
        """Parse reference list check like: ip in %suspicious_ips."""
        field = self._parse_udm_field_access()

        self._consume_keyword("in")

        if not self._check_yaral_type(YaraLTokenType.REFERENCE_LIST):
            raise self._error("Expected reference list")

        list_name = self._advance().value.strip("%")
        ref_list = ReferenceList(name=list_name)
        return BinaryCondition(left=field, operator="in", right=ref_list)
