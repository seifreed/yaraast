"""Parsing routines for YARA-L rules."""

from __future__ import annotations

from yaraast.lexer.tokens import TokenType as BaseTokenType

from ._shared import YaraLParserError
from .ast_nodes import (
    BinaryCondition,
    ConditionExpression,
    ConditionSection,
    EventCountCondition,
    EventExistsCondition,
    UnaryCondition,
    VariableComparisonCondition,
)
from .tokens import YaraLTokenType


class YaraLConditionParsingMixin:
    """Mixin providing YARA-L parse routines."""

    def _parse_condition_section(self) -> ConditionSection:
        """Parse condition section."""
        self._consume_keyword("condition")
        self._consume(BaseTokenType.COLON, "Expected ':' after 'condition'")

        expression = self._parse_condition_expression()

        return ConditionSection(expression=expression)

    def _parse_condition_expression(self) -> ConditionExpression:
        """Parse condition expression."""
        return self._parse_or_condition()

    def _parse_or_condition(self) -> ConditionExpression:
        """Parse OR condition."""
        left = self._parse_and_condition()

        while self._check_keyword("or"):
            self._advance()
            right = self._parse_and_condition()
            left = BinaryCondition(operator="or", left=left, right=right)

        return left

    def _parse_and_condition(self) -> ConditionExpression:
        """Parse AND condition."""
        left = self._parse_unary_condition()

        while self._check_keyword("and"):
            self._advance()
            right = self._parse_unary_condition()
            left = BinaryCondition(operator="and", left=left, right=right)

        return left

    def _parse_unary_condition(self) -> ConditionExpression:
        """Parse unary condition."""
        if self._check_keyword("not"):
            self._advance()
            operand = self._parse_unary_condition()
            return UnaryCondition(operator="not", operand=operand)

        return self._parse_primary_condition()

    def _parse_primary_condition(self) -> ConditionExpression:
        """Parse primary condition."""
        # Parenthesized expression
        if self._check(BaseTokenType.LPAREN):
            return self._parse_parenthesized_condition()

        # Event count: #e > 5
        if self._check(BaseTokenType.STRING_COUNT):
            return self._parse_event_count_condition()

        # Variable or event reference: $var or $e1
        if self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
            BaseTokenType.STRING_IDENTIFIER
        ):
            return self._parse_variable_condition()

        # Fallback: treat as exists condition
        if self._check(BaseTokenType.IDENTIFIER):
            return self._parse_identifier_condition()

        msg = f"Unexpected token in condition: {self._peek()}"
        raise YaraLParserError(
            msg,
            self._peek(),
        )

    def _parse_parenthesized_condition(self) -> ConditionExpression:
        """Parse a parenthesized condition expression."""
        self._advance()
        expr = self._parse_condition_expression()
        self._consume(BaseTokenType.RPAREN, "Expected ')' after expression")
        return expr

    def _parse_event_count_condition(self) -> EventCountCondition:
        """Parse an event count condition: #e > 5."""
        self._advance()
        event_name = self._consume(
            BaseTokenType.IDENTIFIER,
            "Expected event name after '#'",
        ).value

        operator = self._consume_comparison_operator()
        count = int(
            self._consume(
                BaseTokenType.INTEGER,
                "Expected number after operator",
            ).value,
        )

        return EventCountCondition(event=event_name, operator=operator, count=count)

    def _consume_comparison_operator(self) -> str:
        """Consume and return a comparison operator token."""
        operator_map = {
            BaseTokenType.GT: ">",
            BaseTokenType.LT: "<",
            BaseTokenType.GE: ">=",
            BaseTokenType.LE: "<=",
            BaseTokenType.EQ: "==",
            BaseTokenType.NEQ: "!=",
        }
        for token_type, op in operator_map.items():
            if self._check(token_type):
                self._advance()
                return op

        msg = "Expected comparison operator"
        raise YaraLParserError(msg, self._peek())

    def _parse_comparison_value(self):
        """Parse the value on the right side of a comparison."""
        if self._check(BaseTokenType.INTEGER):
            return int(self._advance().value)
        if (
            self._check(BaseTokenType.STRING)
            or self._check_yaral_type(YaraLTokenType.EVENT_VAR)
            or self._check(BaseTokenType.STRING_IDENTIFIER)
            or self._check(BaseTokenType.IDENTIFIER)
        ):
            return self._advance().value

        msg = "Expected value after comparison operator"
        raise YaraLParserError(msg, self._peek())

    def _check_comparison_operator(self) -> bool:
        """Check if the current token is a comparison operator."""
        return (
            self._check(BaseTokenType.GT)
            or self._check(BaseTokenType.LT)
            or self._check(BaseTokenType.GE)
            or self._check(BaseTokenType.LE)
            or self._check(BaseTokenType.EQ)
            or self._check(BaseTokenType.NEQ)
        )

    def _parse_variable_condition(self) -> ConditionExpression:
        """Parse a condition starting with a variable ($var or $e1)."""
        var_token = self._advance()
        var_name = var_token.value

        # Check if followed by comparison operator
        if self._check_comparison_operator():
            operator = self._consume_comparison_operator()
            value = self._parse_comparison_value()
            return VariableComparisonCondition(variable=var_name, operator=operator, value=value)

        # Just a variable reference (event exists)
        event_name = var_name.lstrip("$")
        return EventExistsCondition(event=event_name)

    def _parse_identifier_condition(self) -> ConditionExpression:
        """Parse a condition starting with an identifier."""
        name = self._advance().value

        # Check if followed by comparison operator
        if self._check_comparison_operator():
            operator = self._consume_comparison_operator()
            value = self._parse_comparison_value()
            return VariableComparisonCondition(variable=name, operator=operator, value=value)

        return EventExistsCondition(event=name)
