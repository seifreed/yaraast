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
            self._advance()
            expr = self._parse_condition_expression()
            self._consume(BaseTokenType.RPAREN, "Expected ')' after expression")
            return expr

        # Event count: #e > 5
        if self._check(BaseTokenType.STRING_COUNT):
            self._advance()
            event_name = self._consume(
                BaseTokenType.IDENTIFIER,
                "Expected event name after '#'",
            ).value

            # Parse comparison operator
            operator = None
            if self._check(BaseTokenType.GT):
                operator = ">"
                self._advance()
            elif self._check(BaseTokenType.LT):
                operator = "<"
                self._advance()
            elif self._check(BaseTokenType.GE):
                operator = ">="
                self._advance()
            elif self._check(BaseTokenType.LE):
                operator = "<="
                self._advance()
            elif self._check(BaseTokenType.EQ):
                operator = "=="
                self._advance()
            elif self._check(BaseTokenType.NEQ):
                operator = "!="
                self._advance()
            else:
                msg = "Expected comparison operator"
                raise YaraLParserError(msg, self._peek())

            count = int(
                self._consume(
                    BaseTokenType.INTEGER,
                    "Expected number after operator",
                ).value,
            )

            return EventCountCondition(event=event_name, operator=operator, count=count)

        # Variable or event reference: $var or $e1
        if self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
            BaseTokenType.STRING_IDENTIFIER
        ):
            var_token = self._advance()
            var_name = var_token.value

            # Check if followed by comparison operator
            if (
                self._check(BaseTokenType.GT)
                or self._check(BaseTokenType.LT)
                or self._check(BaseTokenType.GE)
                or self._check(BaseTokenType.LE)
                or self._check(BaseTokenType.EQ)
                or self._check(BaseTokenType.NEQ)
            ):

                # Parse comparison operator
                operator = None
                if self._check(BaseTokenType.GT):
                    operator = ">"
                    self._advance()
                elif self._check(BaseTokenType.LT):
                    operator = "<"
                    self._advance()
                elif self._check(BaseTokenType.GE):
                    operator = ">="
                    self._advance()
                elif self._check(BaseTokenType.LE):
                    operator = "<="
                    self._advance()
                elif self._check(BaseTokenType.EQ):
                    operator = "=="
                    self._advance()
                elif self._check(BaseTokenType.NEQ):
                    operator = "!="
                    self._advance()

                # Parse comparison value
                value = None
                if self._check(BaseTokenType.INTEGER):
                    value = int(self._advance().value)
                elif (
                    self._check(BaseTokenType.STRING)
                    or self._check_yaral_type(YaraLTokenType.EVENT_VAR)
                    or self._check(BaseTokenType.STRING_IDENTIFIER)
                    or self._check(BaseTokenType.IDENTIFIER)
                ):
                    value = self._advance().value
                else:
                    msg = "Expected value after comparison operator"
                    raise YaraLParserError(msg, self._peek())

                return VariableComparisonCondition(
                    variable=var_name, operator=operator, value=value
                )
            # Just a variable reference (event exists)
            event_name = var_name.lstrip("$")
            return EventExistsCondition(event=event_name)

        # Fallback: treat as exists condition
        if self._check(BaseTokenType.IDENTIFIER):
            name = self._advance().value

            # Check if followed by comparison operator
            if (
                self._check(BaseTokenType.GT)
                or self._check(BaseTokenType.LT)
                or self._check(BaseTokenType.GE)
                or self._check(BaseTokenType.LE)
                or self._check(BaseTokenType.EQ)
                or self._check(BaseTokenType.NEQ)
            ):

                # Parse comparison operator
                operator = None
                if self._check(BaseTokenType.GT):
                    operator = ">"
                    self._advance()
                elif self._check(BaseTokenType.LT):
                    operator = "<"
                    self._advance()
                elif self._check(BaseTokenType.GE):
                    operator = ">="
                    self._advance()
                elif self._check(BaseTokenType.LE):
                    operator = "<="
                    self._advance()
                elif self._check(BaseTokenType.EQ):
                    operator = "=="
                    self._advance()
                elif self._check(BaseTokenType.NEQ):
                    operator = "!="
                    self._advance()

                # Parse comparison value
                value = None
                if self._check(BaseTokenType.INTEGER):
                    value = int(self._advance().value)
                elif (
                    self._check(BaseTokenType.STRING)
                    or self._check_yaral_type(YaraLTokenType.EVENT_VAR)
                    or self._check(BaseTokenType.STRING_IDENTIFIER)
                    or self._check(BaseTokenType.IDENTIFIER)
                ):
                    value = self._advance().value
                else:
                    msg = "Expected value after comparison operator"
                    raise YaraLParserError(msg, self._peek())

                return VariableComparisonCondition(variable=name, operator=operator, value=value)
            return EventExistsCondition(event=name)

        msg = f"Unexpected token in condition: {self._peek()}"
        raise YaraLParserError(
            msg,
            self._peek(),
        )
