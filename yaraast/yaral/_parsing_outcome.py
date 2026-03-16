"""Parsing routines for YARA-L rules."""

from __future__ import annotations

from typing import Any

from yaraast.lexer.tokens import TokenType as BaseTokenType

from ._parsing_outcome_args import OutcomeArgumentParsingMixin
from .ast_nodes import (
    AggregationFunction,
    ConditionalExpression,
    OutcomeAssignment,
    OutcomeExpression,
    OutcomeSection,
)
from .tokens import YaraLTokenType


class YaraLOutcomeParsingMixin(OutcomeArgumentParsingMixin):
    """Mixin providing YARA-L parse routines."""

    def _parse_outcome_section(self) -> OutcomeSection:
        """Parse outcome section."""
        self._consume_keyword("outcome")
        self._consume(BaseTokenType.COLON, "Expected ':' after 'outcome'")

        assignments = []

        while not self._check_section_keyword() and not self._check(
            BaseTokenType.RBRACE,
        ):
            # Parse outcome assignment: $var = expression
            if self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
                BaseTokenType.STRING_IDENTIFIER,
            ):
                var_token = self._advance()
                var_name = var_token.value

                self._consume(BaseTokenType.EQ, "Expected '=' after outcome variable")

                expression = self._parse_outcome_arithmetic_expression()

                assignments.append(
                    OutcomeAssignment(variable=var_name, expression=expression),
                )
            else:
                self._advance()

        return OutcomeSection(assignments=assignments)

    def _parse_outcome_expression(self) -> OutcomeExpression:
        """Parse outcome expression."""
        # Check for aggregation functions
        if self._check(BaseTokenType.IDENTIFIER):
            token = self._peek()
            if token.value in [
                "count",
                "count_distinct",
                "sum",
                "min",
                "max",
                "avg",
                "array",
                "array_distinct",
                "earliest",
                "latest",
            ]:
                func_name = self._advance().value
                self._consume(BaseTokenType.LPAREN, f"Expected '(' after {func_name}")

                # Parse arguments
                arguments = []
                if not self._check(BaseTokenType.RPAREN):
                    arguments.append(self._parse_outcome_arithmetic_expression())

                    while self._check(BaseTokenType.COMMA):
                        self._advance()
                        arguments.append(self._parse_outcome_arithmetic_expression())

                self._consume(
                    BaseTokenType.RPAREN,
                    f"Expected ')' after {func_name} arguments",
                )

                return AggregationFunction(function=func_name, arguments=arguments)

        # Check for conditional expression: if(condition, true_val, false_val) or if(condition, true_val)
        if self._check_keyword("if"):
            self._advance()
            self._consume(BaseTokenType.LPAREN, "Expected '(' after 'if'")

            condition = self._parse_outcome_condition()
            self._consume(BaseTokenType.COMMA, "Expected ',' after condition")

            true_value = self._parse_outcome_argument()

            # Check if there's a third argument (false value)
            false_value = None
            if self._check(BaseTokenType.COMMA):
                self._advance()  # Consume comma
                false_value = self._parse_outcome_argument()

            self._consume(BaseTokenType.RPAREN, "Expected ')' after if expression")

            return ConditionalExpression(
                condition=condition,
                true_value=true_value,
                false_value=false_value,
            )

        # Default: parse as simple value
        return self._parse_outcome_argument()

    def _parse_outcome_arithmetic_expression(self) -> Any:
        """Parse arithmetic expression in outcome (handles +, -, *, /)."""
        left = self._parse_outcome_expression()

        # Check for arithmetic operators
        while (
            self._check(BaseTokenType.PLUS)
            or self._check(BaseTokenType.MINUS)
            or self._check(BaseTokenType.MULTIPLY)
            or self._check(BaseTokenType.DIVIDE)
        ):
            operator = self._advance().value
            right = self._parse_outcome_expression()
            # Return as string representation for now
            left = f"{left} {operator} {right}"

        return left

    def _parse_outcome_condition(self) -> Any:
        """Parse logical condition in outcome context (handles and, or, not)."""
        return self._parse_outcome_or_condition()

    def _parse_outcome_or_condition(self) -> Any:
        """Parse OR condition in outcome context."""
        left = self._parse_outcome_and_condition()

        while self._check_keyword("or"):
            self._advance()
            right = self._parse_outcome_and_condition()
            left = f"{left} or {right}"

        return left

    def _parse_outcome_and_condition(self) -> Any:
        """Parse AND condition in outcome context."""
        left = self._parse_outcome_not_condition()

        while self._check_keyword("and"):
            self._advance()
            right = self._parse_outcome_not_condition()
            left = f"{left} and {right}"

        return left

    def _parse_outcome_not_condition(self) -> Any:
        """Parse NOT condition in outcome context."""
        if self._check_keyword("not"):
            self._advance()
            operand = self._parse_outcome_not_condition()
            return f"not {operand}"

        return self._parse_outcome_comparison()

    def _parse_outcome_comparison(self) -> Any:
        """Parse comparison expressions in outcome context."""
        # Parse left-hand side with arithmetic support
        # This handles: $field1 - $field2 > value or function() >= value
        left = self._parse_outcome_arithmetic_term()

        # Check for comparison operators
        if (
            self._check(BaseTokenType.EQ)
            or self._check(BaseTokenType.NEQ)
            or self._check(BaseTokenType.GT)
            or self._check(BaseTokenType.LT)
            or self._check(BaseTokenType.GE)
            or self._check(BaseTokenType.LE)
            or self._check(BaseTokenType.IN)
        ):
            op_token = self._advance()
            op = op_token.value

            # Parse right-hand side with arithmetic support
            right = self._parse_outcome_arithmetic_term()

            # Check for nocase modifier after comparison (especially for regex)
            modifier = ""
            if self._check_keyword("nocase"):
                modifier = " nocase"
                self._advance()

            # Return as string representation
            return f"{left} {op} {right}{modifier}"

        return left

    def _parse_outcome_arithmetic_term(self) -> Any:
        """Parse arithmetic term in outcome condition (handles +, -, *, / for comparisons)."""
        left = self._parse_outcome_primary()

        # Check for arithmetic operators
        while (
            self._check(BaseTokenType.PLUS)
            or self._check(BaseTokenType.MINUS)
            or self._check(BaseTokenType.MULTIPLY)
            or self._check(BaseTokenType.DIVIDE)
        ):
            operator = self._advance().value
            right = self._parse_outcome_primary()
            # Return as string representation
            left = f"{left} {operator} {right}"

        return left

    def _parse_outcome_primary(self) -> Any:
        """Parse primary outcome expression (field, literal, variable, etc.)."""
        # Check for regex pattern
        if self._check(BaseTokenType.REGEX):
            pattern_token = self._advance()
            return f"/{pattern_token.value}/"

        # Delegate to existing argument parsing for other types
        return self._parse_outcome_argument_basic()
