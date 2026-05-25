"""Outcome parsing for Enhanced YARA-L parser."""

from __future__ import annotations

from typing import Any

from yaraast.lexer.tokens import TokenType as BaseTokenType
from yaraast.yaral._shared import parse_numeric_token_value
from yaraast.yaral.ast_nodes import (
    AggregationFunction,
    ConditionalExpression,
    OutcomeAssignment,
    OutcomeExpression,
    OutcomeSection,
)
from yaraast.yaral.tokens import YaraLTokenType

_OUTCOME_FIELD_YARAL_TYPES = {
    YaraLTokenType.METADATA,
    YaraLTokenType.PRINCIPAL,
    YaraLTokenType.TARGET,
    YaraLTokenType.NETWORK,
    YaraLTokenType.SECURITY_RESULT,
    YaraLTokenType.UDM,
    YaraLTokenType.ADDITIONAL,
}

_AGGREGATION_FUNCTIONS = {
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
    "string_concat",
}


class EnhancedYaraLParserOutcomeMixin:
    """Mixin for outcome parsing."""

    def _parse_outcome_section(self) -> OutcomeSection:
        """Parse enhanced outcome section with conditionals."""
        self._consume_keyword("outcome")
        self._consume(BaseTokenType.COLON, "Expected ':' after 'outcome'")

        assignments: list[OutcomeAssignment] = []

        while not self._check_section_keyword() and not self._check(BaseTokenType.RBRACE):
            if self._check_keyword("if"):
                cond_expr = self._parse_conditional_expression()
                assignments.append(
                    OutcomeAssignment(
                        variable="_",
                        expression=cond_expr,
                    ),
                )
            elif self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
                BaseTokenType.STRING_IDENTIFIER,
            ):
                var_name = self._advance().value
                self._consume(BaseTokenType.EQ, "Expected '=' after outcome variable")
                expression = self._parse_outcome_expression()
                assignments.append(
                    OutcomeAssignment(
                        variable=var_name,
                        expression=expression,
                    ),
                )
            else:
                self._advance()

        return OutcomeSection(assignments=assignments)

    def _parse_outcome_expression(self) -> OutcomeExpression | Any:
        """Parse enhanced outcome expression with aggregations."""
        if self._check(BaseTokenType.IDENTIFIER):
            token = self._peek()
            if token.value in _AGGREGATION_FUNCTIONS:
                return self._parse_aggregation_function()

        if self._is_outcome_field_access_start():
            return self._parse_udm_field_access()
        if self._check_yaral_type(YaraLTokenType.EVENT_VAR):
            return self._advance().value

        if self._check(BaseTokenType.STRING):
            return self._advance().value
        if self._check(BaseTokenType.INTEGER) or self._check(BaseTokenType.DOUBLE):
            return parse_numeric_token_value(self._advance().value)

        raise self._error("Expected outcome expression")

    def _is_outcome_field_access_start(self) -> bool:
        if getattr(self._peek(), "yaral_type", None) in _OUTCOME_FIELD_YARAL_TYPES:
            return True
        next_token = self._peek_ahead(1)
        if next_token is None or next_token.type != BaseTokenType.DOT:
            return False
        return self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
            BaseTokenType.IDENTIFIER
        )

    def _parse_aggregation_function(self) -> AggregationFunction:
        """Parse aggregation function."""
        func_name = self._advance().value

        self._consume(BaseTokenType.LPAREN, f"Expected '(' after {func_name}")

        arguments = []
        while not self._check(BaseTokenType.RPAREN):
            if self._is_outcome_field_access_start() or self._check(BaseTokenType.IDENTIFIER):
                arg = self._parse_udm_field_access()
                arguments.append(arg)
            elif self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
                BaseTokenType.STRING
            ):
                arg = self._advance().value
                arguments.append(arg)
            elif self._check(BaseTokenType.INTEGER) or self._check(BaseTokenType.DOUBLE):
                arg = parse_numeric_token_value(self._advance().value)
                arguments.append(arg)

            if self._check(BaseTokenType.COMMA):
                self._advance()
            else:
                break

        self._consume(BaseTokenType.RPAREN, f"Expected ')' after {func_name} arguments")

        return AggregationFunction(function=func_name, arguments=arguments)

    def _parse_conditional_expression(self) -> ConditionalExpression:
        """Parse conditional expression in outcome section."""
        self._consume_keyword("if")

        condition = self._parse_condition_expression()

        self._consume_keyword("then")

        then_expr = self._parse_outcome_expression()

        else_expr = None
        if self._check_keyword("else"):
            self._advance()
            else_expr = self._parse_outcome_expression()

        return ConditionalExpression(
            condition=condition,
            true_value=then_expr,
            false_value=else_expr,
        )
