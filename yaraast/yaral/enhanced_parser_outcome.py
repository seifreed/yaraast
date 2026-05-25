"""Outcome parsing for Enhanced YARA-L parser."""

from __future__ import annotations

from typing import Any

from yaraast.lexer.tokens import TokenType as BaseTokenType
from yaraast.yaral._shared import parse_numeric_token_value
from yaraast.yaral.ast_nodes import (
    AggregationFunction,
    ArithmeticExpression,
    ConditionalExpression,
    FunctionCall,
    OutcomeAssignment,
    OutcomeExpression,
    OutcomeSection,
    RawOutcomeExpression,
    UDMFieldAccess,
)
from yaraast.yaral.generator_helpers import format_literal
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
        left = self._parse_outcome_additive_expression()
        if not self._check_outcome_comparison_operator():
            return left

        operator = self._parse_comparison_operator()
        right = self._parse_event_value()
        return RawOutcomeExpression(
            f"{self._format_outcome_expression_text(left)} {operator} "
            f"{self._format_event_value_text(right)}"
        )

    def _check_outcome_comparison_operator(self) -> bool:
        if (
            self._check(BaseTokenType.EQ)
            or self._check(BaseTokenType.IEQUALS)
            or self._check(BaseTokenType.NEQ)
            or self._check(BaseTokenType.GT)
            or self._check(BaseTokenType.LT)
            or self._check(BaseTokenType.GE)
            or self._check(BaseTokenType.LE)
            or self._check(BaseTokenType.MATCHES)
            or self._check(BaseTokenType.IN)
            or self._check_keyword("matches")
            or self._check_keyword("in")
        ):
            return True
        next_token = self._peek_ahead(1)
        return bool(
            self._check_keyword("not")
            and next_token is not None
            and next_token.value in {"matches", "in"}
        )

    def _format_outcome_expression_text(self, value: Any) -> str:
        if isinstance(value, RawOutcomeExpression):
            return str(value)
        if isinstance(value, ArithmeticExpression):
            left = self._format_outcome_expression_text(value.left)
            right = self._format_outcome_expression_text(value.right)
            return f"{left} {value.operator} {right}"
        if isinstance(value, AggregationFunction):
            args = ", ".join(self._format_outcome_expression_text(arg) for arg in value.arguments)
            return f"{value.function}({args})"
        if isinstance(value, FunctionCall):
            args = ", ".join(self._format_outcome_expression_text(arg) for arg in value.arguments)
            return f"{value.function}({args})"
        if isinstance(value, ConditionalExpression):
            condition = self._format_condition_expression_text(value.condition)
            true_value = self._format_outcome_expression_text(value.true_value)
            if value.false_value is None:
                return f"if({condition}, {true_value})"
            false_value = self._format_outcome_expression_text(value.false_value)
            return f"if({condition}, {true_value}, {false_value})"
        if isinstance(value, UDMFieldAccess):
            return value.full_path
        return format_literal(value)

    def _parse_outcome_additive_expression(self) -> OutcomeExpression | Any:
        left = self._parse_outcome_multiplicative_expression()

        while self._check(BaseTokenType.PLUS) or self._check(BaseTokenType.MINUS):
            operator = self._advance().value
            right = self._parse_outcome_multiplicative_expression()
            left = ArithmeticExpression(operator=operator, left=left, right=right)

        return left

    def _parse_outcome_multiplicative_expression(self) -> OutcomeExpression | Any:
        left = self._parse_outcome_primary_expression()

        while self._check(BaseTokenType.MULTIPLY) or self._check(BaseTokenType.DIVIDE):
            operator = self._advance().value
            right = self._parse_outcome_primary_expression()
            left = ArithmeticExpression(operator=operator, left=left, right=right)

        return left

    def _parse_outcome_primary_expression(self) -> OutcomeExpression | Any:
        """Parse a primary enhanced outcome expression."""
        if self._check(BaseTokenType.LPAREN):
            self._advance()
            expression = self._parse_outcome_expression()
            self._consume(BaseTokenType.RPAREN, "Expected ')' after expression")
            return expression

        if self._check_keyword("if"):
            return self._parse_conditional_expression()

        if self._check(BaseTokenType.IDENTIFIER):
            token = self._peek()
            next_token = self._peek_ahead(1)
            if next_token is not None and next_token.type == BaseTokenType.LPAREN:
                if token.value in _AGGREGATION_FUNCTIONS:
                    return self._parse_aggregation_function()
                return self._parse_outcome_function_call()
            if token.value in _AGGREGATION_FUNCTIONS:
                return self._parse_aggregation_function()

        if self._is_outcome_field_access_start():
            return self._parse_udm_field_access()
        if self._check_yaral_type(YaraLTokenType.EVENT_VAR):
            return self._advance().value

        if self._check(BaseTokenType.STRING):
            return self._advance().value
        if self._check(BaseTokenType.BOOLEAN_TRUE):
            self._advance()
            return True
        if self._check(BaseTokenType.BOOLEAN_FALSE):
            self._advance()
            return False
        if self._check(BaseTokenType.INTEGER) or self._check(BaseTokenType.DOUBLE):
            return parse_numeric_token_value(self._advance().value)
        if self._check(BaseTokenType.REGEX) or self._check(BaseTokenType.DIVIDE):
            return self._parse_regex_pattern()
        if self._check(BaseTokenType.IDENTIFIER):
            return RawOutcomeExpression(str(self._advance().value))

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
        if not self._check(BaseTokenType.RPAREN):
            arguments.append(self._parse_outcome_expression())
            while self._check(BaseTokenType.COMMA):
                self._advance()
                arguments.append(self._parse_outcome_expression())

        self._consume(BaseTokenType.RPAREN, f"Expected ')' after {func_name} arguments")

        return AggregationFunction(function=func_name, arguments=arguments)

    def _parse_outcome_function_call(self) -> FunctionCall:
        """Parse a generic outcome function call."""
        func_name = str(self._advance().value)

        self._consume(BaseTokenType.LPAREN, f"Expected '(' after {func_name}")

        arguments = []
        if not self._check(BaseTokenType.RPAREN):
            arguments.append(self._parse_outcome_expression())
            while self._check(BaseTokenType.COMMA):
                self._advance()
                arguments.append(self._parse_outcome_expression())

        self._consume(BaseTokenType.RPAREN, f"Expected ')' after {func_name} arguments")

        return FunctionCall(function=func_name, arguments=arguments)

    def _parse_conditional_expression(self) -> ConditionalExpression:
        """Parse conditional expression in outcome section."""
        self._consume_keyword("if")

        if self._check(BaseTokenType.LPAREN):
            self._advance()
            condition = self._parse_condition_expression()
            self._consume(BaseTokenType.COMMA, "Expected ',' after condition")
            then_expr = self._parse_outcome_expression()

            else_expr = None
            if self._check(BaseTokenType.COMMA):
                self._advance()
                else_expr = self._parse_outcome_expression()

            self._consume(BaseTokenType.RPAREN, "Expected ')' after if expression")
            return ConditionalExpression(
                condition=condition,
                true_value=then_expr,
                false_value=else_expr,
            )

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
