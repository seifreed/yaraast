"""Expression parsing helpers for logical/arithmetic operators."""

from __future__ import annotations

from yaraast.ast.conditions import AtExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    Expression,
    ParenthesesExpression,
    RangeExpression,
    StringIdentifier,
    UnaryExpression,
)
from yaraast.ast.operators import DefinedExpression
from yaraast.lexer import TokenType

from ._shared import ParserError

RELATIONAL_TOKEN_TYPES = (
    TokenType.LT,
    TokenType.LE,
    TokenType.GT,
    TokenType.GE,
    TokenType.EQ,
    TokenType.NEQ,
    TokenType.CONTAINS,
    TokenType.MATCHES,
    TokenType.STARTSWITH,
    TokenType.ENDSWITH,
    TokenType.ICONTAINS,
    TokenType.ISTARTSWITH,
    TokenType.IENDSWITH,
    TokenType.IEQUALS,
)


class ExpressionBinaryMixin:
    """Mixin with logical/arithmetic expression parsing."""

    def _parse_or_expression(self) -> Expression:
        """Parse OR expression."""
        expr = self._parse_and_expression()

        while self._match(TokenType.OR):
            operator = "or"
            right = self._parse_and_expression()
            expr = self._set_node_location_from_nodes(
                BinaryExpression(left=expr, operator=operator, right=right),
                expr,
                right,
            )

        return expr

    def _parse_and_expression(self) -> Expression:
        """Parse AND expression."""
        expr = self._parse_not_expression()

        while self._match(TokenType.AND):
            operator = "and"
            right = self._parse_not_expression()
            expr = self._set_node_location_from_nodes(
                BinaryExpression(left=expr, operator=operator, right=right),
                expr,
                right,
            )

        return expr

    def _parse_not_expression(self) -> Expression:
        """Parse NOT expression."""
        if self._match(TokenType.NOT):
            start_token = self._previous()
            operand = self._parse_not_expression()
            return self._set_node_location_from_tokens(
                UnaryExpression(operator="not", operand=operand), start_token, self._previous()
            )

        return self._parse_relational_expression()

    def _parse_relational_expression(self) -> Expression:
        """Parse relational expression."""
        expr = self._parse_range_expression()

        if self._match(*RELATIONAL_TOKEN_TYPES):
            operator_token = self._previous()
            operator = operator_token.value.lower()
            right = self._parse_range_expression()
            self._reject_string_identifier_non_logical_operand(expr, right, operator_token)
            expr = self._set_node_location_from_nodes(
                BinaryExpression(left=expr, operator=operator, right=right),
                expr,
                right,
            )
            if self._check_any(*RELATIONAL_TOKEN_TYPES):
                msg = "Unexpected relational operator"
                raise ParserError(msg, self._peek())

        return expr

    def _parse_range_expression(self) -> Expression:
        """Parse range expression (a..b)."""
        expr = self._parse_bitwise_or_expression()

        if self._match(TokenType.DOUBLE_DOT):
            if not getattr(self, "_allow_range_expression", False):
                msg = "Unexpected range expression"
                raise ParserError(msg, self._previous())
            high = self._parse_bitwise_or_expression()
            expr = self._set_node_location_from_nodes(
                RangeExpression(low=expr, high=high), expr, high
            )

        return expr

    def _parse_bitwise_or_expression(self) -> Expression:
        """Parse bitwise OR expression."""
        expr = self._parse_bitwise_xor_expression()

        while self._match(TokenType.BITWISE_OR):
            operator_token = self._previous()
            operator = operator_token.value
            right = self._parse_bitwise_xor_expression()
            self._reject_string_identifier_non_logical_operand(expr, right, operator_token)
            expr = self._set_node_location_from_nodes(
                BinaryExpression(left=expr, operator=operator, right=right),
                expr,
                right,
            )

        return expr

    def _parse_bitwise_xor_expression(self) -> Expression:
        """Parse bitwise XOR expression."""
        expr = self._parse_bitwise_and_expression()

        while self._match(TokenType.XOR):
            operator_token = self._previous()
            operator = operator_token.value
            right = self._parse_bitwise_and_expression()
            self._reject_string_identifier_non_logical_operand(expr, right, operator_token)
            expr = self._set_node_location_from_nodes(
                BinaryExpression(left=expr, operator=operator, right=right),
                expr,
                right,
            )

        return expr

    def _parse_bitwise_and_expression(self) -> Expression:
        """Parse bitwise AND expression."""
        expr = self._parse_shift_expression()

        while self._match(TokenType.BITWISE_AND):
            operator_token = self._previous()
            operator = operator_token.value
            right = self._parse_shift_expression()
            self._reject_string_identifier_non_logical_operand(expr, right, operator_token)
            expr = self._set_node_location_from_nodes(
                BinaryExpression(left=expr, operator=operator, right=right),
                expr,
                right,
            )

        return expr

    def _parse_shift_expression(self) -> Expression:
        """Parse shift expression."""
        expr = self._parse_additive_expression()

        while self._match(TokenType.SHIFT_LEFT, TokenType.SHIFT_RIGHT):
            operator_token = self._previous()
            operator = operator_token.value
            right = self._parse_additive_expression()
            self._reject_string_identifier_non_logical_operand(expr, right, operator_token)
            expr = self._set_node_location_from_nodes(
                BinaryExpression(left=expr, operator=operator, right=right),
                expr,
                right,
            )

        return expr

    def _parse_additive_expression(self) -> Expression:
        """Parse additive expression."""
        expr = self._parse_multiplicative_expression()

        while self._match(TokenType.PLUS, TokenType.MINUS):
            operator_token = self._previous()
            operator = operator_token.value
            right = self._parse_multiplicative_expression()
            self._reject_string_identifier_non_logical_operand(expr, right, operator_token)
            expr = self._set_node_location_from_nodes(
                BinaryExpression(left=expr, operator=operator, right=right),
                expr,
                right,
            )

        return expr

    def _parse_multiplicative_expression(self) -> Expression:
        """Parse multiplicative expression."""
        expr = self._parse_unary_expression()

        while self._match(TokenType.MULTIPLY, TokenType.DIVIDE, TokenType.MODULO):
            operator_token = self._previous()
            operator = operator_token.value
            right = self._parse_unary_expression()
            self._reject_string_identifier_non_logical_operand(expr, right, operator_token)
            expr = self._set_node_location_from_nodes(
                BinaryExpression(left=expr, operator=operator, right=right),
                expr,
                right,
            )

        return expr

    def _reject_string_identifier_non_logical_operand(
        self,
        left: Expression,
        right: Expression,
        token,
    ) -> None:
        if getattr(self, "_allow_string_identifier_non_logical_binary", False):
            return
        if self._is_string_identifier_operand(left) or self._is_string_identifier_operand(right):
            msg = "String identifiers can only be used as boolean operands or with at/in"
            raise ParserError(msg, token)

    def _is_string_identifier_operand(self, expr: Expression) -> bool:
        while isinstance(expr, ParenthesesExpression):
            expr = expr.expression
        return isinstance(expr, StringIdentifier)

    def _reject_invalid_numeric_unary_operand(
        self,
        operator: str,
        operand: Expression,
        token,
    ) -> None:
        if operator not in {"-", "~"}:
            return
        while isinstance(operand, ParenthesesExpression):
            operand = operand.expression
        if isinstance(operand, StringIdentifier | OfExpression | AtExpression):
            msg = "Invalid operand for numeric unary operator"
            raise ParserError(msg, token)
        if isinstance(operand, InExpression) and not self._is_string_count_in_expression(operand):
            msg = "Invalid operand for numeric unary operator"
            raise ParserError(msg, token)

    def _is_string_count_in_expression(self, operand: InExpression) -> bool:
        from yaraast.ast.expressions import StringCount

        return isinstance(operand.subject, StringCount)

    def _parse_unary_expression(self) -> Expression:
        """Parse unary expression."""
        if self._match(TokenType.MINUS, TokenType.BITWISE_NOT):
            start_token = self._previous()
            operator = self._previous().value
            operand = self._parse_unary_expression()
            self._reject_invalid_numeric_unary_operand(operator, operand, start_token)
            return self._set_node_location_from_tokens(
                UnaryExpression(operator=operator, operand=operand), start_token, self._previous()
            )

        if self._match(TokenType.DEFINED):
            start_token = self._previous()
            operand = self._parse_not_expression()
            return self._set_node_location_from_tokens(
                DefinedExpression(expression=operand), start_token, self._previous()
            )

        return self._parse_postfix_expression()
