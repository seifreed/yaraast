"""Expression parsing helpers for logical/arithmetic operators."""

from __future__ import annotations

from yaraast.ast.expressions import BinaryExpression, Expression, RangeExpression, UnaryExpression
from yaraast.ast.operators import DefinedExpression
from yaraast.lexer import TokenType


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

        while self._match(
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
        ):
            operator = self._previous().value.lower()
            right = self._parse_range_expression()
            expr = self._set_node_location_from_nodes(
                BinaryExpression(left=expr, operator=operator, right=right),
                expr,
                right,
            )

        return expr

    def _parse_range_expression(self) -> Expression:
        """Parse range expression (a..b)."""
        expr = self._parse_bitwise_expression()

        if self._match(TokenType.DOUBLE_DOT):
            high = self._parse_bitwise_expression()
            expr = self._set_node_location_from_nodes(
                RangeExpression(low=expr, high=high), expr, high
            )

        return expr

    def _parse_bitwise_expression(self) -> Expression:
        """Parse bitwise expression."""
        expr = self._parse_shift_expression()

        while self._match(TokenType.BITWISE_AND, TokenType.BITWISE_OR, TokenType.XOR):
            operator = self._previous().value
            right = self._parse_shift_expression()
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
            operator = self._previous().value
            right = self._parse_additive_expression()
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
            operator = self._previous().value
            right = self._parse_multiplicative_expression()
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
            operator = self._previous().value
            right = self._parse_unary_expression()
            expr = self._set_node_location_from_nodes(
                BinaryExpression(left=expr, operator=operator, right=right),
                expr,
                right,
            )

        return expr

    def _parse_unary_expression(self) -> Expression:
        """Parse unary expression."""
        if self._match(TokenType.MINUS, TokenType.BITWISE_NOT):
            start_token = self._previous()
            operator = self._previous().value
            operand = self._parse_unary_expression()
            return self._set_node_location_from_tokens(
                UnaryExpression(operator=operator, operand=operand), start_token, self._previous()
            )

        if self._match(TokenType.DEFINED):
            start_token = self._previous()
            operand = self._parse_postfix_expression()
            return self._set_node_location_from_tokens(
                DefinedExpression(expression=operand), start_token, self._previous()
            )

        return self._parse_postfix_expression()
