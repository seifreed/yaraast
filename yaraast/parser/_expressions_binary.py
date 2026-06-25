"""Expression parsing helpers for logical/arithmetic operators."""

from __future__ import annotations

from collections.abc import Callable

from yaraast.ast.conditions import (
    AtExpression,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    Expression,
    IntegerLiteral,
    ParenthesesExpression,
    RangeExpression,
    RegexLiteral,
    StringCount,
    StringIdentifier,
    StringLiteral,
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

        if (
            self._check(TokenType.OF)
            and not getattr(self, "_suppress_of_postfix", False)
            and self._is_valid_of_quantifier(expr)
        ):
            expr = self._parse_expression_of_postfix(expr)
            expr = self._parse_of_restriction_postfix(expr)
        elif (
            self._check_percentage_of_postfix()
            and not getattr(self, "_suppress_of_postfix", False)
            and self._is_valid_percentage_of_quantifier(expr)
        ):
            expr = self._parse_percentage_expression_of_postfix(expr)
            expr = self._parse_of_restriction_postfix(expr)

        if self._match(*RELATIONAL_TOKEN_TYPES):
            operator_token = self._previous()
            operator = operator_token.value.lower()
            right = self._parse_without_of_postfix(self._parse_range_expression)
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

    def _is_valid_of_quantifier(self, expr: Expression) -> bool:
        """Return True when ``expr`` may act as the count of an of-expression.

        libyara accepts any ``primary_expression`` (numeric leaf or arithmetic
        thereof) as the quantifier of an of-expression, e.g. ``#a of them`` or
        ``#a + 1 of them``.  String identifiers, wildcards, and boolean results
        such as nested of/at/in expressions are syntax errors as quantifiers.
        """
        expr = self._unwrap_parenthesized_expression(expr)
        if isinstance(
            expr,
            StringIdentifier
            | StringLiteral
            | RegexLiteral
            | BooleanLiteral
            | DoubleLiteral
            | OfExpression
            | AtExpression
            | InExpression,
        ):
            if isinstance(expr, InExpression):
                return self._is_string_count_in_expression(expr)
            return False
        if isinstance(expr, UnaryExpression):
            return expr.operator in {"-", "~"} and self._is_valid_of_quantifier(expr.operand)
        if isinstance(expr, BinaryExpression):
            return self._is_valid_of_quantifier(expr.left) and self._is_valid_of_quantifier(
                expr.right
            )
        return not isinstance(expr, RangeExpression)

    def _parse_of_restriction_postfix(self, expr: Expression) -> Expression:
        if not isinstance(expr, OfExpression):
            return expr
        if self._match(TokenType.AT):
            self._validate_of_restriction_string_set(expr)
            return self._parse_at_postfix(expr)
        if self._match(TokenType.IN):
            self._validate_of_restriction_string_set(expr)
            return self._parse_in_postfix(expr)
        return expr

    def _validate_of_restriction_string_set(self, expr: OfExpression) -> None:
        if self._of_string_set_kind(expr.string_set, top_level=True) == "string":
            return
        msg = "Rule sets cannot use at/in restrictions"
        raise ParserError(msg, self._previous())

    def _parse_expression_of_postfix(self, quantifier: Expression) -> Expression:
        """Wrap ``quantifier`` as the count of an of-expression."""
        self._match(TokenType.OF)
        start_token = self._previous()
        self._validate_static_of_quantifier(quantifier, start_token)
        string_set = self._parse_of_string_set()
        node = OfExpression(quantifier=quantifier, string_set=string_set)
        if getattr(quantifier, "location", None) is not None:
            node.location = self._location_from_tokens(
                self._synthetic_token_from_location(quantifier.location),
                self._previous(),
            )
            return node
        return self._set_node_location_from_tokens(node, start_token, self._previous())

    def _check_percentage_of_postfix(self) -> bool:
        return (
            self._check(TokenType.MODULO)
            and self.current + 1 < len(self.tokens)
            and self.tokens[self.current + 1].type == TokenType.OF
        )

    def _is_valid_percentage_of_quantifier(self, expr: Expression) -> bool:
        if isinstance(expr, ParenthesesExpression):
            return self._is_valid_of_quantifier(expr.expression)
        if isinstance(expr, BinaryExpression):
            return (
                expr.operator in {"*", "%"}
                and self._is_valid_of_quantifier(expr.left)
                and self._is_valid_of_quantifier(expr.right)
            )
        return self._is_valid_of_quantifier(expr)

    def _parse_percentage_expression_of_postfix(self, quantifier: Expression) -> Expression:
        self._match(TokenType.MODULO)
        start_token = self._previous()
        percentage = self._set_node_location_from_nodes(
            UnaryExpression(operator="%", operand=quantifier),
            quantifier,
            start_token,
        )
        self._validate_static_percentage_quantifier(percentage, start_token)
        if not self._match(TokenType.OF):
            msg = "Expected 'of' after percentage quantifier"
            raise ParserError(msg, self._peek())
        string_set = self._parse_of_string_set()
        node = OfExpression(quantifier=percentage, string_set=string_set)
        if getattr(quantifier, "location", None) is not None:
            node.location = self._location_from_tokens(
                self._synthetic_token_from_location(quantifier.location),
                self._previous(),
            )
            return node
        return self._set_node_location_from_tokens(node, start_token, self._previous())

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
            self._validate_static_range_bounds(expr, self._previous())

        return expr

    def _parse_bitwise_or_expression(self) -> Expression:
        """Parse bitwise OR expression."""
        expr = self._parse_bitwise_xor_expression()

        while self._match(TokenType.BITWISE_OR):
            operator_token = self._previous()
            operator = operator_token.value
            right = self._parse_without_of_postfix(self._parse_bitwise_xor_expression)
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
            right = self._parse_without_of_postfix(self._parse_bitwise_and_expression)
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
            right = self._parse_without_of_postfix(self._parse_shift_expression)
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
            right = self._parse_without_of_postfix(self._parse_additive_expression)
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
            right = self._parse_without_of_postfix(self._parse_multiplicative_expression)
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

        while True:
            if self._check_percentage_of_postfix():
                break
            if not self._match(TokenType.MULTIPLY, TokenType.DIVIDE, TokenType.MODULO):
                break
            operator_token = self._previous()
            operator = operator_token.value
            right = self._parse_without_of_postfix(self._parse_unary_expression)
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
        if self._is_non_numeric_condition_operand(left) or self._is_non_numeric_condition_operand(
            right
        ):
            msg = "Condition expressions can only be used as boolean operands"
            raise ParserError(msg, token)

    def _parse_without_of_postfix(self, parser: Callable[[], Expression]) -> Expression:
        previous_suppress_of = getattr(self, "_suppress_of_postfix", False)
        self._suppress_of_postfix = True
        try:
            return parser()
        finally:
            self._suppress_of_postfix = previous_suppress_of

    def _is_string_identifier_operand(self, expr: Expression) -> bool:
        expr = self._unwrap_parenthesized_expression(expr)
        return isinstance(expr, StringIdentifier)

    def _is_non_numeric_condition_operand(self, expr: Expression) -> bool:
        expr = self._unwrap_parenthesized_expression(expr)
        if isinstance(expr, OfExpression | AtExpression | ForExpression | ForOfExpression):
            return True
        if isinstance(expr, InExpression):
            return not isinstance(expr.subject, StringCount)
        return False

    def _unwrap_parenthesized_expression(self, expr: Expression) -> Expression:
        while isinstance(expr, ParenthesesExpression):
            expr = expr.expression
        return expr

    def _reject_invalid_numeric_unary_operand(
        self,
        operator: str,
        operand: Expression,
        token,
    ) -> None:
        if operator not in {"-", "~"}:
            return
        operand = self._unwrap_parenthesized_expression(operand)
        if isinstance(operand, StringIdentifier | OfExpression | AtExpression):
            msg = "Invalid operand for numeric unary operator"
            raise ParserError(msg, token)
        if isinstance(operand, InExpression) and not self._is_string_count_in_expression(operand):
            msg = "Invalid operand for numeric unary operator"
            raise ParserError(msg, token)

    def _is_string_count_in_expression(self, operand: InExpression) -> bool:
        from yaraast.ast.expressions import StringCount

        return isinstance(operand.subject, StringCount)

    def _validate_static_range_bounds(self, range_expr: RangeExpression, token) -> None:
        low = self._static_integer_value(range_expr.low)
        high = self._static_integer_value(range_expr.high)
        if low is not None and high is not None and low < 0:
            msg = "Range lower bound can not be negative"
            raise ParserError(msg, token)
        if low is not None and high is not None and high < low:
            msg = "Range lower bound must be less than upper bound"
            raise ParserError(msg, token)

    def _validate_static_of_quantifier(self, quantifier: Expression, token) -> None:
        value = self._static_integer_value(quantifier)
        if value is not None and value < 0:
            msg = "Of-expression quantifier can not be negative"
            raise ParserError(msg, token)

    def _validate_static_percentage_quantifier(self, quantifier: Expression, token) -> None:
        if not isinstance(quantifier, UnaryExpression) or quantifier.operator != "%":
            return
        value = self._static_integer_value(quantifier.operand)
        if value is not None and not 1 <= value <= 100:
            msg = "Percentage quantifier must be between 1 and 100"
            raise ParserError(msg, token)

    def _static_integer_value(self, expr: Expression) -> int | None:
        expr = self._unwrap_parenthesized_expression(expr)
        if isinstance(expr, IntegerLiteral):
            return expr.value
        if isinstance(expr, UnaryExpression):
            value = self._static_integer_value(expr.operand)
            if value is None:
                return None
            if expr.operator == "-":
                return -value
            if expr.operator == "~":
                return ~value
        if isinstance(expr, BinaryExpression) and expr.operator in {
            "+",
            "-",
            "*",
            "%",
            "<<",
            ">>",
            "&",
            "|",
            "^",
        }:
            right = self._static_integer_value(expr.right)
            if right is not None and expr.operator in {"<<", ">>"}:
                if right < 0:
                    return None
                if right >= _INT64_BITS:
                    return 0
            left = self._static_integer_value(expr.left)
            if left is None or right is None:
                return None
            if expr.operator == "+":
                return _normalize_int64(left + right)
            if expr.operator == "-":
                return _normalize_int64(left - right)
            if expr.operator == "*":
                return _normalize_int64(left * right)
            if expr.operator == "%":
                if right == 0:
                    return None
                return _integer_remainder(left, right)
            if expr.operator == "<<":
                return _shift_left_int64(left, right)
            if expr.operator == ">>":
                return _shift_right_int64(left, right)
            if expr.operator == "&":
                return _normalize_int64(left & right)
            if expr.operator == "|":
                return _normalize_int64(left | right)
            return _normalize_int64(left ^ right)
        return None

    def _parse_unary_expression(self) -> Expression:
        """Parse unary expression."""
        if self._match(TokenType.MINUS, TokenType.BITWISE_NOT):
            start_token = self._previous()
            operator = self._previous().value
            operand = self._parse_without_of_postfix(self._parse_unary_expression)
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


def _integer_remainder(left: int, right: int) -> int:
    quotient = abs(left) // abs(right)
    if (left < 0) != (right < 0):
        quotient = -quotient
    return left - quotient * right


_INT64_BITS = 64
_INT64_MAX = (1 << 63) - 1
_UINT64_MASK = (1 << _INT64_BITS) - 1


def _normalize_int64(value: int) -> int:
    unsigned = value & _UINT64_MASK
    if unsigned > _INT64_MAX:
        return unsigned - (1 << _INT64_BITS)
    return unsigned


def _shift_left_int64(left: int, right: int) -> int:
    if right >= _INT64_BITS:
        return 0
    return _normalize_int64(left << right)


def _shift_right_int64(left: int, right: int) -> int:
    if right >= _INT64_BITS:
        return 0
    return _normalize_int64(left) >> right
