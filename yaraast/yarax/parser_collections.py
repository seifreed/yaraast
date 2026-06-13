"""Collection parsing mixin for YARA-X parser."""

from __future__ import annotations

from typing import Any, cast

from yaraast.ast.expressions import Expression, StringLiteral
from yaraast.lexer.tokens import TokenType
from yaraast.parser._shared import ParserError
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    DictExpression,
    DictItem,
    ListExpression,
    SliceExpression,
    SpreadOperator,
    TupleExpression,
    TupleIndexing,
)
from yaraast.yarax.parser_helpers import (
    ERROR_EXPECTED_BRACE_CLOSE,
    ERROR_EXPECTED_BRACKET_CLOSE,
    ERROR_EXPECTED_COLON_DICT,
    ERROR_EXPECTED_VARIABLE,
)


class YaraXParserCollectionsMixin:
    """Collection parsing helpers for YARA-X."""

    def _parse_list_or_comprehension(self: Any) -> Expression:
        """Parse list literal or array comprehension."""
        self._consume(TokenType.LBRACKET, "Expected '['")

        if self._check(TokenType.RBRACKET):
            self._advance()
            return ListExpression(elements=[])

        if self._is_spread_operator():
            return cast(Expression, self._parse_spread_list())

        first_expr, used_contextual = self._parse_expression_allowing_contextual_keywords()

        if self._check(TokenType.FOR) or self._check_keyword("for"):
            return cast(
                Expression,
                self._parse_array_comprehension_body(first_expr, used_contextual),
            )
        if used_contextual:
            raise ParserError("Unexpected token", self._peek())

        return cast(Expression, self._parse_regular_list(first_expr))

    def _is_spread_operator(self: Any) -> bool:
        """Check if current position is a spread operator."""
        current = self._peek()
        next_token = self._peek_ahead(1)
        if self._check(TokenType.DOUBLE_DOT):
            return bool(
                next_token is not None
                and next_token.type == TokenType.DOT
                and self._tokens_are_adjacent(current, next_token)
            )
        third_token = self._peek_ahead(2)
        return (
            self._check(TokenType.DOT)
            and next_token is not None
            and next_token.type == TokenType.DOT
            and third_token is not None
            and third_token.type == TokenType.DOT
            and self._tokens_are_adjacent(current, next_token)
            and self._tokens_are_adjacent(next_token, third_token)
        )

    def _consume_spread_operator(self: Any) -> None:
        """Consume a spread operator token sequence."""
        if self._check(TokenType.DOUBLE_DOT):
            self._advance()
            self._consume(TokenType.DOT, "Expected '...'")
            return
        self._advance()
        self._advance()
        self._consume(TokenType.DOT, "Expected '...'")

    def _parse_spread_list(self: Any) -> ListExpression:
        """Parse list with spread operators."""
        elements: list[Expression] = []
        while not self._check(TokenType.RBRACKET):
            if self._is_spread_operator():
                self._consume_spread_operator()
                expr = self._parse_expression()
                elements.append(SpreadOperator(expression=expr, is_dict=False))
            else:
                elements.append(self._parse_expression())

            if not self._check(TokenType.RBRACKET):
                self._consume(TokenType.COMMA, "Expected ',' or ']'")

        self._consume(TokenType.RBRACKET, ERROR_EXPECTED_BRACKET_CLOSE)
        return ListExpression(elements=elements)

    def _parse_regular_list(self: Any, first_expr: Expression) -> ListExpression:
        """Parse regular list elements after first expression."""
        elements: list[Expression] = [first_expr]
        while self._check(TokenType.COMMA):
            self._advance()
            if self._check(TokenType.RBRACKET):
                break
            if self._is_spread_operator():
                self._consume_spread_operator()
                expr = self._parse_expression()
                elements.append(SpreadOperator(expression=expr, is_dict=False))
            else:
                elements.append(self._parse_expression())

        self._consume(TokenType.RBRACKET, ERROR_EXPECTED_BRACKET_CLOSE)
        return ListExpression(elements=elements)

    def _parse_array_comprehension_body(
        self: Any, expression: Expression, used_contextual: set[str]
    ) -> ArrayComprehension:
        """Parse array comprehension after initial expression."""
        if self._check(TokenType.FOR):
            self._advance()
        else:
            self._consume_keyword("for")

        variable = self._consume_local_identifier(ERROR_EXPECTED_VARIABLE).value
        local_names = self._local_identifier_scope_names(variable)
        if not used_contextual.issubset(local_names):
            raise ParserError("Unexpected token", self._peek())

        if self._check(TokenType.IN):
            self._advance()
        else:
            self._consume_keyword("in")

        iterable = self._parse_expression()

        condition = None
        if self._check_keyword("if"):
            self._advance()
            with self._contextual_local_identifier_scope(local_names):
                condition = self._parse_expression()

        self._consume(TokenType.RBRACKET, ERROR_EXPECTED_BRACKET_CLOSE)

        return ArrayComprehension(
            expression=expression,
            variable=variable,
            iterable=iterable,
            condition=condition,
        )

    def _parse_dict_or_comprehension(self: Any) -> Expression:
        """Parse dict literal or dict comprehension."""
        self._consume(TokenType.LBRACE, "Expected '{'")

        if self._check(TokenType.RBRACE):
            self._advance()
            return DictExpression(items=[])

        if self._is_dict_spread_operator():
            return cast(Expression, self._parse_dict_with_spread())

        first_key, used_contextual_key = self._parse_expression_allowing_contextual_keywords()
        self._consume(TokenType.COLON, ERROR_EXPECTED_COLON_DICT)
        first_value, used_contextual_value = self._parse_expression_allowing_contextual_keywords()

        if self._check(TokenType.FOR) or self._check_keyword("for"):
            return cast(
                Expression,
                self._parse_dict_comprehension_body(
                    first_key,
                    first_value,
                    used_contextual_key,
                    used_contextual_value,
                ),
            )
        if used_contextual_key or used_contextual_value:
            raise ParserError("Unexpected token", self._peek())

        return cast(Expression, self._parse_regular_dict(first_key, first_value))

    def _is_dict_spread_operator(self: Any) -> bool:
        """Check if current position is a dict spread operator."""
        next_token = self._peek_ahead(1)
        return (
            self._check(TokenType.MULTIPLY)
            and next_token is not None
            and next_token.type == TokenType.MULTIPLY
            and self._tokens_are_adjacent(self._peek(), next_token)
        )

    def _parse_dict_with_spread(self: Any) -> DictExpression:
        """Parse dict with spread operators."""
        items: list[DictItem] = []
        while not self._check(TokenType.RBRACE):
            if self._is_dict_spread_operator():
                items.append(self._parse_dict_spread_item())
            else:
                key = self._parse_expression()
                self._consume(TokenType.COLON, ERROR_EXPECTED_COLON_DICT)
                value = self._parse_expression()
                items.append(DictItem(key=key, value=value))

            if not self._check(TokenType.RBRACE):
                self._consume(TokenType.COMMA, "Expected ',' or '}'")

        self._consume(TokenType.RBRACE, ERROR_EXPECTED_BRACE_CLOSE)
        return DictExpression(items=items)

    def _parse_dict_spread_item(self: Any) -> DictItem:
        self._advance()
        self._advance()
        expr = self._parse_expression()
        return DictItem(
            key=StringLiteral(value="__spread__"),
            value=SpreadOperator(expression=expr, is_dict=True),
        )

    def _parse_regular_dict(
        self: Any, first_key: Expression, first_value: Expression
    ) -> DictExpression:
        """Parse regular dict after first key-value pair."""
        items: list[DictItem] = [DictItem(key=first_key, value=first_value)]

        while self._check(TokenType.COMMA):
            self._advance()
            if self._check(TokenType.RBRACE):
                break

            if self._is_dict_spread_operator():
                items.append(self._parse_dict_spread_item())
            else:
                key = self._parse_expression()
                self._consume(TokenType.COLON, ERROR_EXPECTED_COLON_DICT)
                value = self._parse_expression()
                items.append(DictItem(key=key, value=value))

        self._consume(TokenType.RBRACE, ERROR_EXPECTED_BRACE_CLOSE)
        return DictExpression(items=items)

    def _parse_dict_comprehension_body(
        self: Any,
        key_expr: Expression,
        value_expr: Expression,
        used_contextual_key: set[str],
        used_contextual_value: set[str],
    ) -> DictComprehension:
        """Parse dict comprehension after initial key-value pair."""
        if self._check(TokenType.FOR):
            self._advance()
        else:
            self._consume_keyword("for")

        first_var = self._consume_local_identifier(ERROR_EXPECTED_VARIABLE).value

        key_variable = first_var
        value_variable = None

        if self._check(TokenType.COMMA):
            self._advance()
            value_variable = self._consume_local_identifier("Expected second variable").value
            key_variable = first_var
        local_names = self._local_identifier_scope_names(key_variable, value_variable)
        used_contextual = used_contextual_key | used_contextual_value
        if not used_contextual.issubset(local_names):
            raise ParserError("Unexpected token", self._peek())

        if self._check(TokenType.IN):
            self._advance()
        else:
            self._consume_keyword("in")

        iterable = self._parse_expression()

        condition = None
        if self._check_keyword("if"):
            self._advance()
            with self._contextual_local_identifier_scope(local_names):
                condition = self._parse_expression()

        self._consume(TokenType.RBRACE, ERROR_EXPECTED_BRACE_CLOSE)

        return DictComprehension(
            key_expression=key_expr,
            value_expression=value_expr,
            key_variable=key_variable,
            value_variable=value_variable,
            iterable=iterable,
            condition=condition,
        )

    def _parse_tuple_or_parentheses(self: Any) -> Expression:
        """Parse tuple or parenthesized expression."""
        self._consume(TokenType.LPAREN, "Expected '('")

        if self._check(TokenType.RPAREN):
            self._advance()
            return TupleExpression(elements=[])

        first = self._parse_expression()

        if self._check(TokenType.COMMA):
            elements: list[Expression] = [first]
            while self._check(TokenType.COMMA):
                self._advance()
                if self._check(TokenType.RPAREN):
                    break
                elements.append(self._parse_expression())

            self._consume(TokenType.RPAREN, "Expected ')'")
            return TupleExpression(elements=elements)

        self._consume(TokenType.RPAREN, "Expected ')'")

        from yaraast.ast.expressions import ParenthesesExpression

        return ParenthesesExpression(expression=first)

    def _parse_tuple_indexing_postfix(self: Any, tuple_expr: Expression) -> Expression:
        """Parse tuple indexing on an expression."""
        self._consume(TokenType.LBRACKET, "Expected '['")

        if self._check(TokenType.COLON):
            return cast(Expression, self._parse_slice_expression(tuple_expr, None))

        index = self._parse_expression()

        if self._check(TokenType.COLON):
            return cast(Expression, self._parse_slice_expression(tuple_expr, index))

        self._consume(TokenType.RBRACKET, ERROR_EXPECTED_BRACKET_CLOSE)

        return TupleIndexing(tuple_expr=tuple_expr, index=index)

    def _parse_slice_expression(
        self: Any, target: Expression, start: Expression | None
    ) -> SliceExpression:
        """Parse slice expression after target and optional start."""
        if start is None:
            self._consume(TokenType.COLON, "Expected ':'")
        else:
            self._advance()

        stop = None
        if not self._check(TokenType.COLON) and not self._check(TokenType.RBRACKET):
            stop = self._parse_expression()

        step = None
        if self._check(TokenType.COLON):
            self._advance()
            if not self._check(TokenType.RBRACKET):
                step = self._parse_expression()

        self._consume(TokenType.RBRACKET, ERROR_EXPECTED_BRACKET_CLOSE)

        return SliceExpression(target=target, start=start, stop=stop, step=step)
