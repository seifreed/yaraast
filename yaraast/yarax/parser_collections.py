"""Collection parsing mixin for YARA-X parser."""

from __future__ import annotations

from yaraast.ast.expressions import Expression, StringLiteral
from yaraast.lexer.tokens import TokenType
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

    def _parse_list_or_comprehension(self) -> Expression:
        """Parse list literal or array comprehension."""
        self._consume(TokenType.LBRACKET, "Expected '['")

        if self._check(TokenType.RBRACKET):
            self._advance()
            return ListExpression(elements=[])

        if self._is_spread_operator():
            return self._parse_spread_list()

        first_expr = self._parse_or_expression()

        if self._check(TokenType.FOR) or self._check_keyword("for"):
            return self._parse_array_comprehension_body(first_expr)

        return self._parse_regular_list(first_expr)

    def _is_spread_operator(self) -> bool:
        """Check if current position is a spread operator."""
        if self._check(TokenType.DOUBLE_DOT):
            return bool(self._peek_ahead(1) and self._peek_ahead(1).type == TokenType.DOT)
        return (
            self._check(TokenType.DOT)
            and self._peek_ahead(1)
            and self._peek_ahead(1).type == TokenType.DOT
        )

    def _consume_spread_operator(self) -> None:
        """Consume a spread operator token sequence."""
        if self._check(TokenType.DOUBLE_DOT):
            self._advance()
            self._consume(TokenType.DOT, "Expected '...'")
            return
        self._advance()
        self._advance()
        self._advance()

    def _parse_spread_list(self) -> ListExpression:
        """Parse list with spread operators."""
        elements = []
        while not self._check(TokenType.RBRACKET):
            if self._is_spread_operator():
                self._consume_spread_operator()
                expr = self._parse_or_expression()
                elements.append(SpreadOperator(expression=expr, is_dict=False))
            else:
                elements.append(self._parse_or_expression())

            if not self._check(TokenType.RBRACKET):
                self._consume(TokenType.COMMA, "Expected ',' or ']'")

        self._consume(TokenType.RBRACKET, ERROR_EXPECTED_BRACKET_CLOSE)
        return ListExpression(elements=elements)

    def _parse_regular_list(self, first_expr: Expression) -> ListExpression:
        """Parse regular list elements after first expression."""
        elements = [first_expr]
        while self._check(TokenType.COMMA):
            self._advance()
            if self._check(TokenType.RBRACKET):
                break
            if self._is_spread_operator():
                self._consume_spread_operator()
                expr = self._parse_or_expression()
                elements.append(SpreadOperator(expression=expr, is_dict=False))
            else:
                elements.append(self._parse_or_expression())

        self._consume(TokenType.RBRACKET, ERROR_EXPECTED_BRACKET_CLOSE)
        return ListExpression(elements=elements)

    def _parse_array_comprehension_body(self, expression: Expression) -> ArrayComprehension:
        """Parse array comprehension after initial expression."""
        if self._check(TokenType.FOR):
            self._advance()
        else:
            self._consume_keyword("for")

        variable = self._consume(TokenType.IDENTIFIER, ERROR_EXPECTED_VARIABLE).value

        if self._check(TokenType.IN):
            self._advance()
        else:
            self._consume_keyword("in")

        iterable = self._parse_or_expression()

        condition = None
        if self._check_keyword("if"):
            self._advance()
            condition = self._parse_or_expression()

        self._consume(TokenType.RBRACKET, ERROR_EXPECTED_BRACKET_CLOSE)

        return ArrayComprehension(
            expression=expression,
            variable=variable,
            iterable=iterable,
            condition=condition,
        )

    def _parse_dict_or_comprehension(self) -> Expression:
        """Parse dict literal or dict comprehension."""
        self._consume(TokenType.LBRACE, "Expected '{'")

        if self._check(TokenType.RBRACE):
            self._advance()
            return DictExpression(items=[])

        if self._is_dict_spread_operator():
            return self._parse_dict_with_spread()

        first_key = self._parse_or_expression()
        self._consume(TokenType.COLON, ERROR_EXPECTED_COLON_DICT)
        first_value = self._parse_or_expression()

        if self._check(TokenType.FOR) or self._check_keyword("for"):
            return self._parse_dict_comprehension_body(first_key, first_value)

        return self._parse_regular_dict(first_key, first_value)

    def _is_dict_spread_operator(self) -> bool:
        """Check if current position is a dict spread operator."""
        return (
            self._check(TokenType.MULTIPLY)
            and self._peek_ahead(1)
            and self._peek_ahead(1).type == TokenType.MULTIPLY
        )

    def _parse_dict_with_spread(self) -> DictExpression:
        """Parse dict with spread operators."""
        items = []
        while not self._check(TokenType.RBRACE):
            if self._check(TokenType.MULTIPLY) and self._is_dict_spread_operator():
                self._advance()  # First *
                self._advance()  # Second *
                expr = self._parse_or_expression()
                items.append(
                    DictItem(
                        key=StringLiteral(value="__spread__"),
                        value=SpreadOperator(expression=expr, is_dict=True),
                    ),
                )
            else:
                key = self._parse_or_expression()
                self._consume(TokenType.COLON, ERROR_EXPECTED_COLON_DICT)
                value = self._parse_or_expression()
                items.append(DictItem(key=key, value=value))

            if not self._check(TokenType.RBRACE):
                self._consume(TokenType.COMMA, "Expected ',' or '}'")

        self._consume(TokenType.RBRACE, ERROR_EXPECTED_BRACE_CLOSE)
        return DictExpression(items=items)

    def _parse_regular_dict(self, first_key: Expression, first_value: Expression) -> DictExpression:
        """Parse regular dict after first key-value pair."""
        items = [DictItem(key=first_key, value=first_value)]

        while self._check(TokenType.COMMA):
            self._advance()
            if self._check(TokenType.RBRACE):
                break

            key = self._parse_or_expression()
            self._consume(TokenType.COLON, ERROR_EXPECTED_COLON_DICT)
            value = self._parse_or_expression()
            items.append(DictItem(key=key, value=value))

        self._consume(TokenType.RBRACE, ERROR_EXPECTED_BRACE_CLOSE)
        return DictExpression(items=items)

    def _parse_dict_comprehension_body(
        self, key_expr: Expression, value_expr: Expression
    ) -> DictComprehension:
        """Parse dict comprehension after initial key-value pair."""
        if self._check(TokenType.FOR):
            self._advance()
        else:
            self._consume_keyword("for")

        first_var = self._consume(TokenType.IDENTIFIER, ERROR_EXPECTED_VARIABLE).value

        key_variable = first_var
        value_variable = None

        if self._check(TokenType.COMMA):
            self._advance()
            value_variable = self._consume(TokenType.IDENTIFIER, "Expected second variable").value
            key_variable = first_var

        if self._check(TokenType.IN):
            self._advance()
        else:
            self._consume_keyword("in")

        iterable = self._parse_or_expression()

        condition = None
        if self._check_keyword("if"):
            self._advance()
            condition = self._parse_or_expression()

        self._consume(TokenType.RBRACE, ERROR_EXPECTED_BRACE_CLOSE)

        return DictComprehension(
            key_expression=key_expr,
            value_expression=value_expr,
            key_variable=key_variable,
            value_variable=value_variable,
            iterable=iterable,
            condition=condition,
        )

    def _parse_tuple_or_parentheses(self) -> Expression:
        """Parse tuple or parenthesized expression."""
        self._consume(TokenType.LPAREN, "Expected '('")

        if self._check(TokenType.RPAREN):
            self._advance()
            return TupleExpression(elements=[])

        first = self._parse_or_expression()

        if self._check(TokenType.COMMA):
            elements = [first]
            while self._check(TokenType.COMMA):
                self._advance()
                if self._check(TokenType.RPAREN):
                    break
                elements.append(self._parse_or_expression())

            self._consume(TokenType.RPAREN, "Expected ')'")
            return TupleExpression(elements=elements)

        self._consume(TokenType.RPAREN, "Expected ')'")

        if self._check(TokenType.LBRACKET):
            return TupleExpression(elements=[first])

        from yaraast.ast.expressions import ParenthesesExpression

        return ParenthesesExpression(expression=first)

    def _parse_tuple_indexing_postfix(self, tuple_expr: Expression) -> TupleIndexing:
        """Parse tuple indexing on an expression."""
        self._consume(TokenType.LBRACKET, "Expected '['")

        if self._check(TokenType.COLON):
            return self._parse_slice_expression(tuple_expr, None)

        index = self._parse_or_expression()

        if self._check(TokenType.COLON):
            return self._parse_slice_expression(tuple_expr, index)

        self._consume(TokenType.RBRACKET, ERROR_EXPECTED_BRACKET_CLOSE)

        return TupleIndexing(tuple_expr=tuple_expr, index=index)

    def _parse_slice_expression(
        self, target: Expression, start: Expression | None
    ) -> SliceExpression:
        """Parse slice expression after target and optional start."""
        if start is None:
            self._consume(TokenType.COLON, "Expected ':'")
        else:
            self._advance()

        stop = None
        if not self._check(TokenType.COLON) and not self._check(TokenType.RBRACKET):
            stop = self._parse_or_expression()

        step = None
        if self._check(TokenType.COLON):
            self._advance()
            if not self._check(TokenType.RBRACKET):
                step = self._parse_or_expression()

        self._consume(TokenType.RBRACKET, ERROR_EXPECTED_BRACKET_CLOSE)

        return SliceExpression(target=target, start=start, stop=stop, step=step)
