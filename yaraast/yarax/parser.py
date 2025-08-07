"""Enhanced YARA-X parser with support for new syntax features."""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast.ast.conditions import Condition
from yaraast.ast.expressions import Expression, FunctionCall, StringLiteral
from yaraast.lexer.tokens import TokenType
from yaraast.parser.parser import Parser as BaseParser
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    DictExpression,
    DictItem,
    LambdaExpression,
    ListExpression,
    MatchCase,
    PatternMatch,
    SliceExpression,
    SpreadOperator,
    TupleExpression,
    TupleIndexing,
    WithDeclaration,
    WithStatement,
)

if TYPE_CHECKING:
    from yaraast.lexer.lexer import Token

# Error message constants
ERROR_EXPECTED_VARIABLE = "Expected variable name"
ERROR_EXPECTED_BRACKET_CLOSE = "Expected ']'"
ERROR_EXPECTED_COLON_DICT = "Expected ':' in dict"
ERROR_EXPECTED_BRACE_CLOSE = "Expected '}'"


class YaraXParser(BaseParser):
    """Enhanced parser for YARA-X with support for new syntax features."""

    def __init__(self, text: str) -> None:
        """Initialize YARA-X parser.

        Args:
            text: YARA-X source code to parse
        """
        super().__init__(text)

    def _parse_condition(self) -> Condition:
        """Parse condition with YARA-X extensions."""
        # Check for 'with' statement
        if self._check_keyword("with"):
            return self._parse_with_statement()

        # Otherwise parse normal condition
        return super()._parse_condition()

    def parse_condition(self) -> Condition:
        """Parse condition with YARA-X extensions."""
        return self._parse_condition()

    def _parse_with_statement(self) -> WithStatement:
        """Parse 'with' statement.

        Example:
            with $a = "test", $b = 10:
                $a matches /test/ and #b > 5
        """
        self._consume_keyword("with")

        # Parse declarations
        declarations = []
        declarations.append(self._parse_with_declaration())

        while self._check(TokenType.COMMA):
            self._advance()
            declarations.append(self._parse_with_declaration())

        self._consume(TokenType.COLON, "Expected ':' after with declarations")

        # Parse body condition
        body = super()._parse_condition()

        return WithStatement(declarations=declarations, body=body)

    def _parse_with_declaration(self) -> WithDeclaration:
        """Parse single declaration in with statement."""
        # Get identifier (e.g., $a)
        identifier = self._consume(TokenType.STRING_IDENTIFIER, ERROR_EXPECTED_VARIABLE).value

        self._consume(TokenType.ASSIGN, "Expected '=' in with declaration")

        # Parse initial value
        value = self._parse_or_expression()

        return WithDeclaration(identifier=identifier, value=value)

    def parse_expression(self) -> Expression:
        """Parse expression with YARA-X extensions."""
        # Check for list/array literal
        if self._check(TokenType.LBRACKET):
            return self._parse_list_or_comprehension()

        # Check for dict literal
        if self._check(TokenType.LBRACE):
            return self._parse_dict_or_comprehension()

        # Check for tuple
        if self._check(TokenType.LPAREN):
            # Need to look ahead to distinguish tuple from parentheses
            return self._parse_tuple_or_parentheses()

        # Check for lambda
        if self._check_keyword("lambda"):
            return self._parse_lambda()

        # Check for match expression
        if self._check_keyword("match"):
            return self._parse_pattern_match()

        # Otherwise parse normal expression
        expr = super()._parse_or_expression()

        # Check for tuple indexing
        if isinstance(expr, FunctionCall) and self._check(TokenType.LBRACKET):
            # Function call followed by indexing - likely tuple indexing
            return self._parse_tuple_indexing_postfix(expr)

        return expr

    def _parse_list_or_comprehension(self) -> Expression:
        """Parse list literal or array comprehension."""
        self._consume(TokenType.LBRACKET, "Expected '['")

        # Empty list
        if self._check(TokenType.RBRACKET):
            self._advance()
            return ListExpression(elements=[])

        # Check for spread operator
        if self._is_spread_operator():
            return self._parse_spread_list()

        # Parse first element
        first_expr = self._parse_or_expression()

        # Check for comprehension
        if self._check_keyword("for"):
            return self._parse_array_comprehension_body(first_expr)

        # Regular list
        return self._parse_regular_list(first_expr)

    def _is_spread_operator(self) -> bool:
        """Check if current position is a spread operator."""
        return (
            self._check(TokenType.DOT)
            and self._peek_ahead(1)
            and self._peek_ahead(1).type == TokenType.DOT
        )

    def _parse_spread_list(self) -> ListExpression:
        """Parse list with spread operators."""
        elements = []
        while not self._check(TokenType.RBRACKET):
            if self._check(TokenType.DOT):
                # Spread operator
                self._advance()  # First dot
                self._advance()  # Second dot
                self._advance()  # Third dot
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
                break  # Trailing comma
            elements.append(self._parse_or_expression())

        self._consume(TokenType.RBRACKET, ERROR_EXPECTED_BRACKET_CLOSE)
        return ListExpression(elements=elements)

    def _parse_array_comprehension_body(self, expression: Expression) -> ArrayComprehension:
        """Parse array comprehension after initial expression."""
        self._consume_keyword("for")

        # Parse variable
        variable = self._consume(TokenType.IDENTIFIER, ERROR_EXPECTED_VARIABLE).value

        self._consume_keyword("in")

        # Parse iterable
        iterable = self._parse_or_expression()

        # Check for condition
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

        # Empty dict
        if self._check(TokenType.RBRACE):
            self._advance()
            return DictExpression(items=[])

        # Check for spread operator dict
        if self._is_dict_spread_operator():
            return self._parse_dict_with_spread()

        # Parse first key
        first_key = self._parse_or_expression()
        self._consume(TokenType.COLON, ERROR_EXPECTED_COLON_DICT)
        first_value = self._parse_or_expression()

        # Check for comprehension
        if self._check_keyword("for"):
            return self._parse_dict_comprehension_body(first_key, first_value)

        # Regular dict
        return self._parse_regular_dict(first_key, first_value)

    def _is_dict_spread_operator(self) -> bool:
        """Check if current position is a dict spread operator."""
        return (
            self._check(TokenType.STAR)
            and self._peek_ahead(1)
            and self._peek_ahead(1).type == TokenType.STAR
        )

    def _parse_dict_with_spread(self) -> DictExpression:
        """Parse dict with spread operators."""
        items = []
        while not self._check(TokenType.RBRACE):
            if self._check(TokenType.STAR):
                # Spread operator
                self._advance()  # First star
                self._advance()  # Second star
                expr = self._parse_or_expression()
                # For dict spread, we need special handling
                # This is a simplification - real implementation would merge dicts
                items.append(
                    DictItem(
                        key=StringLiteral(value="__spread__"),
                        value=SpreadOperator(expression=expr, is_dict=True),
                    )
                )
            else:
                # Regular key-value pair
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
                break  # Trailing comma

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
        self._consume_keyword("for")

        # Parse variable(s)
        first_var = self._consume(TokenType.IDENTIFIER, ERROR_EXPECTED_VARIABLE).value

        key_variable = first_var
        value_variable = None

        # Check for two variables (k, v pattern)
        if self._check(TokenType.COMMA):
            self._advance()
            value_variable = self._consume(TokenType.IDENTIFIER, "Expected second variable").value
            key_variable = first_var

        self._consume_keyword("in")

        # Parse iterable
        iterable = self._parse_or_expression()

        # Check for condition
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

        # Empty tuple
        if self._check(TokenType.RPAREN):
            self._advance()
            return TupleExpression(elements=[])

        # Parse first element
        first = self._parse_or_expression()

        # Check for comma (indicates tuple)
        if self._check(TokenType.COMMA):
            elements = [first]
            while self._check(TokenType.COMMA):
                self._advance()
                if self._check(TokenType.RPAREN):
                    break  # Trailing comma
                elements.append(self._parse_or_expression())

            self._consume(TokenType.RPAREN, "Expected ')'")
            return TupleExpression(elements=elements)

        # Single element - could be tuple or parentheses
        self._consume(TokenType.RPAREN, "Expected ')'")

        # Check if followed by indexing (indicates tuple)
        if self._check(TokenType.LBRACKET):
            # Single element tuple being indexed
            return TupleExpression(elements=[first])

        # Otherwise it's just parentheses
        from yaraast.ast.expressions import ParenthesesExpression

        return ParenthesesExpression(expression=first)

    def _parse_tuple_indexing_postfix(self, tuple_expr: Expression) -> TupleIndexing:
        """Parse tuple indexing on an expression."""
        self._consume(TokenType.LBRACKET, "Expected '['")

        # Check for slice
        if self._check(TokenType.COLON):
            # Slice expression
            return self._parse_slice_expression(tuple_expr, None)

        # Parse index
        index = self._parse_or_expression()

        # Check if this is actually a slice
        if self._check(TokenType.COLON):
            return self._parse_slice_expression(tuple_expr, index)

        self._consume(TokenType.RBRACKET, ERROR_EXPECTED_BRACKET_CLOSE)

        return TupleIndexing(tuple_expr=tuple_expr, index=index)

    def _parse_slice_expression(
        self, target: Expression, start: Expression | None
    ) -> SliceExpression:
        """Parse slice expression after target and optional start."""
        # We've already seen the colon or have a start expression
        if start is None:
            self._consume(TokenType.COLON, "Expected ':'")
        else:
            self._advance()  # Consume the colon

        # Parse stop
        stop = None
        if not self._check(TokenType.COLON) and not self._check(TokenType.RBRACKET):
            stop = self._parse_or_expression()

        # Parse step
        step = None
        if self._check(TokenType.COLON):
            self._advance()
            if not self._check(TokenType.RBRACKET):
                step = self._parse_or_expression()

        self._consume(TokenType.RBRACKET, ERROR_EXPECTED_BRACKET_CLOSE)

        return SliceExpression(target=target, start=start, stop=stop, step=step)

    def parse_primary_expression(self) -> Expression:
        """Parse primary expression with YARA-X extensions."""
        # Check for tuple indexing on any primary expression
        expr = super().parse_primary_expression()

        # Check for indexing
        while self._check(TokenType.LBRACKET):
            self._advance()

            # Check for slice
            if self._check(TokenType.COLON):
                expr = self._parse_slice_expression(expr, None)
            else:
                index = self._parse_or_expression()

                # Check if this is a slice
                if self._check(TokenType.COLON):
                    expr = self._parse_slice_expression(expr, index)
                else:
                    self._consume(TokenType.RBRACKET, ERROR_EXPECTED_BRACKET_CLOSE)

                    # Determine if this is tuple indexing or array access
                    if isinstance(expr, TupleExpression | FunctionCall):
                        expr = TupleIndexing(tuple_expr=expr, index=index)
                    else:
                        from yaraast.ast.expressions import ArrayAccess

                        expr = ArrayAccess(array=expr, index=index)

        return expr

    def _parse_lambda(self) -> LambdaExpression:
        """Parse lambda expression."""
        self._consume_keyword("lambda")

        # Parse parameters
        parameters = []
        if not self._check(TokenType.COLON):
            parameters.append(self._consume(TokenType.IDENTIFIER, "Expected parameter").value)

            while self._check(TokenType.COMMA):
                self._advance()
                parameters.append(self._consume(TokenType.IDENTIFIER, "Expected parameter").value)

        self._consume(TokenType.COLON, "Expected ':' after lambda parameters")

        # Parse body
        body = self._parse_or_expression()

        return LambdaExpression(parameters=parameters, body=body)

    def _parse_pattern_match(self) -> PatternMatch:
        """Parse pattern match expression."""
        self._consume_keyword("match")

        # Parse value to match
        value = self._parse_or_expression()

        self._consume(TokenType.LBRACE, "Expected '{' after match value")

        # Parse cases
        cases = []
        default = None

        while not self._check(TokenType.RBRACE):
            if self._check(TokenType.UNDERSCORE):
                # Default case
                self._advance()
                self._consume(TokenType.ARROW, "Expected '=>' after '_'")
                default = self._parse_or_expression()

                if self._check(TokenType.COMMA):
                    self._advance()
            else:
                # Regular case
                pattern = self._parse_or_expression()
                self._consume(TokenType.ARROW, "Expected '=>' after pattern")
                result = self._parse_or_expression()
                cases.append(MatchCase(pattern=pattern, result=result))

                if self._check(TokenType.COMMA):
                    self._advance()

        self._consume(TokenType.RBRACE, ERROR_EXPECTED_BRACE_CLOSE)

        return PatternMatch(value=value, cases=cases, default=default)

    def _check_keyword(self, keyword: str) -> bool:
        """Check if current token is a specific keyword."""
        if self._is_at_end():
            return False
        token = self._peek()
        return token.type == TokenType.IDENTIFIER and token.value == keyword

    def _consume_keyword(self, keyword: str) -> Token:
        """Consume a specific keyword token."""
        if not self._check_keyword(keyword):
            from yaraast.parser.parser import ParserError

            raise ParserError(f"Expected keyword '{keyword}'", self._peek())
        return self._advance()

    def _peek_ahead(self, n: int) -> Token | None:
        """Peek ahead n tokens."""
        index = self.current + n
        if index < len(self.tokens):
            return self.tokens[index]
        return None

    def _consume(self, token_type: TokenType, error_message: str) -> Token:
        """Consume token of expected type or raise error."""
        if self._check(token_type):
            return self._advance()

        current = self._peek()
        from yaraast.parser.parser import ParserError

        raise ParserError(error_message, current)
