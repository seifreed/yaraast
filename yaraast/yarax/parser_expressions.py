"""Expression parsing mixin for YARA-X parser."""

from __future__ import annotations

from yaraast.ast.expressions import Expression, FunctionCall
from yaraast.lexer.tokens import TokenType
from yaraast.yarax.ast_nodes import (
    LambdaExpression,
    MatchCase,
    PatternMatch,
    TupleExpression,
    TupleIndexing,
)
from yaraast.yarax.parser_helpers import ERROR_EXPECTED_BRACE_CLOSE, ERROR_EXPECTED_BRACKET_CLOSE


class YaraXParserExpressionsMixin:
    """Expression parsing for YARA-X."""

    def parse_expression(self) -> Expression:
        """Parse expression with YARA-X extensions."""
        if self._check(TokenType.LBRACKET):
            return self._parse_list_or_comprehension()

        if self._check(TokenType.LBRACE):
            return self._parse_dict_or_comprehension()

        if self._check(TokenType.LPAREN):
            return self._parse_tuple_or_parentheses()

        if self._check_keyword("lambda"):
            return self._parse_lambda()

        if self._check_keyword("match"):
            return self._parse_pattern_match()

        return super()._parse_or_expression()

    def parse_primary_expression(self) -> Expression:
        """Parse primary expression with YARA-X extensions."""
        expr = super()._parse_primary_expression()

        while self._check(TokenType.LBRACKET):
            self._advance()

            if self._check(TokenType.COLON):
                expr = self._parse_slice_expression(expr, None)
            else:
                index = self._parse_or_expression()

                if self._check(TokenType.COLON):
                    expr = self._parse_slice_expression(expr, index)
                else:
                    self._consume(TokenType.RBRACKET, ERROR_EXPECTED_BRACKET_CLOSE)
                    from yaraast.ast.expressions import ArrayAccess

                    expr = ArrayAccess(array=expr, index=index)

        return expr

    def _parse_lambda(self) -> LambdaExpression:
        """Parse lambda expression."""
        self._consume_keyword("lambda")

        parameters = []
        if not self._check(TokenType.COLON):
            parameters.append(self._consume(TokenType.IDENTIFIER, "Expected parameter").value)

            while self._check(TokenType.COMMA):
                self._advance()
                parameters.append(self._consume(TokenType.IDENTIFIER, "Expected parameter").value)

        self._consume(TokenType.COLON, "Expected ':' after lambda parameters")

        body = self._parse_or_expression()
        return LambdaExpression(parameters=parameters, body=body)

    def _parse_pattern_match(self) -> PatternMatch:
        """Parse pattern match expression."""
        self._consume_keyword("match")

        value = self._parse_or_expression()

        self._consume(TokenType.LBRACE, "Expected '{' after match value")

        cases = []
        default = None

        while not self._check(TokenType.RBRACE):
            if self._check(TokenType.IDENTIFIER) and self._peek().value == "_":
                self._advance()
                self._consume_arrow()
                default = self._parse_or_expression()

                if self._check(TokenType.COMMA):
                    self._advance()
            else:
                pattern = self._parse_or_expression()
                self._consume_arrow()
                result = self._parse_or_expression()
                cases.append(MatchCase(pattern=pattern, result=result))

                if self._check(TokenType.COMMA):
                    self._advance()

        self._consume(TokenType.RBRACE, ERROR_EXPECTED_BRACE_CLOSE)

        return PatternMatch(value=value, cases=cases, default=default)

    def _parse_bracket_access(self, expr: Expression):
        """Parse bracket access with slice and tuple-indexing support."""
        if self._check(TokenType.COLON):
            return self._parse_slice_expression(expr, None)

        index = self._parse_or_expression()

        if self._check(TokenType.COLON):
            return self._parse_slice_expression(expr, index)

        self._consume(TokenType.RBRACKET, ERROR_EXPECTED_BRACKET_CLOSE)

        from yaraast.ast.expressions import ArrayAccess

        if isinstance(expr, TupleExpression | FunctionCall):
            return TupleIndexing(tuple_expr=expr, index=index)

        return ArrayAccess(array=expr, index=index)
