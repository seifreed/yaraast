"""Expression parsing mixin for YARA-X parser."""

from __future__ import annotations

from typing import Any, cast

from yaraast.ast.expressions import Expression, FunctionCall
from yaraast.lexer.tokens import TokenType
from yaraast.parser._shared import ParserError
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

    _parsing_of_string_set: bool = False

    def parse_expression(self: Any) -> Expression:
        """Parse expression with YARA-X extensions."""
        return cast(Expression, self._parse_expression())

    def _parse_expression(self: Any) -> Expression:
        """Parse a full expression with YARA-X primary expressions."""
        return cast(Expression, self._parse_or_expression())

    def _parse_primary_expression(self: Any) -> Expression:
        """Parse primary expression with YARA-X extensions."""
        if self._parsing_of_string_set:
            return cast(Expression, cast(Any, super())._parse_primary_expression())

        if self._check(TokenType.LBRACKET):
            return cast(Expression, self._parse_list_or_comprehension())

        if self._check(TokenType.LBRACE):
            return cast(Expression, self._parse_dict_or_comprehension())

        if self._check(TokenType.LPAREN):
            return cast(Expression, self._parse_tuple_or_parentheses())

        if self._check_keyword("lambda"):
            return cast(Expression, self._parse_lambda())

        if self._check_keyword("match"):
            return cast(Expression, self._parse_pattern_match())

        return cast(Expression, cast(Any, super())._parse_primary_expression())

    def parse_primary_expression(self: Any) -> Expression:
        """Parse primary expression and postfix operators with YARA-X extensions."""
        return cast(Expression, self._parse_postfix_expression())

    def _parse_of_string_set(self: Any) -> Expression:
        """Parse YARA string sets without treating parenthesized sets as tuples."""
        old_value = self._parsing_of_string_set
        self._parsing_of_string_set = True
        try:
            return cast(Expression, cast(Any, super())._parse_of_string_set())
        finally:
            self._parsing_of_string_set = old_value

    def _parse_lambda(self: Any) -> LambdaExpression:
        """Parse lambda expression."""
        self._consume_keyword("lambda")

        parameters: list[str] = []
        if not self._check(TokenType.COLON):
            parameters.append(self._consume(TokenType.IDENTIFIER, "Expected parameter").value)

            while self._check(TokenType.COMMA):
                self._advance()
                parameters.append(self._consume(TokenType.IDENTIFIER, "Expected parameter").value)

        self._consume(TokenType.COLON, "Expected ':' after lambda parameters")

        body = self.parse_expression()
        return LambdaExpression(parameters=parameters, body=body)

    def _parse_pattern_match(self: Any) -> PatternMatch:
        """Parse pattern match expression."""
        self._consume_keyword("match")

        value = self.parse_expression()

        self._consume(TokenType.LBRACE, "Expected '{' after match value")

        cases: list[MatchCase] = []
        default = None

        while not self._check(TokenType.RBRACE):
            if self._check(TokenType.IDENTIFIER) and self._peek().value == "_":
                self._advance()
                self._consume_arrow()
                default = self.parse_expression()
                self._consume_match_case_separator()
                if not self._check(TokenType.RBRACE):
                    raise ParserError("Default match case must be last", self._peek())
            else:
                pattern = self.parse_expression()
                self._consume_arrow()
                result = self.parse_expression()
                cases.append(MatchCase(pattern=pattern, result=result))
                self._consume_match_case_separator()

        self._consume(TokenType.RBRACE, ERROR_EXPECTED_BRACE_CLOSE)

        return PatternMatch(value=value, cases=cases, default=default)

    def _consume_match_case_separator(self: Any) -> None:
        if self._check(TokenType.COMMA):
            self._advance()
            return
        if not self._check(TokenType.RBRACE):
            self._consume(TokenType.COMMA, "Expected ',' or '}' after match case")

    def _parse_bracket_access(self: Any, expr: Expression) -> Expression:
        """Parse bracket access with slice and tuple-indexing support."""
        if self._check(TokenType.COLON):
            return cast(Expression, self._parse_slice_expression(expr, None))

        index = self.parse_expression()

        if self._check(TokenType.COLON):
            return cast(Expression, self._parse_slice_expression(expr, index))

        self._consume(TokenType.RBRACKET, ERROR_EXPECTED_BRACKET_CLOSE)

        from yaraast.ast.expressions import ArrayAccess, StringLiteral
        from yaraast.ast.modules import DictionaryAccess

        if isinstance(index, StringLiteral):
            return DictionaryAccess(object=expr, key=index.value)

        if isinstance(expr, TupleExpression | FunctionCall):
            return TupleIndexing(tuple_expr=expr, index=index)

        return ArrayAccess(array=expr, index=index)
