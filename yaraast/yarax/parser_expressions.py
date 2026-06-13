"""Expression parsing mixin for YARA-X parser."""

from __future__ import annotations

from typing import Any, cast

from yaraast.ast.expressions import Expression, FunctionCall, Identifier
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
        expression = cast(Expression, self._parse_expression())
        self._require_expression_end("expression")
        return expression

    def _parse_expression(self: Any) -> Expression:
        """Parse a full expression with YARA-X primary expressions."""
        return cast(Expression, cast(Any, super())._parse_expression())

    def _parse_expression_allowing_contextual_keywords(self: Any) -> tuple[Expression, set[str]]:
        previous_allow: bool = getattr(self, "_allow_contextual_keyword_expression", False)
        previous_used: set[str] = getattr(self, "_used_contextual_keyword_expression", set())
        self._allow_contextual_keyword_expression = True
        self._used_contextual_keyword_expression: set[str] = set()
        try:
            expression = self._parse_expression()
            used_contextual = set(self._used_contextual_keyword_expression)
            return expression, used_contextual
        finally:
            self._allow_contextual_keyword_expression = previous_allow
            self._used_contextual_keyword_expression = previous_used

    def _require_expression_end(self: Any, context: str) -> None:
        if not self._is_at_end():
            raise ParserError(f"Unexpected token after {context}", self._peek())

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

        if getattr(self, "_allow_contextual_keyword_expression", False) and self._check_any(
            TokenType.AS, TokenType.INCLUDE
        ):
            token = self._advance()
            self._used_contextual_keyword_expression.add(str(token.value))
            return cast(
                Expression,
                self._set_node_location_from_token(Identifier(name=str(token.value)), token),
            )

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
            parameters.append(self._consume_local_identifier("Expected parameter").value)

            while self._check(TokenType.COMMA):
                self._advance()
                parameters.append(self._consume_local_identifier("Expected parameter").value)

        self._consume(TokenType.COLON, "Expected ':' after lambda parameters")

        local_names = self._local_identifier_scope_names(*parameters)
        with self._contextual_local_identifier_scope(local_names):
            body = self._parse_expression()
        return LambdaExpression(parameters=parameters, body=body)

    def _parse_pattern_match(self: Any) -> PatternMatch:
        """Parse pattern match expression."""
        self._consume_keyword("match")

        value = self._parse_expression()

        self._consume(TokenType.LBRACE, "Expected '{' after match value")

        cases: list[MatchCase] = []
        default = None

        while not self._check(TokenType.RBRACE):
            if self._check(TokenType.IDENTIFIER) and self._peek().value == "_":
                self._advance()
                self._consume_arrow()
                default = self._parse_expression()
                self._consume_match_case_separator()
                if not self._check(TokenType.RBRACE):
                    raise ParserError("Default match case must be last", self._peek())
            else:
                pattern = self._parse_expression()
                self._consume_arrow()
                result = self._parse_expression()
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

        index = self._parse_expression()

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
