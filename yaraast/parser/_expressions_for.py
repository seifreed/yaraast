"""For/of expression parsing helpers."""

from __future__ import annotations

from yaraast.ast.conditions import ForExpression, ForOfExpression, OfExpression
from yaraast.ast.expressions import (
    ArrayAccess,
    Expression,
    FunctionCall,
    Identifier,
    MemberAccess,
    StringLiteral,
)
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.lexer import TokenType

from ._shared import ParserError


class ExpressionForMixin:
    """Mixin with quantifier/for/of expression parsing."""

    def _parse_for_expression(self, start_token=None) -> ForExpression:
        """Parse for expression."""
        start_token = start_token or self._peek()
        if self._match(TokenType.ANY):
            quantifier = "any"
        elif self._match(TokenType.ALL):
            quantifier = "all"
        elif self._match(TokenType.NONE):
            quantifier = "none"
        elif self._match(TokenType.INTEGER):
            quantifier = str(self._previous().value)
        else:
            msg = "Expected quantifier after 'for'"
            raise ParserError(msg, self._peek())

        if self._match(TokenType.OF):
            return self._parse_for_of_expression(quantifier, start_token)

        if not self._match(TokenType.IDENTIFIER):
            msg = "Expected variable name"
            raise ParserError(msg, self._peek())

        variable = self._previous().value

        # Support multi-variable for loops: for any k, v in dict : (...)
        if self._match(TokenType.COMMA) and self._match(TokenType.IDENTIFIER):
            variable = f"{variable},{self._previous().value}"

        if not self._match(TokenType.IN):
            msg = "Expected 'in' after variable"
            raise ParserError(msg, self._peek())

        iterable = self._parse_expression()

        if not self._match(TokenType.COLON):
            msg = "Expected ':' after iterable"
            raise ParserError(msg, self._peek())

        if not self._match(TokenType.LPAREN):
            msg = "Expected '(' after ':'"
            raise ParserError(msg, self._peek())

        body = self._parse_expression()

        if not self._match(TokenType.RPAREN):
            msg = "Expected ')' after for body"
            raise ParserError(msg, self._peek())

        return self._set_node_location_from_tokens(
            ForExpression(
                quantifier=quantifier,
                variable=variable,
                iterable=iterable,
                body=body,
            ),
            start_token,
            self._previous(),
        )

    def _parse_for_of_expression(self, quantifier: str, start_token=None) -> ForOfExpression:
        """Parse for...of expression."""
        start_token = start_token or self._peek()
        string_set = self._parse_expression()

        condition = None
        if self._match(TokenType.COLON) and self._match(TokenType.LPAREN):
            condition = self._parse_expression()
            if not self._match(TokenType.RPAREN):
                msg = "Expected ')' after condition"
                raise ParserError(msg, self._peek())

        return self._set_node_location_from_tokens(
            ForOfExpression(
                quantifier=quantifier,
                string_set=string_set,
                condition=condition,
            ),
            start_token,
            self._previous(),
        )

    def _parse_of_expression(self, quantifier: str) -> OfExpression:
        """Parse of expression."""
        start_token = self._previous()
        string_set = self._parse_of_string_set()
        return self._set_node_location_from_tokens(
            OfExpression(
                quantifier=self._set_node_location_from_token(
                    StringLiteral(value=quantifier), start_token
                ),
                string_set=string_set,
            ),
            start_token,
            self._previous(),
        )

    def _parse_of_string_set(self) -> Expression:
        """Parse string set for 'of' expression without consuming IN/AT postfix operators."""
        expr = self._parse_primary_expression()

        while True:
            if self._match(TokenType.DOT):
                expr = self._parse_of_member_access(expr)
            elif self._match(TokenType.LBRACKET):
                expr = self._parse_of_bracket_access(expr)
            elif self._match(TokenType.LPAREN):
                expr = self._parse_of_function_call(expr)
            else:
                break

        return expr

    def _parse_of_member_access(self, expr: Expression) -> MemberAccess:
        """Parse member access within 'of' string set context."""
        start_token = self._previous()
        if not self._match(TokenType.IDENTIFIER):
            msg = "Expected member name after '.'"
            raise ParserError(msg, self._peek())
        member = self._previous().value
        return self._set_node_location_from_tokens(
            MemberAccess(object=expr, member=member), start_token, self._previous()
        )

    def _parse_of_bracket_access(self, expr: Expression) -> ArrayAccess | DictionaryAccess:
        """Parse bracket access within 'of' string set context."""
        start_token = self._previous()
        index = self._parse_expression()
        if not self._match(TokenType.RBRACKET):
            msg = "Expected ']'"
            raise ParserError(msg, self._peek())
        if isinstance(index, StringLiteral):
            return self._set_node_location_from_tokens(
                DictionaryAccess(object=expr, key=index.value), start_token, self._previous()
            )
        return self._set_node_location_from_tokens(
            ArrayAccess(array=expr, index=index), start_token, self._previous()
        )

    def _parse_of_function_call(self, expr: Expression) -> FunctionCall:
        """Parse function call within 'of' string set context."""
        start_token = self._previous()
        args = self._collect_function_args()
        return self._build_function_call(expr, args, start_token)

    def _collect_function_args(self) -> list[Expression]:
        """Collect function arguments from parentheses."""
        args = []
        while not self._check(TokenType.RPAREN) and not self._is_at_end():
            args.append(self._parse_expression())
            if not self._match(TokenType.COMMA):
                break

        if not self._match(TokenType.RPAREN):
            msg = "Expected ')' after arguments"
            raise ParserError(msg, self._peek())
        return args

    def _build_function_call(
        self,
        expr: Expression,
        args: list[Expression],
        start_token=None,
    ) -> FunctionCall:
        """Build FunctionCall from expression and arguments."""
        start_token = start_token or self._previous()
        if isinstance(expr, Identifier):
            return self._set_node_location_from_tokens(
                FunctionCall(function=expr.name, arguments=args), start_token, self._previous()
            )
        if isinstance(expr, MemberAccess):
            function_name = self._resolve_function_name(expr)
            return self._set_node_location_from_tokens(
                FunctionCall(function=function_name, arguments=args), start_token, self._previous()
            )
        msg = "Invalid function call"
        raise ParserError(msg, self._peek())

    def _resolve_function_name(self, expr: MemberAccess) -> str:
        """Resolve function name from member access expression."""
        if isinstance(expr.object, Identifier):
            return f"{expr.object.name}.{expr.member}"
        if isinstance(expr.object, ModuleReference):
            return f"{expr.object.module}.{expr.member}"
        if isinstance(expr.object, MemberAccess):
            return f"{self._member_access_to_string(expr.object)}.{expr.member}"
        return f"unknown.{expr.member}"

    def _parse_expression(self) -> Expression:
        """Parse general expression."""
        return self._parse_or_expression()

    def _member_access_to_string(self, expr: MemberAccess) -> str:
        """Convert MemberAccess to string representation."""
        if isinstance(expr.object, Identifier):
            return f"{expr.object.name}.{expr.member}"
        if isinstance(expr.object, ModuleReference):
            return f"{expr.object.module}.{expr.member}"
        if isinstance(expr.object, MemberAccess):
            return f"{self._member_access_to_string(expr.object)}.{expr.member}"
        return f"unknown.{expr.member}"
