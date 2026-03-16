"""Postfix expression parsing helpers."""

from __future__ import annotations

from yaraast.ast.conditions import AtExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    ArrayAccess,
    Expression,
    FunctionCall,
    Identifier,
    MemberAccess,
    StringIdentifier,
    StringLiteral,
)
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.lexer import TokenType

from ._shared import ParserError


class ExpressionPostfixMixin:
    """Mixin with postfix expression parsing helpers."""

    def _parse_postfix_expression(self) -> Expression:
        """Parse postfix expression."""
        expr = self._parse_primary_expression()

        while True:
            if self._match(TokenType.DOT):
                expr = self._parse_member_access(expr)
            elif self._match(TokenType.LBRACKET):
                expr = self._parse_bracket_access(expr)
            elif self._match(TokenType.LPAREN):
                expr = self._parse_function_call_postfix(expr)
            elif self._match(TokenType.AT):
                expr = self._parse_at_postfix(expr)
            elif self._match(TokenType.IN):
                expr = self._parse_in_postfix(expr)
            else:
                break

        return expr

    def _parse_member_access(self, expr: Expression) -> MemberAccess:
        """Parse member access expression (object.member)."""
        dot_token = self._previous()
        if not self._match(TokenType.IDENTIFIER):
            msg = "Expected member name after '.'"
            raise ParserError(msg, self._peek())
        member = self._previous().value
        node = MemberAccess(object=expr, member=member)
        if getattr(expr, "location", None) is not None:
            node.location = self._location_from_tokens(
                self._synthetic_token_from_location(expr.location),
                self._previous(),
            )
            return node
        return self._set_node_location_from_tokens(node, dot_token, self._previous())

    def _parse_bracket_access(self, expr: Expression) -> ArrayAccess | DictionaryAccess:
        """Parse bracket access expression (array[index] or dict['key'])."""
        start_token = self._previous()
        index = self._parse_expression()
        if not self._match(TokenType.RBRACKET):
            msg = "Expected ']'"
            raise ParserError(msg, self._peek())
        node = (
            DictionaryAccess(object=expr, key=index.value)
            if isinstance(index, StringLiteral)
            else ArrayAccess(array=expr, index=index)
        )
        if getattr(expr, "location", None) is not None:
            node.location = self._location_from_tokens(
                self._synthetic_token_from_location(expr.location),
                self._previous(),
            )
            return node
        return self._set_node_location_from_tokens(node, start_token, self._previous())

    def _parse_function_call_postfix(self, expr: Expression) -> FunctionCall:
        """Parse function call expression (func(args))."""
        start_token = self._previous()
        args = self._parse_function_arguments()

        if isinstance(expr, Identifier):
            node = FunctionCall(function=expr.name, arguments=args)
        elif isinstance(expr, MemberAccess):
            function_name = self._build_function_name_from_member_access(expr)
            node = FunctionCall(function=function_name, arguments=args)
        else:
            msg = "Invalid function call"
            raise ParserError(msg, self._peek())
        if getattr(expr, "location", None) is not None:
            node.location = self._location_from_tokens(
                self._synthetic_token_from_location(expr.location),
                self._previous(),
            )
            return node
        if isinstance(expr, Identifier):
            return self._set_node_location_from_tokens(node, start_token, self._previous())
        msg = "Invalid function call"
        if isinstance(expr, MemberAccess):
            return self._set_node_location_from_tokens(node, start_token, self._previous())
        raise ParserError(msg, self._peek())

    def _parse_function_arguments(self) -> list[Expression]:
        """Parse function call arguments."""
        args = []
        while not self._check(TokenType.RPAREN) and not self._is_at_end():
            args.append(self._parse_expression())
            if not self._match(TokenType.COMMA):
                break

        if not self._match(TokenType.RPAREN):
            msg = "Expected ')' after arguments"
            raise ParserError(msg, self._peek())
        return args

    def _build_function_name_from_member_access(self, expr: MemberAccess) -> str:
        """Build function name from member access expression."""
        if isinstance(expr.object, Identifier):
            return f"{expr.object.name}.{expr.member}"
        if isinstance(expr.object, ModuleReference):
            return f"{expr.object.module}.{expr.member}"
        if isinstance(expr.object, MemberAccess):
            return f"{self._member_access_to_string(expr.object)}.{expr.member}"
        return f"unknown.{expr.member}"

    def _parse_at_postfix(self, expr: Expression) -> AtExpression:
        """Parse AT postfix expression ($string at offset)."""
        if isinstance(expr, StringIdentifier):
            start_token = self._previous()
            offset = self._parse_additive_expression()
            node = AtExpression(string_id=expr.name, offset=offset)
            if getattr(expr, "location", None) is not None:
                node.location = self._location_from_tokens(
                    self._synthetic_token_from_location(expr.location),
                    self._previous(),
                )
                return node
            return self._set_node_location_from_tokens(node, start_token, self._previous())
        msg = "AT keyword can only be used with string identifiers"
        raise ParserError(msg, self._peek())

    def _parse_in_postfix(self, expr: Expression) -> InExpression:
        """Parse IN postfix expression ($string in range)."""
        if isinstance(expr, StringIdentifier):
            start_token = self._previous()
            range_expr = self._parse_additive_expression()
            node = InExpression(subject=expr.name, range=range_expr)
            if getattr(expr, "location", None) is not None:
                node.location = self._location_from_tokens(
                    self._synthetic_token_from_location(expr.location),
                    self._previous(),
                )
                return node
            return self._set_node_location_from_tokens(node, start_token, self._previous())
        if isinstance(expr, OfExpression):
            start_token = self._previous()
            range_expr = self._parse_additive_expression()
            node = InExpression(subject=expr, range=range_expr)
            if getattr(expr, "location", None) is not None:
                node.location = self._location_from_tokens(
                    self._synthetic_token_from_location(expr.location),
                    self._previous(),
                )
                return node
            return self._set_node_location_from_tokens(node, start_token, self._previous())
        msg = "IN keyword can only be used with string identifiers or 'of' expressions"
        raise ParserError(msg, self._peek())
