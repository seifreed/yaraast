"""Postfix expression parsing helpers."""

from __future__ import annotations

from yaraast.ast.conditions import AtExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    ArrayAccess,
    DoubleLiteral,
    Expression,
    FunctionCall,
    Identifier,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    StringWildcard,
)
from yaraast.ast.extern import ExternRuleReference
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.lexer import TokenType

from ._shared import ParserError

_BUILTIN_INTEGER_READ_FUNCTIONS: frozenset[str] = frozenset(
    {
        "uint8",
        "uint16",
        "uint32",
        "int8",
        "int16",
        "int32",
        "uint8be",
        "uint16be",
        "uint32be",
        "int8be",
        "int16be",
        "int32be",
        "uint16le",
        "uint32le",
        "int16le",
        "int32le",
    }
)


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

    def _parse_member_access(self, expr: Expression) -> MemberAccess | ExternRuleReference:
        """Parse member access expression (object.member)."""
        dot_token = self._previous()
        self._reject_string_reference_postfix(expr, dot_token)
        if not self._match(TokenType.IDENTIFIER):
            msg = "Expected member name after '.'"
            raise ParserError(msg, self._peek())
        member = str(self._previous().value)
        namespace = self._dotted_expression_name(expr)
        if namespace is not None and self._is_extern_rule_reference(member, namespace):
            node = ExternRuleReference(rule_name=member, namespace=namespace)
            if getattr(expr, "location", None) is not None:
                node.location = self._location_from_tokens(
                    self._synthetic_token_from_location(expr.location),
                    self._previous(),
                )
                return node
            return self._set_node_location_from_tokens(node, dot_token, self._previous())

        node = MemberAccess(object=expr, member=member)
        if getattr(expr, "location", None) is not None:
            node.location = self._location_from_tokens(
                self._synthetic_token_from_location(expr.location),
                self._previous(),
            )
            return node
        return self._set_node_location_from_tokens(node, dot_token, self._previous())

    def _dotted_expression_name(self, expr: Expression) -> str | None:
        if isinstance(expr, Identifier):
            return expr.name
        if isinstance(expr, ModuleReference):
            return expr.module
        if isinstance(expr, MemberAccess):
            prefix = self._dotted_expression_name(expr.object)
            if prefix is not None:
                return f"{prefix}.{expr.member}"
        return None

    def _parse_bracket_access(self, expr: Expression) -> ArrayAccess | DictionaryAccess:
        """Parse bracket access expression (array[index] or dict['key'])."""
        start_token = self._previous()
        self._reject_string_reference_postfix(expr, start_token)
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

    def _reject_string_reference_postfix(self, expr: Expression, token) -> None:
        if isinstance(
            expr,
            (StringIdentifier, StringWildcard, StringCount, StringOffset, StringLength),
        ):
            msg = "String references do not support postfix access"
            raise ParserError(msg, token)

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
            self._validate_builtin_integer_read_arity(node, start_token)
            node.location = self._location_from_tokens(
                self._synthetic_token_from_location(expr.location),
                self._previous(),
            )
            return node
        if isinstance(expr, Identifier):
            self._validate_builtin_integer_read_arity(node, start_token)
            return self._set_node_location_from_tokens(node, start_token, self._previous())
        msg = "Invalid function call"
        if isinstance(expr, MemberAccess):
            self._validate_builtin_integer_read_arity(node, start_token)
            return self._set_node_location_from_tokens(node, start_token, self._previous())
        raise ParserError(msg, self._peek())

    def _validate_builtin_integer_read_arity(self, node: FunctionCall, token) -> None:
        if node.function in _BUILTIN_INTEGER_READ_FUNCTIONS and len(node.arguments) != 1:
            msg = f"{node.function}() expects exactly 1 argument"
            raise ParserError(msg, token)

    def _parse_function_arguments(self) -> list[Expression]:
        """Parse function call arguments."""
        args = []
        while not self._check(TokenType.RPAREN) and not self._is_at_end():
            args.append(self._parse_expression())
            if not self._match(TokenType.COMMA):
                break
            if self._check(TokenType.RPAREN) or self._is_at_end():
                msg = "Expected argument after ','"
                raise ParserError(msg, self._peek())

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
        """Parse AT postfix expression ($string at offset or N of set at offset)."""
        if isinstance(expr, StringIdentifier | OfExpression):
            start_token = self._previous()
            if isinstance(expr, OfExpression):
                self._reject_percentage_of_postfix(expr, start_token)
            offset = self._parse_additive_expression()
            subject: str | Expression = expr.name if isinstance(expr, StringIdentifier) else expr
            node = AtExpression(string_id=subject, offset=offset)
            if getattr(expr, "location", None) is not None:
                node.location = self._location_from_tokens(
                    self._synthetic_token_from_location(expr.location),
                    self._previous(),
                )
                return node
            return self._set_node_location_from_tokens(node, start_token, self._previous())
        msg = "AT keyword can only be used with string identifiers or 'of' expressions"
        raise ParserError(msg, self._peek())

    def _parse_in_postfix(self, expr: Expression) -> InExpression:
        """Parse IN postfix expression ($string in range)."""
        if isinstance(expr, StringIdentifier):
            start_token = self._previous()
            range_expr = self._parse_parenthesized_range_after_in()
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
            self._reject_percentage_of_postfix(expr, start_token)
            range_expr = self._parse_parenthesized_range_after_in()
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

    def _reject_percentage_of_postfix(self, expr: OfExpression, token) -> None:
        if isinstance(expr.quantifier, DoubleLiteral | float):
            msg = "Percentage of-expressions do not support 'in' or 'at' restrictions"
            raise ParserError(msg, token)

    def _parse_parenthesized_range_after_in(self) -> RangeExpression:
        if not self._match(TokenType.LPAREN):
            msg = "Expected '(' after 'in'"
            raise ParserError(msg, self._peek())

        start_token = self._previous()
        low = self._parse_bitwise_or_expression()
        if self._is_parenthesized_range_bound(low):
            msg = "Unexpected parenthesized range"
            raise ParserError(msg, self._previous())
        if not self._match(TokenType.DOUBLE_DOT):
            msg = "Expected '..' in range"
            raise ParserError(msg, self._peek())
        high = self._parse_bitwise_or_expression()
        if self._is_parenthesized_range_bound(high):
            msg = "Unexpected parenthesized range"
            raise ParserError(msg, self._previous())
        if not self._match(TokenType.RPAREN):
            msg = "Expected ')' after range"
            raise ParserError(msg, self._peek())

        return self._set_node_location_from_tokens(
            RangeExpression(low=low, high=high), start_token, self._previous()
        )

    def _is_parenthesized_range_bound(self, expr: Expression) -> bool:
        return isinstance(expr, ParenthesesExpression) and isinstance(
            expr.expression, RangeExpression
        )
