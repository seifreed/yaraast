"""For/of expression parsing helpers."""

from __future__ import annotations

from yaraast.ast.conditions import ForExpression, ForOfExpression, OfExpression, QuantifierValue
from yaraast.ast.expressions import (
    ArrayAccess,
    BooleanLiteral,
    Expression,
    FunctionCall,
    Identifier,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    RegexLiteral,
    SetExpression,
    StringIdentifier,
    StringLiteral,
    StringWildcard,
)
from yaraast.ast.modules import DictionaryAccess
from yaraast.lexer import TokenType

from ._shared import ParserError, max_expression_depth

_CONTEXTUAL_LOCAL_IDENTIFIER_TOKENS = (TokenType.IDENTIFIER, TokenType.AS, TokenType.INCLUDE)


def _for_loop_variable_names(variable: str) -> set[str]:
    return {part.strip() for part in variable.split(",") if part.strip()}


class ExpressionForMixin:
    """Mixin with quantifier/for/of expression parsing."""

    _expression_depth: int

    def _parse_for_expression(self, start_token=None) -> ForExpression | ForOfExpression:
        """Parse for expression."""
        start_token = start_token or self._peek()
        quantifier: QuantifierValue
        if self._match(TokenType.ANY):
            quantifier = "any"
        elif self._match(TokenType.ALL):
            quantifier = "all"
        elif self._match(TokenType.NONE):
            quantifier = "none"
        else:
            quantifier = self._parse_for_quantifier_expression()

        if self._match(TokenType.OF):
            return self._parse_for_of_expression(quantifier, start_token)

        if not self._match_for_loop_identifier():
            msg = "Expected variable name"
            raise ParserError(msg, self._peek())

        variable = self._previous().value

        # Support multi-variable for loops: for any k, v in dict : (...)
        if self._match(TokenType.COMMA):
            if not self._match_for_loop_identifier():
                msg = "Expected second variable after ','"
                raise ParserError(msg, self._peek())
            variable = f"{variable},{self._previous().value}"

        if not self._match(TokenType.IN):
            msg = "Expected 'in' after variable"
            raise ParserError(msg, self._peek())

        if not self._check_any(TokenType.LPAREN, TokenType.IDENTIFIER):
            msg = "Expected identifier or '(' after 'in'"
            raise ParserError(msg, self._peek())

        previous_allow_range = getattr(self, "_allow_range_expression", False)
        previous_allow_set = getattr(self, "_allow_set_expression", False)
        self._allow_range_expression = True
        self._allow_set_expression = True
        try:
            iterable = self._parse_expression()
        finally:
            self._allow_range_expression = previous_allow_range
            self._allow_set_expression = previous_allow_set
        if self._is_nested_parenthesized_range(iterable):
            msg = "Unexpected parenthesized range"
            raise ParserError(msg, self._previous())

        if not self._match(TokenType.COLON):
            msg = "Expected ':' after iterable"
            raise ParserError(msg, self._peek())

        if not self._match(TokenType.LPAREN):
            msg = "Expected '(' after ':'"
            raise ParserError(msg, self._peek())

        self._contextual_local_identifiers.append(_for_loop_variable_names(variable))
        try:
            body = self._parse_expression()
        finally:
            self._contextual_local_identifiers.pop()

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

    def _match_for_loop_identifier(self) -> bool:
        return self._match(*_CONTEXTUAL_LOCAL_IDENTIFIER_TOKENS)

    def _parse_for_quantifier_expression(self) -> QuantifierValue:
        """Parse a non-keyword 'for' quantifier as a primary expression.

        YARA's grammar defines the loop quantifier as ``primary_expression``,
        so any arithmetic/bitwise expression is accepted (for example
        ``for #a i in ...`` or ``for filesize i in ...``).  Boolean, relational
        and string-reference forms are rejected as syntax errors, matching
        libyara.
        """
        token = self._peek()
        if token.type == TokenType.COLON or self._is_at_end():
            msg = "Expected quantifier after 'for'"
            raise ParserError(msg, token)
        previous_suppress_of = getattr(self, "_suppress_of_postfix", False)
        self._suppress_of_postfix = True
        try:
            quantifier = self._parse_bitwise_or_expression()
        except ParserError as exc:
            msg = "Expected quantifier after 'for'"
            raise ParserError(msg, token) from exc
        finally:
            self._suppress_of_postfix = previous_suppress_of
        self._reject_invalid_for_quantifier(quantifier, token)
        return quantifier

    def _reject_invalid_for_quantifier(self, quantifier: Expression, token) -> None:
        """Reject quantifier nodes libyara treats as syntax errors."""
        if isinstance(quantifier, BooleanLiteral | RegexLiteral | StringIdentifier):
            msg = "Expected quantifier after 'for'"
            raise ParserError(msg, token)

    def _is_nested_parenthesized_range(self, iterable: Expression) -> bool:
        if not isinstance(iterable, ParenthesesExpression):
            return False

        inner = iterable.expression
        if isinstance(inner, ParenthesesExpression) and isinstance(
            inner.expression, RangeExpression
        ):
            return True

        if isinstance(inner, RangeExpression):
            return self._range_has_parenthesized_range_bound(inner)

        return False

    def _range_has_parenthesized_range_bound(self, range_expr: RangeExpression) -> bool:
        return self._is_parenthesized_range_bound(
            range_expr.low
        ) or self._is_parenthesized_range_bound(range_expr.high)

    def _is_parenthesized_range_bound(self, expr: Expression) -> bool:
        return isinstance(expr, ParenthesesExpression) and isinstance(
            expr.expression, RangeExpression
        )

    def _parse_for_of_expression(
        self,
        quantifier: QuantifierValue,
        start_token=None,
    ) -> ForOfExpression:
        """Parse for...of expression."""
        start_token = start_token or self._peek()
        string_set = self._parse_of_string_set()
        self._validate_for_of_string_set(string_set)

        if not self._match(TokenType.COLON):
            msg = "Expected ':' after string set"
            raise ParserError(msg, self._peek())
        if not self._match(TokenType.LPAREN):
            msg = "Expected '(' after ':'"
            raise ParserError(msg, self._peek())
        previous_allow_anonymous = getattr(self, "_allow_anonymous_string_reference", False)
        self._allow_anonymous_string_reference = True
        try:
            condition = self._parse_expression()
        finally:
            self._allow_anonymous_string_reference = previous_allow_anonymous
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
        previous_allow_wildcard = getattr(self, "_allow_string_wildcard_reference", False)
        previous_allow_set = getattr(self, "_allow_set_expression", False)
        self._allow_string_wildcard_reference = True
        self._allow_set_expression = True
        try:
            expr = self._parse_primary_expression()
            self._reject_parenthesized_them_set(expr)

            while True:
                if self._match(TokenType.DOT):
                    expr = self._parse_of_member_access(expr)
                elif self._match(TokenType.LBRACKET):
                    expr = self._parse_of_bracket_access(expr)
                elif self._match(TokenType.LPAREN):
                    expr = self._parse_of_function_call(expr)
                else:
                    break
            self._validate_of_string_set(expr)
        finally:
            self._allow_string_wildcard_reference = previous_allow_wildcard
            self._allow_set_expression = previous_allow_set

        return expr

    def _validate_of_string_set(self, expr: Expression) -> None:
        kind = self._of_string_set_kind(expr, top_level=True)
        if kind is not None:
            return
        msg = "Expected string or rule identifier in of string set"
        raise ParserError(msg, self._previous())

    def _validate_for_of_string_set(self, expr: Expression) -> None:
        kind = self._of_string_set_kind(expr, top_level=True)
        if kind == "string":
            return
        msg = "Expected string identifiers in for...of string set"
        raise ParserError(msg, self._previous())

    def _of_string_set_kind(self, expr: Expression, *, top_level: bool = False) -> str | None:
        if isinstance(expr, StringIdentifier):
            return "string"
        if isinstance(expr, StringWildcard):
            return "string" if expr.pattern.startswith("$") else "rule"
        if isinstance(expr, Identifier):
            if expr.name == "them":
                return "string" if top_level else None
            if expr.name in {"filesize", "entrypoint"}:
                return None
            return "rule"
        if isinstance(expr, ParenthesesExpression):
            return self._of_string_set_kind(expr.expression)
        if isinstance(expr, SetExpression):
            return self._of_set_expression_kind(expr)
        return None

    def _of_set_expression_kind(self, expr: SetExpression) -> str | None:
        kind: str | None = None
        for element in expr.elements:
            element_kind = self._of_string_set_kind(element)
            if element_kind is None:
                return None
            if kind is None:
                kind = element_kind
            elif kind != element_kind:
                msg = "Mixed string and rule sets are not valid in of string sets"
                raise ParserError(msg, self._previous())
        return kind

    def _reject_parenthesized_them_set(self, expr: Expression) -> None:
        if (
            isinstance(expr, ParenthesesExpression)
            and isinstance(expr.expression, Identifier)
            and expr.expression.name == "them"
        ):
            msg = "'them' cannot be parenthesized in an of-expression string set"
            raise ParserError(msg, self._previous())

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
            if self._check(TokenType.RPAREN) or self._is_at_end():
                msg = "Expected argument after ','"
                raise ParserError(msg, self._peek())

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
            call = self._build_member_function_call(expr, args)
            return self._set_node_location_from_tokens(call, start_token, self._previous())
        msg = "Invalid function call"
        raise ParserError(msg, self._peek())

    def _parse_expression(self) -> Expression:
        """Parse general expression.

        Guards against unbounded recursion from pathologically nested input by
        tracking the current expression nesting depth and rejecting input that
        gets close to the interpreter recursion limit with a clean ParserError
        instead of letting the recursive descent exhaust the interpreter stack.
        """
        depth = getattr(self, "_expression_depth", 0) + 1
        limit = max_expression_depth()
        if depth > limit:
            msg = f"expression nesting too deep (max: {limit})"
            raise ParserError(msg, self._peek())
        self._expression_depth = depth
        try:
            return self._parse_or_expression()
        finally:
            self._expression_depth = depth - 1
