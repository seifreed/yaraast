"""Primary expression parsing helpers."""

from __future__ import annotations

from dataclasses import fields, is_dataclass

from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import (
    BooleanLiteral,
    DoubleLiteral,
    Expression,
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    RangeExpression,
    RegexLiteral,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    StringWildcard,
)
from yaraast.ast.extern import ExternRuleReference
from yaraast.ast.modules import ModuleReference
from yaraast.lexer import TokenType

from ._shared import (
    KNOWN_MODULES,
    ParserError,
    split_regex_value,
    validate_regex_modifiers,
    validate_regex_pattern,
)


class ExpressionPrimaryMixin:
    """Mixin with primary expression parsing helpers."""

    def _parse_literal(self) -> Expression | None:
        """Parse literal expressions (integer, double, string, boolean, regex)."""
        if self._match(TokenType.INTEGER):
            return self._set_node_location_from_token(
                IntegerLiteral(value=self._previous().value), self._previous()
            )

        if self._match(TokenType.DOUBLE):
            return self._set_node_location_from_token(
                DoubleLiteral(value=self._previous().value), self._previous()
            )

        if self._match(TokenType.STRING):
            return self._set_node_location_from_token(
                StringLiteral(value=self._previous().value), self._previous()
            )

        if self._match(TokenType.BOOLEAN_TRUE):
            return self._set_node_location_from_token(BooleanLiteral(value=True), self._previous())

        if self._match(TokenType.BOOLEAN_FALSE):
            return self._set_node_location_from_token(BooleanLiteral(value=False), self._previous())

        if self._match(TokenType.REGEX):
            regex_val = self._previous().value
            try:
                pattern, modifiers = split_regex_value(regex_val)
                validate_regex_pattern(pattern)
                validate_regex_modifiers(modifiers)
            except ValueError as e:
                raise ParserError(str(e), self._previous()) from e

            return self._set_node_location_from_token(
                RegexLiteral(pattern=pattern, modifiers=modifiers), self._previous()
            )

        return None

    def _parse_string_reference(self) -> Expression | None:
        """Parse string reference expressions ($, #, @, !)."""
        if self._match(TokenType.STRING_IDENTIFIER):
            token = self._previous()
            name = token.value
            if name == "$" and not self._can_use_anonymous_string_reference():
                msg = "wrong use of anonymous string"
                raise ParserError(msg, token)
            if name.endswith("*"):
                if not self._can_use_string_wildcard_reference():
                    msg = "String wildcards can only be used in of string sets"
                    raise ParserError(msg, token)
                return self._set_node_location_from_token(StringWildcard(pattern=name), token)
            return self._set_node_location_from_token(StringIdentifier(name=name), token)

        if self._match(TokenType.STRING_COUNT):
            token = self._previous()
            string_id = token.value[1:]
            if not string_id and not self._can_use_anonymous_string_reference():
                msg = "wrong use of anonymous string"
                raise ParserError(msg, token)
            return self._set_node_location_from_token(StringCount(string_id=string_id), token)

        if self._match(TokenType.STRING_OFFSET):
            start_token = self._previous()
            string_id = start_token.value[1:]
            if not string_id and not self._can_use_anonymous_string_reference():
                msg = "wrong use of anonymous string"
                raise ParserError(msg, start_token)
            index = None
            if self._match(TokenType.LBRACKET):
                index = self._parse_expression()
                if not self._match(TokenType.RBRACKET):
                    msg = "Expected ']'"
                    raise ParserError(msg, self._peek())
            end_token = self._previous() if index is not None else start_token
            return self._set_node_location_from_tokens(
                StringOffset(string_id=string_id, index=index), start_token, end_token
            )

        if self._match(TokenType.STRING_LENGTH):
            start_token = self._previous()
            string_id = start_token.value[1:]
            if not string_id and not self._can_use_anonymous_string_reference():
                msg = "wrong use of anonymous string"
                raise ParserError(msg, start_token)
            index = None
            if self._match(TokenType.LBRACKET):
                index = self._parse_expression()
                if not self._match(TokenType.RBRACKET):
                    msg = "Expected ']'"
                    raise ParserError(msg, self._peek())
            end_token = self._previous() if index is not None else start_token
            return self._set_node_location_from_tokens(
                StringLength(string_id=string_id, index=index), start_token, end_token
            )

        return None

    def _can_use_anonymous_string_reference(self) -> bool:
        return bool(getattr(self, "_allow_anonymous_string_reference", False))

    def _can_use_string_wildcard_reference(self) -> bool:
        return bool(getattr(self, "_allow_string_wildcard_reference", False))

    def _parse_keyword_expression(self) -> Expression | None:
        """Parse keyword expressions (filesize, entrypoint, them)."""
        if self._match(TokenType.FILESIZE):
            return self._set_node_location_from_token(Identifier(name="filesize"), self._previous())

        if self._match(TokenType.ENTRYPOINT):
            return self._set_node_location_from_token(
                Identifier(name="entrypoint"), self._previous()
            )

        if self._match(TokenType.THEM):
            return self._set_node_location_from_token(Identifier(name="them"), self._previous())

        return None

    def _parse_quantifier_expression(self) -> Expression | None:
        """Parse quantifier expressions (any/all of, numeric of, percentage of)."""
        if self._check(TokenType.INTEGER):
            saved_pos = self.current
            self._advance()
            start_token = self._previous()
            quantifier_value = self._previous().value

            # Handle percentage quantifier: 50% of them
            if self._match(TokenType.MODULO):
                if self._match(TokenType.OF):
                    if not 1 <= quantifier_value <= 100:
                        msg = "Percentage quantifier must be between 1 and 100"
                        raise ParserError(msg, start_token)
                    string_set = self._parse_of_string_set()
                    quantifier = self._set_node_location_from_token(
                        DoubleLiteral(value=int(quantifier_value) / 100.0), start_token
                    )
                    return self._set_node_location_from_tokens(
                        OfExpression(quantifier=quantifier, string_set=string_set),
                        start_token,
                        self._previous(),
                    )
                self.current = saved_pos
                return None

            if self._match(TokenType.OF):
                string_set = self._parse_of_string_set()
                quantifier = self._set_node_location_from_token(
                    IntegerLiteral(value=quantifier_value), start_token
                )
                return self._set_node_location_from_tokens(
                    OfExpression(quantifier=quantifier, string_set=string_set),
                    start_token,
                    self._previous(),
                )
            self.current = saved_pos

        if self._match(TokenType.ANY, TokenType.ALL, TokenType.NONE):
            quantifier = self._previous().value
            if self._match(TokenType.OF):
                return self._parse_of_expression(quantifier)

        return None

    def _parse_parenthesized_expression(self) -> Expression | None:
        """Parse parenthesized expressions and set expressions."""
        if not self._match(TokenType.LPAREN):
            return None
        start_token = self._previous()

        exprs = [self._parse_expression()]

        if self._match(TokenType.COMMA):
            if not getattr(self, "_allow_set_expression", False):
                msg = "Unexpected set expression"
                raise ParserError(msg, start_token)
            if self._check(TokenType.RPAREN) or self._is_at_end():
                msg = "Expected expression after ',' in set"
                raise ParserError(msg, self._peek())

            while True:
                exprs.append(self._parse_expression())
                if not self._match(TokenType.COMMA):
                    break
                if self._check(TokenType.RPAREN) or self._is_at_end():
                    msg = "Expected expression after ',' in set"
                    raise ParserError(msg, self._peek())

            if not self._match(TokenType.RPAREN):
                msg = "Expected ')' after set elements"
                raise ParserError(msg, self._peek())

            if any(self._contains_range_expression(expr) for expr in exprs):
                msg = "Range expressions cannot be set elements"
                raise ParserError(msg, start_token)

            return self._set_node_location_from_tokens(
                SetExpression(elements=exprs), start_token, self._previous()
            )

        if not self._match(TokenType.RPAREN):
            msg = "Expected ')' after expression"
            raise ParserError(msg, self._peek())

        if self._match(TokenType.OF):
            string_set = self._parse_of_string_set()
            return self._set_node_location_from_tokens(
                OfExpression(quantifier=exprs[0], string_set=string_set),
                start_token,
                self._previous(),
            )

        return self._set_node_location_from_tokens(
            ParenthesesExpression(expression=exprs[0]), start_token, self._previous()
        )

    def _parse_primary_expression(self) -> Expression:
        """Parse primary expression."""
        for parser in self._get_primary_expression_parsers():
            result = parser()
            if result is not None:
                return result

        msg = f"Unexpected token: {self._peek().value}"
        raise ParserError(msg, self._peek())

    def _get_primary_expression_parsers(self) -> list:
        """Return list of primary expression parsers to try in order."""
        return [
            self._parse_quantifier_expression,
            self._parse_literal,
            self._parse_string_reference,
            self._parse_keyword_expression,
            self._try_parse_identifier,
            self._parse_parenthesized_expression,
            self._try_parse_for_expression,
            self._try_parse_string_operation,
        ]

    def _try_parse_identifier(self) -> Expression | None:
        """Try to parse an identifier or module reference."""
        if not self._match(TokenType.IDENTIFIER):
            return None
        token = self._previous()
        name = self._previous().value
        if self._can_use_string_wildcard_reference() and self._match(TokenType.MULTIPLY):
            return self._set_node_location_from_tokens(
                StringWildcard(pattern=f"{name}*"), token, self._previous()
            )
        if self._can_use_string_wildcard_reference():
            return self._set_node_location_from_token(Identifier(name=name), token)
        if self._is_extern_rule_reference(str(name)):
            return self._set_node_location_from_token(
                ExternRuleReference(rule_name=str(name)), token
            )
        if name in KNOWN_MODULES:
            return self._set_node_location_from_token(ModuleReference(module=name), token)
        return self._set_node_location_from_token(Identifier(name=name), token)

    def _try_parse_for_expression(self) -> Expression | None:
        """Try to parse a for expression."""
        if not self._match(TokenType.FOR):
            return None
        return self._parse_for_expression(self._previous())

    def _try_parse_string_operation(self) -> Expression | None:
        """Try to parse string identifier/wildcard (AT/IN handled by postfix parser)."""
        if not self._check(TokenType.STRING_IDENTIFIER):
            return None
        start_token = self._advance()
        string_id = start_token.value

        if string_id.endswith("*"):
            return self._set_node_location_from_token(
                StringWildcard(pattern=string_id), start_token
            )
        return self._set_node_location_from_token(StringIdentifier(name=string_id), start_token)

    def _contains_range_expression(self, expr: Expression) -> bool:
        if isinstance(expr, RangeExpression):
            return True
        if not is_dataclass(expr):
            return False

        for field in fields(expr):
            value = getattr(expr, field.name)
            if isinstance(value, Expression) and self._contains_range_expression(value):
                return True
            if isinstance(value, list) and any(
                isinstance(item, Expression) and self._contains_range_expression(item)
                for item in value
            ):
                return True

        return False
