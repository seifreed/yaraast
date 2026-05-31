"""Condition parsing mixin for YARA-X parser."""

from __future__ import annotations

from typing import Any, cast

from yaraast.ast.conditions import Condition
from yaraast.lexer.tokens import TokenType
from yaraast.parser._shared import ParserError
from yaraast.yarax.ast_nodes import WithDeclaration, WithStatement
from yaraast.yarax.parser_helpers import ERROR_EXPECTED_VARIABLE


class YaraXParserConditionsMixin:
    """Condition parsing for YARA-X."""

    def _parse_condition(self: Any) -> Condition:
        """Parse condition with YARA-X extensions."""
        if self._check_keyword("with"):
            return cast(Condition, self._parse_with_statement())
        return cast(Condition, self.parse_expression())

    def parse_condition(self: Any) -> Condition:
        """Parse condition with YARA-X extensions."""
        return cast(Condition, self._parse_condition())

    def _parse_with_statement(self: Any) -> WithStatement:
        """Parse 'with' statement."""
        self._consume_keyword("with")

        declarations = [self._parse_with_declaration()]
        while self._check(TokenType.COMMA):
            self._advance()
            declarations.append(self._parse_with_declaration())

        self._consume(TokenType.COLON, "Expected ':' after with declarations")
        body = self._parse_condition()
        return WithStatement(declarations=declarations, body=body)

    def _parse_with_declaration(self: Any) -> WithDeclaration:
        """Parse single declaration in with statement."""
        # YARA-X allows local variable names like `pdfpos` (IDENTIFIER) in `with`.
        # Keep support for `$name` style string identifiers as well.
        if self._check(TokenType.STRING_IDENTIFIER) or self._check(TokenType.IDENTIFIER):
            identifier = self._advance().value
        else:
            raise ParserError(ERROR_EXPECTED_VARIABLE, self._peek())
        self._consume(TokenType.ASSIGN, "Expected '=' in with declaration")
        value = self.parse_expression()
        return WithDeclaration(identifier=identifier, value=value)
