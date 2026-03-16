"""Condition parsing mixin for YARA-X parser."""

from __future__ import annotations

from yaraast.ast.conditions import Condition
from yaraast.lexer.tokens import TokenType
from yaraast.yarax.ast_nodes import WithDeclaration, WithStatement
from yaraast.yarax.parser_helpers import ERROR_EXPECTED_VARIABLE


class YaraXParserConditionsMixin:
    """Condition parsing for YARA-X."""

    def _parse_condition(self) -> Condition:
        """Parse condition with YARA-X extensions."""
        if self._check_keyword("with"):
            return self._parse_with_statement()
        return super()._parse_condition()

    def parse_condition(self) -> Condition:
        """Parse condition with YARA-X extensions."""
        return self._parse_condition()

    def _parse_with_statement(self) -> WithStatement:
        """Parse 'with' statement."""
        self._consume_keyword("with")

        declarations = [self._parse_with_declaration()]
        while self._check(TokenType.COMMA):
            self._advance()
            declarations.append(self._parse_with_declaration())

        self._consume(TokenType.COLON, "Expected ':' after with declarations")
        body = super()._parse_condition()
        return WithStatement(declarations=declarations, body=body)

    def _parse_with_declaration(self) -> WithDeclaration:
        """Parse single declaration in with statement."""
        # YARA-X allows local variable names like `pdfpos` (IDENTIFIER) in `with`.
        # Keep support for `$name` style string identifiers as well.
        if self._check(TokenType.STRING_IDENTIFIER) or self._check(TokenType.IDENTIFIER):
            identifier = self._advance().value
        else:
            from yaraast.parser.parser import ParserError

            raise ParserError(ERROR_EXPECTED_VARIABLE, self._peek())
        self._consume(TokenType.ASSIGN, "Expected '=' in with declaration")
        value = self._parse_or_expression()
        return WithDeclaration(identifier=identifier, value=value)
