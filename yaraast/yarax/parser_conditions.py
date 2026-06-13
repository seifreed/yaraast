"""Condition parsing mixin for YARA-X parser."""

from __future__ import annotations

from typing import Any, cast

from yaraast.ast.conditions import Condition
from yaraast.lexer.tokens import TokenType
from yaraast.yarax.ast_nodes import WithDeclaration, WithStatement
from yaraast.yarax.parser_helpers import ERROR_EXPECTED_VARIABLE


class YaraXParserConditionsMixin:
    """Condition parsing for YARA-X."""

    def _parse_condition(self: Any) -> Condition:
        """Parse condition with YARA-X extensions."""
        if self._check_keyword("with"):
            return cast(Condition, self._parse_with_statement())
        return cast(Condition, self._parse_expression())

    def parse_condition(self: Any) -> Condition:
        """Parse condition with YARA-X extensions."""
        condition = cast(Condition, self._parse_condition())
        self._require_expression_end("condition")
        return condition

    def _parse_with_statement(self: Any) -> WithStatement:
        """Parse 'with' statement."""
        self._consume_keyword("with")

        declarations = [self._parse_with_declaration()]
        while self._check(TokenType.COMMA):
            self._advance()
            declarations.append(self._parse_with_declaration())

        self._consume(TokenType.COLON, "Expected ':' after with declarations")
        local_names = self._local_identifier_scope_names(
            *(declaration.identifier for declaration in declarations)
        )
        with self._contextual_local_identifier_scope(local_names):
            body = self._parse_condition()
        return WithStatement(declarations=declarations, body=body)

    def _parse_with_declaration(self: Any) -> WithDeclaration:
        """Parse single declaration in with statement."""
        identifier = self._consume_with_local_identifier(ERROR_EXPECTED_VARIABLE).value
        self._consume(TokenType.ASSIGN, "Expected '=' in with declaration")
        value = self._parse_expression()
        return WithDeclaration(identifier=identifier, value=value)
