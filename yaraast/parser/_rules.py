"""Rule and section parsing helpers."""

from __future__ import annotations

from typing import Any

from yaraast.ast.conditions import Condition
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import StringDefinition
from yaraast.lexer import TokenType

from ._shared import ParserError


class RuleParsingMixin:
    """Mixin with rule, import, include, and meta parsing."""

    def _parse_import(self) -> Import:
        """Parse import statement."""
        start_token = self._previous()
        if not self._match(TokenType.STRING):
            msg = "Expected module name after 'import'"
            raise ParserError(msg, self._peek())

        module = self._previous().value
        alias = None

        # Check for 'as alias'
        if self._match(TokenType.AS):
            if not self._match(TokenType.IDENTIFIER):
                msg = "Expected alias after 'as'"
                raise ParserError(msg, self._peek())
            alias = self._previous().value

        return self._set_node_location_from_tokens(
            Import(module=module, alias=alias), start_token, self._previous()
        )

    def _parse_include(self) -> Include:
        """Parse include statement."""
        start_token = self._previous()
        if not self._match(TokenType.STRING):
            msg = "Expected file path after 'include'"
            raise ParserError(msg, self._peek())

        path = self._previous().value
        return self._set_node_location_from_tokens(
            Include(path=path), start_token, self._previous()
        )

    def _parse_rule(self) -> Rule:
        """Parse rule definition."""
        start_token = self._peek()
        modifiers = self._parse_rule_modifiers()
        name = self._parse_rule_name()
        tags = self._parse_rule_tags()

        if not self._match(TokenType.LBRACE):
            msg = "Expected '{' after rule name"
            raise ParserError(msg, self._peek())

        meta, strings, condition = self._parse_rule_sections()

        if not self._match(TokenType.RBRACE):
            msg = "Expected '}' at end of rule"
            raise ParserError(msg, self._peek())

        return self._set_node_location_from_tokens(
            Rule(
                name=name,
                modifiers=modifiers,
                tags=tags,
                meta=meta,
                strings=strings,
                condition=condition,
            ),
            start_token,
            self._previous(),
        )

    def _parse_rule_modifiers(self) -> list[str]:
        """Parse rule modifiers (private, global)."""
        modifiers = []
        while self._match(TokenType.PRIVATE, TokenType.GLOBAL):
            modifiers.append(self._previous().value.lower())
        return modifiers

    def _parse_rule_name(self) -> str:
        """Parse rule name identifier."""
        if not self._match(TokenType.RULE):
            msg = "Expected 'rule' keyword"
            raise ParserError(msg, self._peek())

        if not self._match(TokenType.IDENTIFIER):
            msg = "Expected rule name"
            raise ParserError(msg, self._peek())

        return self._previous().value

    def _parse_rule_tags(self) -> list[Tag]:
        """Parse rule tags after colon."""
        tags = []
        if self._match(TokenType.COLON):
            while self._check(TokenType.IDENTIFIER):
                tag_token = self._advance()
                tags.append(
                    self._set_node_location_from_token(Tag(name=tag_token.value), tag_token)
                )
        return tags

    def _parse_rule_sections(
        self,
    ) -> tuple[dict[str, Any], list[StringDefinition], Condition | None]:
        """Parse rule sections (meta, strings, condition)."""
        meta: dict[str, Any] = {}
        strings: list[StringDefinition] = []
        condition: Condition | None = None

        while not self._check(TokenType.RBRACE) and not self._is_at_end():
            if self._match(TokenType.META):
                self._expect_colon("meta")
                meta = self._parse_meta_section()
            elif self._match(TokenType.STRINGS):
                self._expect_colon("strings")
                strings = self._parse_strings_section()
            elif self._match(TokenType.CONDITION):
                self._expect_colon("condition")
                condition = self._parse_condition()
            else:
                msg = f"Unexpected section: {self._peek().value}"
                raise ParserError(msg, self._peek())

        return meta, strings, condition

    def _expect_colon(self, section_name: str) -> None:
        """Expect and consume a colon after section name."""
        if not self._match(TokenType.COLON):
            msg = f"Expected ':' after '{section_name}'"
            raise ParserError(msg, self._peek())

    def _parse_meta_section(self) -> dict[str, Any]:
        """Parse meta section."""
        meta: dict[str, Any] = {}

        while not self._check_any(
            TokenType.STRINGS,
            TokenType.CONDITION,
            TokenType.RBRACE,
        ):
            if not self._check(TokenType.IDENTIFIER):
                break

            key = self._advance().value

            if not self._match(TokenType.ASSIGN):
                msg = "Expected '=' after meta key"
                raise ParserError(msg, self._peek())

            # Parse meta value
            # Handle negative numbers: -159 or -3.14
            if self._match(TokenType.MINUS):
                if self._match(TokenType.INTEGER) or self._match(TokenType.DOUBLE):
                    value = -self._previous().value
                else:
                    msg = "Expected number after '-' in meta value"
                    raise ParserError(msg, self._peek())
            elif self._match(TokenType.STRING) or self._match(TokenType.INTEGER):
                value = self._previous().value
            elif self._match(TokenType.BOOLEAN_TRUE):
                value = True
            elif self._match(TokenType.BOOLEAN_FALSE):
                value = False
            else:
                msg = "Invalid meta value"
                raise ParserError(msg, self._peek())

            meta[key] = value

        return meta
