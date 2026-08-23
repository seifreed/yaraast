"""Parsing routines for YARA-L rules."""

from __future__ import annotations

from typing import Any, cast

from yaraast.lexer.tokens import TokenType as BaseTokenType

from ._parser_mixin import YaraLParserMixinBase
from ._shared import parse_numeric_token_value
from .ast_nodes import MetaEntry, MetaSection, OptionsSection, YaraLRule


class YaraLRuleParsingMixin(YaraLParserMixinBase):
    """Mixin providing YARA-L parse routines."""

    def _parse_rule(self) -> YaraLRule:
        """Parse a YARA-L rule."""
        self._consume_keyword("rule")

        # Get rule name
        name_token = self._consume(BaseTokenType.IDENTIFIER, "Expected rule name")
        rule_name = cast(str, name_token.value)

        self._consume(BaseTokenType.LBRACE, "Expected '{' after rule name")

        # Parse sections
        meta = None
        events = None
        match = None
        condition = None
        outcome = None
        options = None

        while not self._check(BaseTokenType.RBRACE) and not self._is_at_end():
            if self._check_keyword("meta"):
                meta = self._parse_meta_section()
            elif self._check_keyword("events"):
                events = self._parse_events_section()
            elif self._check_keyword("match"):
                match = self._parse_match_section()
            elif self._check_keyword("condition"):
                condition = self._parse_condition_section()
            elif self._check_keyword("outcome"):
                outcome = self._parse_outcome_section()
            elif self._check_keyword("options"):
                options = self._parse_options_section()
            else:
                # Skip unknown sections
                self._advance()

        self._consume(BaseTokenType.RBRACE, "Expected '}' after rule body")

        return YaraLRule(
            name=rule_name,
            meta=meta,
            events=events,
            match=match,
            condition=condition,
            outcome=outcome,
            options=options,
        )

    def _parse_meta_section(self) -> MetaSection:
        """Parse meta section."""
        self._consume_keyword("meta")
        self._consume(BaseTokenType.COLON, "Expected ':' after 'meta'")

        entries = []

        while not self._check_section_keyword() and not self._check(
            BaseTokenType.RBRACE,
        ):
            # Parse meta entry
            key_token = self._consume(BaseTokenType.IDENTIFIER, "Expected meta key")
            key = cast(str, key_token.value)

            self._consume(BaseTokenType.EQ, "Expected '=' after meta key")

            # Parse value
            value: str | int | float | bool
            if self._check(BaseTokenType.STRING):
                value = cast(str, self._advance().value)
            elif self._check(BaseTokenType.INTEGER) or self._check(BaseTokenType.DOUBLE):
                value = parse_numeric_token_value(self._advance().value)
            elif self._check(BaseTokenType.BOOLEAN_TRUE):
                self._advance()
                value = True
            elif self._check(BaseTokenType.BOOLEAN_FALSE):
                self._advance()
                value = False
            else:
                value = cast(str, self._advance().value)

            entries.append(MetaEntry(key=key, value=value))

        return MetaSection(entries=entries)

    def _parse_options_section(self) -> OptionsSection:
        """Parse options section."""
        self._consume_keyword("options")
        self._consume(BaseTokenType.COLON, "Expected ':' after 'options'")

        options: dict[str, Any] = {}

        while not self._check_section_keyword() and not self._check(
            BaseTokenType.RBRACE,
        ):
            # Parse option: key = value
            if self._check(BaseTokenType.IDENTIFIER):
                key = cast(str, self._advance().value)
                self._consume(BaseTokenType.EQ, "Expected '=' after option key")

                # Parse value
                value: Any
                if self._check(BaseTokenType.STRING):
                    value = self._advance().value
                elif self._check(BaseTokenType.INTEGER) or self._check(BaseTokenType.DOUBLE):
                    value = parse_numeric_token_value(self._advance().value)
                elif self._check(BaseTokenType.BOOLEAN_TRUE):
                    self._advance()
                    value = True
                elif self._check(BaseTokenType.BOOLEAN_FALSE):
                    self._advance()
                    value = False
                else:
                    value = self._advance().value

                options[key] = value
            else:
                self._advance()

        return OptionsSection(options=options)
