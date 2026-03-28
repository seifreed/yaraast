"""Rule/meta/options parsing for Enhanced YARA-L parser."""

from __future__ import annotations

from typing import Any

from yaraast.lexer.tokens import TokenType as BaseTokenType
from yaraast.yaral.ast_nodes import MetaEntry, MetaSection, OptionsSection, YaraLRule


class EnhancedYaraLParserRulesMixin:
    """Mixin for rule/meta/options parsing."""

    def _parse_rule(
        self,
    ) -> YaraLRule:
        """Parse a complete YARA-L rule."""
        self._consume_keyword("rule")

        name_token = self._consume(BaseTokenType.IDENTIFIER, "Expected rule name")
        rule_name = name_token.value

        self._consume(BaseTokenType.LBRACE, "Expected '{' after rule name")

        meta = None
        events = None
        match = None
        condition = None
        outcome = None
        options = None

        # YARA-L requires strict section order: meta, events, match, condition, outcome, options
        section_order = ["meta", "events", "match", "condition", "outcome", "options"]
        last_section_index = -1

        while not self._check(BaseTokenType.RBRACE) and not self._is_at_end():
            section_parsed = False

            if self._check_keyword("meta"):
                self._validate_section_order("meta", section_order, last_section_index)
                last_section_index = section_order.index("meta")
                meta = self._parse_meta_section()
                section_parsed = True
            elif self._check_keyword("events"):
                self._validate_section_order("events", section_order, last_section_index)
                last_section_index = section_order.index("events")
                events = self._parse_events_section()
                section_parsed = True
            elif self._check_keyword("match"):
                self._validate_section_order("match", section_order, last_section_index)
                last_section_index = section_order.index("match")
                match = self._parse_match_section()
                section_parsed = True
            elif self._check_keyword("condition"):
                self._validate_section_order("condition", section_order, last_section_index)
                last_section_index = section_order.index("condition")
                condition = self._parse_condition_section()
                section_parsed = True
            elif self._check_keyword("outcome"):
                self._validate_section_order("outcome", section_order, last_section_index)
                last_section_index = section_order.index("outcome")
                outcome = self._parse_outcome_section()
                section_parsed = True
            elif self._check_keyword("options"):
                self._validate_section_order("options", section_order, last_section_index)
                last_section_index = section_order.index("options")
                options = self._parse_options_section()
                section_parsed = True

            if not section_parsed:
                if hasattr(self, "errors"):
                    self.errors.append(
                        f"Unexpected content in rule '{rule_name}': '{self._peek().value}'"
                    )
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

    def _validate_section_order(self, section: str, order: list[str], last_index: int) -> None:
        """Validate that sections appear in correct YARA-L order."""
        current_index = order.index(section)
        if current_index <= last_index:
            expected = order[last_index]
            if hasattr(self, "errors"):
                self.errors.append(
                    f"Section '{section}' appears after '{expected}' — "
                    f"YARA-L requires order: {', '.join(order)}"
                )

    def _parse_meta_section(self) -> MetaSection:
        """Parse meta section."""
        self._consume_keyword("meta")
        self._consume(BaseTokenType.COLON, "Expected ':' after 'meta'")

        entries = []

        while not self._check_section_keyword() and not self._check(BaseTokenType.RBRACE):
            key_token = self._consume(BaseTokenType.IDENTIFIER, "Expected meta key")
            key = key_token.value

            self._consume(BaseTokenType.EQ, "Expected '=' after meta key")

            value: Any
            if self._check(BaseTokenType.STRING):
                value = self._advance().value
            elif self._check(BaseTokenType.INTEGER):
                value = int(self._advance().value)
            elif self._check(BaseTokenType.BOOLEAN_TRUE):
                self._advance()
                value = True
            elif self._check(BaseTokenType.BOOLEAN_FALSE):
                self._advance()
                value = False
            else:
                value = self._advance().value

            entries.append(MetaEntry(key=key, value=value))

        return MetaSection(entries=entries)

    def _parse_options_section(self) -> OptionsSection:
        """Parse options section."""
        self._consume_keyword("options")
        self._consume(BaseTokenType.COLON, "Expected ':' after 'options'")

        options = {}

        while not self._check_section_keyword() and not self._check(BaseTokenType.RBRACE):
            if self._check(BaseTokenType.IDENTIFIER):
                key = self._advance().value
                self._consume(BaseTokenType.EQ, "Expected '=' after option key")
                value = self._parse_option_value()
                options[key] = value
            else:
                self._advance()

        return OptionsSection(options=options)

    def _parse_option_value(self) -> str | int | bool:
        """Parse an option value (string, number, or boolean)."""
        if self._check(BaseTokenType.BOOLEAN_TRUE):
            self._advance()
            return True
        if self._check(BaseTokenType.BOOLEAN_FALSE):
            self._advance()
            return False
        if self._check(BaseTokenType.STRING):
            return self._advance().value
        if self._check(BaseTokenType.INTEGER):
            return int(self._advance().value)
        if self._check(BaseTokenType.IDENTIFIER):
            token = self._advance()
            if token.value in ["true", "false"]:
                return token.value == "true"
            return token.value
        raise self._error("Expected option value")
