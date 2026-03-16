"""Match parsing for Enhanced YARA-L parser."""

from __future__ import annotations

from yaraast.lexer.tokens import TokenType as BaseTokenType
from yaraast.yaral.ast_nodes import MatchSection, MatchVariable, TimeWindow


class EnhancedYaraLParserMatchMixin:
    """Mixin for match parsing."""

    def _parse_match_section(self) -> MatchSection:
        """Parse enhanced match section with grouping and windows."""
        self._consume_keyword("match")
        self._consume(BaseTokenType.COLON, "Expected ':' after 'match'")

        variables = []

        while not self._check_section_keyword() and not self._check(BaseTokenType.RBRACE):
            if self._check_keyword("over"):
                standalone_window = self._parse_time_window()
                if variables:
                    variables[-1].time_window = standalone_window
            elif self._check(BaseTokenType.IDENTIFIER):
                var = self._parse_match_variable()
                variables.append(var)
            else:
                self._advance()

        return MatchSection(variables=variables)

    def _parse_match_variable(self) -> MatchVariable:
        """Parse match variable with grouping conditions."""
        name = self._consume(BaseTokenType.IDENTIFIER, "Expected variable name").value

        grouping_field = None
        if self._check(BaseTokenType.EQ):
            self._advance()

            # Parse grouping field: variable = $e.metadata.event_type over 5m
            if self._check(BaseTokenType.IDENTIFIER) or self._check_yaral_type(
                self._get_event_var_type()
            ):
                grouping_field = self._parse_udm_field_access()

        time_window = TimeWindow(duration=1, unit="m")
        if self._check_keyword("over"):
            self._advance()
            condition = self._parse_time_duration()
            duration = int("".join(ch for ch in condition if ch.isdigit()))
            unit = "".join(ch for ch in condition if ch.isalpha())
            if duration > 0 and unit:
                time_window = TimeWindow(duration=duration, unit=unit)

        return MatchVariable(
            variable=name.lstrip("$"), time_window=time_window, grouping_field=grouping_field
        )

    def _get_event_var_type(self):
        """Get the YARA-L event variable token type."""
        from yaraast.yaral.tokens import YaraLTokenType

        return YaraLTokenType.EVENT_VAR
