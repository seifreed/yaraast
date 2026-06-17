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
                standalone_window = self._parse_match_time_window()
                if variables:
                    variables[-1].time_window = standalone_window
            elif self._check(BaseTokenType.IDENTIFIER) or self._check(
                BaseTokenType.STRING_IDENTIFIER
            ):
                variables.extend(self._parse_match_variables())
            else:
                self._advance()

        return MatchSection(variables=variables)

    def _parse_match_variable(self) -> MatchVariable:
        """Parse match variable with grouping conditions."""
        variables = self._parse_match_variables()
        return variables[0]

    def _parse_match_variables(self) -> list[MatchVariable]:
        names = [self._parse_match_variable_name()]
        while self._check(BaseTokenType.COMMA):
            self._advance()
            names.append(self._parse_match_variable_name())

        grouping_field = self._parse_match_grouping_field(len(names))
        time_window = self._parse_optional_match_time_window()

        temporal_anchor = None
        anchor_variable = None
        if self._check_keyword("after") or self._check_keyword("before"):
            temporal_anchor = str(self._advance().value)
            anchor_token = self._advance()
            anchor_variable = str(anchor_token.value).lstrip("$")

        return [
            MatchVariable(
                variable=name.lstrip("$"),
                time_window=time_window,
                grouping_field=grouping_field,
                temporal_anchor=temporal_anchor,
                anchor_variable=anchor_variable,
            )
            for name in names
        ]

    def _parse_match_variable_name(self) -> str:
        if self._check_yaral_type(self._get_event_var_type()) or self._check(
            BaseTokenType.STRING_IDENTIFIER
        ):
            return str(self._advance().value)
        return str(self._consume(BaseTokenType.IDENTIFIER, "Expected variable name").value)

    def _parse_match_grouping_field(self, variable_count: int):
        grouping_field = None
        if self._check(BaseTokenType.EQ):
            if variable_count != 1:
                raise self._error("Expected single match variable before grouping field")
            self._advance()

            # Parse grouping field: variable = $e.metadata.event_type over 5m
            if self._check(BaseTokenType.IDENTIFIER) or self._check_yaral_type(
                self._get_event_var_type()
            ):
                grouping_field = self._parse_udm_field_access()
        return grouping_field

    def _parse_optional_match_time_window(self) -> TimeWindow:
        if self._check_keyword("over"):
            return self._parse_match_time_window()
        return TimeWindow(duration=1, unit="m")

    def _parse_match_time_window(self) -> TimeWindow:
        self._consume_keyword("over")
        modifier = None
        if self._check_keyword("every"):
            modifier = "every"
            self._advance()
        duration, unit = self._parse_duration_parts()
        if duration > 0 and unit:
            return TimeWindow(duration=duration, unit=unit, modifier=modifier)
        return TimeWindow(duration=1, unit="m", modifier=modifier)

    def _get_event_var_type(self):
        """Get the YARA-L event variable token type."""
        from yaraast.yaral.tokens import YaraLTokenType

        return YaraLTokenType.EVENT_VAR
