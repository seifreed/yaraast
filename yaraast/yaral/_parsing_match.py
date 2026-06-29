"""Parsing routines for YARA-L rules."""

from __future__ import annotations

from yaraast.lexer.tokens import TokenType as BaseTokenType

from ._shared import YaraLParserError
from .ast_nodes import (
    EventVariable,
    MatchSection,
    MatchVariable,
    TimeWindow,
    UDMFieldAccess,
    UDMFieldPath,
)
from .tokens import YaraLTokenType


class YaraLMatchParsingMixin:
    """Mixin providing YARA-L parse routines."""

    def _parse_match_section(self) -> MatchSection:
        """Parse match section."""
        self._consume_keyword("match")
        self._consume(BaseTokenType.COLON, "Expected ':' after 'match'")

        variables = []

        while (
            not self._is_at_end()
            and not self._check_section_keyword()
            and not self._check(BaseTokenType.RBRACE)
        ):
            if self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
                BaseTokenType.STRING_IDENTIFIER,
            ):
                var_names = self._parse_match_variable_list()
                grouping_field = None
                if self._check(BaseTokenType.EQ):
                    if len(var_names) != 1:
                        raise YaraLParserError(
                            "Expected single match variable before grouping field",
                            self._peek(),
                        )
                    self._advance()
                    grouping_field = self._parse_match_grouping_field()

                self._consume_keyword("over", "Expected 'over' after match variable(s)")

                modifier = None
                if self._check_keyword("every"):
                    modifier = "every"
                    self._advance()

                time_window = self._parse_time_window(modifier)

                temporal_anchor, anchor_variable = self._parse_temporal_anchor()

                for var_name in var_names:
                    variables.append(
                        MatchVariable(
                            variable=var_name,
                            time_window=time_window,
                            grouping_field=grouping_field,
                            temporal_anchor=temporal_anchor,
                            anchor_variable=anchor_variable,
                        )
                    )
            else:
                self._advance()

        return MatchSection(variables=variables)

    def _parse_temporal_anchor(self) -> tuple[str | None, str | None]:
        if not (self._check_keyword("after") or self._check_keyword("before")):
            return None, None

        temporal_anchor = str(self._advance().value)
        if not (
            self._check_yaral_type(YaraLTokenType.EVENT_VAR)
            or self._check(BaseTokenType.STRING_IDENTIFIER)
        ):
            raise YaraLParserError("Expected temporal anchor variable", self._peek())
        anchor_variable = str(self._advance().value).lstrip("$")
        return temporal_anchor, anchor_variable

    def _parse_match_variable_list(self) -> list[str]:
        """Parse one or more comma-separated match variables ($a, $b, $c)."""
        var_token = self._advance()
        var_names = [var_token.value.lstrip("$")]

        while self._check(BaseTokenType.COMMA):
            self._advance()  # consume comma
            if self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
                BaseTokenType.STRING_IDENTIFIER,
            ):
                next_token = self._advance()
                var_names.append(next_token.value.lstrip("$"))
            else:
                break

        return var_names

    def _parse_match_grouping_field(self) -> UDMFieldAccess:
        event = None
        if self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
            BaseTokenType.STRING_IDENTIFIER
        ):
            event = EventVariable(name=str(self._advance().value))
            self._consume(BaseTokenType.DOT, "Expected field path after match grouping event")
            field_parts = [
                str(self._consume(BaseTokenType.IDENTIFIER, "Expected field name").value)
            ]
        elif self._check(BaseTokenType.IDENTIFIER):
            field_parts = [str(self._advance().value)]
        else:
            raise YaraLParserError("Expected match grouping field", self._peek())

        field = UDMFieldPath(parts=self._parse_match_field_path_continuation(field_parts))
        return UDMFieldAccess(event=event, field=field)

    def _parse_match_field_path_continuation(self, field_parts: list[str]) -> list[str]:
        while self._check(BaseTokenType.DOT) or self._check(BaseTokenType.LBRACKET):
            if self._check(BaseTokenType.DOT):
                self._advance()
                if self._check(BaseTokenType.IDENTIFIER):
                    field_parts.append(str(self._advance().value))
                elif self._check(BaseTokenType.LBRACKET):
                    self._advance()
                    field_parts.append(self._parse_match_bracket_part())
                else:
                    raise YaraLParserError("Expected field name", self._peek())
            else:
                self._advance()
                field_parts.append(self._parse_match_bracket_part())
        return field_parts

    def _parse_match_bracket_part(self) -> str:
        if self._check(BaseTokenType.STRING):
            key = self._advance().value
            self._consume(BaseTokenType.RBRACKET, "Expected ']'")
            return f'["{key}"]'
        if self._check(BaseTokenType.INTEGER):
            index = self._advance().value
            self._consume(BaseTokenType.RBRACKET, "Expected ']'")
            return f"[{index}]"
        raise YaraLParserError("Expected field key or index", self._peek())

    def _parse_time_window(self, modifier: str | None = None) -> TimeWindow:
        """Parse time window like 5m, 1h, 7d."""
        if self._check_yaral_type(YaraLTokenType.TIME_LITERAL):
            time_token = self._advance()
            # Parse the time literal (e.g., "5m")
            import re

            match = re.match(r"(\d+)([smhd])", time_token.value)
            if match:
                duration = int(match.group(1))
                unit = match.group(2)
                return TimeWindow(duration=duration, unit=unit, modifier=modifier)
        elif self._check(BaseTokenType.INTEGER):
            duration = int(self._advance().value)
            # Check for unit
            unit = "m"  # Default to minutes
            if self._check(BaseTokenType.IDENTIFIER):
                unit_token = self._peek()
                if unit_token.value in [
                    "s",
                    "m",
                    "h",
                    "d",
                    "seconds",
                    "minutes",
                    "hours",
                    "days",
                ]:
                    unit = unit_token.value[0]  # Take first letter
                    self._advance()
            return TimeWindow(duration=duration, unit=unit, modifier=modifier)

        msg = "Expected time window"
        raise YaraLParserError(msg, self._peek())
