"""Parsing routines for YARA-L rules."""

from __future__ import annotations

from yaraast.lexer.tokens import TokenType as BaseTokenType

from ._shared import YaraLParserError
from .ast_nodes import MatchSection, MatchVariable, TimeWindow
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

                self._consume_keyword("over", "Expected 'over' after match variable(s)")

                modifier = None
                if self._check_keyword("every"):
                    modifier = "every"
                    self._advance()

                time_window = self._parse_time_window(modifier)

                for var_name in var_names:
                    variables.append(MatchVariable(variable=var_name, time_window=time_window))
            else:
                self._advance()

        return MatchSection(variables=variables)

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
