"""Helper parsing methods for Enhanced YARA-L parser."""

from __future__ import annotations

from typing import Any

from yaraast.lexer.tokens import TokenType as BaseTokenType
from yaraast.yaral.ast_nodes import (
    EventVariable,
    ReferenceList,
    RegexPattern,
    TimeWindow,
    UDMFieldAccess,
    UDMFieldPath,
)
from yaraast.yaral.tokens import YaraLTokenType


class EnhancedYaraLParserHelpersMixin:
    """Mixin with shared parsing helpers."""

    def _parse_udm_field_path(self) -> UDMFieldPath:
        """Parse UDM field path like metadata.event_type."""
        parts = []
        parts.append(self._consume(BaseTokenType.IDENTIFIER, "Expected field name").value)

        while self._check(BaseTokenType.DOT):
            self._advance()
            parts.append(self._consume(BaseTokenType.IDENTIFIER, "Expected field name").value)

        return UDMFieldPath(parts=parts)

    def _parse_udm_field_access(self) -> UDMFieldAccess:
        """Parse UDM field access like $e.metadata.event_type."""
        event = None

        if self._check_yaral_type(YaraLTokenType.EVENT_VAR):
            event = EventVariable(name=self._advance().value)
            if self._check(BaseTokenType.DOT):
                self._advance()

        field = self._parse_udm_field_path()

        return UDMFieldAccess(event=event, field=field)

    def _parse_comparison_operator(self) -> str:
        """Parse comparison operator."""
        if self._check(BaseTokenType.EQ):
            self._advance()
            return "="
        if self._check(BaseTokenType.NEQ):
            self._advance()
            return "!="
        if self._check(BaseTokenType.GT):
            self._advance()
            return ">"
        if self._check(BaseTokenType.LT):
            self._advance()
            return "<"
        if self._check(BaseTokenType.GE):
            self._advance()
            return ">="
        if self._check(BaseTokenType.LE):
            self._advance()
            return "<="
        if self._check_keyword("matches"):
            self._advance()
            return "=~"
        if self._check(BaseTokenType.IN):
            self._advance()
            return "in"
        if self._check_keyword("in"):
            self._advance()
            return "in"
        if (
            self._check_keyword("not")
            and self._peek_ahead(1)
            and self._peek_ahead(1).value == "matches"
        ):
            self._advance()
            self._advance()
            return "!~"
        raise self._error("Expected comparison operator")

    def _parse_time_window(self) -> TimeWindow:
        """Parse time window specification."""
        self._consume_keyword("over")

        duration, unit = self._parse_duration_parts()
        return TimeWindow(duration=duration, unit=unit)

    def _parse_event_value(self) -> Any:
        """Parse event value (literal, reference, or field)."""
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
        if self._check_yaral_type(YaraLTokenType.REFERENCE_LIST):
            name = self._advance().value.strip("%")
            return ReferenceList(name=name)
        if self._check_yaral_type(YaraLTokenType.EVENT_VAR):
            return self._parse_udm_field_access()
        if self._check(BaseTokenType.IDENTIFIER):
            token = self._peek()
            if token.value in ["true", "false"]:
                self._advance()
                return token.value == "true"
            return self._parse_udm_field_path()
        if self._check(BaseTokenType.REGEX) or self._check(BaseTokenType.DIVIDE):
            return self._parse_regex_pattern()
        raise self._error("Expected value")

    def _parse_regex_pattern(self) -> RegexPattern:
        """Parse regex pattern like /pattern/modifiers."""
        if self._check(BaseTokenType.REGEX):
            token = self._consume(BaseTokenType.REGEX, "Expected regex pattern")
            value = token.value
            if value.startswith("/") and "/" in value[1:]:
                last = value.rfind("/")
                pattern = value[1:last]
                modifiers = value[last + 1 :]
            else:
                pattern = value
                modifiers = ""
            return RegexPattern(pattern=pattern, flags=list(modifiers))

        self._consume(BaseTokenType.DIVIDE, "Expected '/' for regex")
        pattern_parts = []
        while not self._check(BaseTokenType.DIVIDE) and not self._is_at_end():
            pattern_parts.append(str(self._advance().value))

        pattern = "".join(pattern_parts)
        self._consume(BaseTokenType.DIVIDE, "Expected '/' to close regex")

        modifiers = ""
        if self._check(BaseTokenType.IDENTIFIER):
            token = self._peek()
            if len(token.value) <= 3 and all(c in "igms" for c in token.value):
                modifiers = self._advance().value

        return RegexPattern(pattern=pattern, flags=list(modifiers))

    def _parse_time_duration(self) -> str:
        """Parse time duration like '5m', '1h', '30s'."""
        duration, unit = self._parse_duration_parts()
        return f"{duration}{unit}"

    def _parse_duration_parts(self) -> tuple[int, str]:
        """Parse a time duration into numeric value and unit."""
        if self._check_yaral_type(YaraLTokenType.TIME_LITERAL):
            token = self._advance().value
            number = "".join(ch for ch in token if ch.isdigit())
            unit = "".join(ch for ch in token if ch.isalpha())
            return int(number), unit

        duration = int(self._consume(BaseTokenType.INTEGER, "Expected duration").value)
        unit = self._consume(BaseTokenType.IDENTIFIER, "Expected time unit").value
        return duration, unit
