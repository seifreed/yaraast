"""Helper parsing methods for Enhanced YARA-L parser."""

from __future__ import annotations

from typing import Any

from yaraast.lexer.tokens import TokenType as BaseTokenType
from yaraast.yaral._shared import parse_numeric_token_value
from yaraast.yaral.ast_nodes import (
    EventVariable,
    FunctionCall,
    RawConditionValue,
    ReferenceList,
    RegexPattern,
    TimeWindow,
    UDMFieldAccess,
    UDMFieldPath,
)
from yaraast.yaral.generator_helpers import format_literal
from yaraast.yaral.tokens import YaraLTokenType


class EnhancedYaraLParserHelpersMixin:
    """Mixin with shared parsing helpers."""

    def _parse_udm_field_path(self) -> UDMFieldPath:
        """Parse UDM field path like metadata.event_type."""
        parts = []
        parts.append(self._consume(BaseTokenType.IDENTIFIER, "Expected field name").value)

        while self._check(BaseTokenType.DOT) or self._check(BaseTokenType.LBRACKET):
            if self._check(BaseTokenType.DOT):
                self._advance()
                if self._check(BaseTokenType.IDENTIFIER):
                    parts.append(self._advance().value)
                elif self._check(BaseTokenType.LBRACKET):
                    self._advance()
                    parts.append(self._parse_udm_bracket_part())
                else:
                    raise self._error("Expected field name")
            elif self._check(BaseTokenType.LBRACKET):
                self._advance()
                parts.append(self._parse_udm_bracket_part())

        return UDMFieldPath(parts=parts)

    def _parse_udm_bracket_part(self) -> str:
        if self._check(BaseTokenType.STRING):
            key = self._advance().value
            self._consume(BaseTokenType.RBRACKET, "Expected ']'")
            return f'["{key}"]'
        if self._check(BaseTokenType.INTEGER):
            index = self._advance().value
            self._consume(BaseTokenType.RBRACKET, "Expected ']'")
            return f"[{index}]"
        raise self._error("Expected field key or index")

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
        if self._check(BaseTokenType.IEQUALS):
            self._advance()
            return "=="
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
        if self._check(BaseTokenType.MATCHES):
            return str(self._advance().value)
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
        if self._check(BaseTokenType.LPAREN):
            value = self._parse_parenthesized_event_value()
            return self._parse_event_arithmetic_value(value)
        value = self._parse_event_primary_value()
        return self._parse_event_arithmetic_value(value)

    def _parse_event_primary_value(self) -> Any:
        if self._check(BaseTokenType.BOOLEAN_TRUE):
            self._advance()
            return True
        if self._check(BaseTokenType.BOOLEAN_FALSE):
            self._advance()
            return False
        if self._check(BaseTokenType.STRING):
            return self._advance().value
        if self._check(BaseTokenType.INTEGER) or self._check(BaseTokenType.DOUBLE):
            return parse_numeric_token_value(self._advance().value)
        if self._check_yaral_type(YaraLTokenType.REFERENCE_LIST):
            name = self._advance().value.strip("%")
            return ReferenceList(name=name)
        if self._check_yaral_type(YaraLTokenType.EVENT_VAR):
            if self._peek_ahead(1) is None or self._peek_ahead(1).type != BaseTokenType.DOT:
                return str(self._advance().value)
            return self._parse_udm_field_access()
        if self._check(BaseTokenType.IDENTIFIER):
            token = self._peek()
            if token.value in ["true", "false"]:
                self._advance()
                return token.value == "true"
            if self._is_event_function_call_value_start():
                return self._parse_event_function_call_value()
            return self._parse_udm_field_path()
        if self._check(BaseTokenType.REGEX) or self._check(BaseTokenType.DIVIDE):
            return self._parse_regex_pattern()
        raise self._error("Expected value")

    def _parse_parenthesized_event_value(self) -> RawConditionValue:
        self._advance()
        value = self._parse_event_value()
        self._consume(BaseTokenType.RPAREN, "Expected ')' after value")
        return RawConditionValue(f"({self._format_event_value_text(value)})")

    def _parse_event_arithmetic_value(self, value: Any) -> Any:
        if not self._check_event_arithmetic_operator():
            return value
        left = self._format_event_value_text(value)
        return RawConditionValue(self._parse_event_arithmetic_text(left))

    def _parse_event_arithmetic_text(self, left: str) -> str:
        expression = left
        while self._check_event_arithmetic_operator():
            operator = str(self._advance().value)
            right = self._format_event_value_text(self._parse_event_value())
            expression = f"{expression} {operator} {right}"
        return expression

    def _check_event_arithmetic_operator(self) -> bool:
        return (
            self._check(BaseTokenType.PLUS)
            or self._check(BaseTokenType.MINUS)
            or self._check(BaseTokenType.MULTIPLY)
            or self._check(BaseTokenType.DIVIDE)
        )

    def _format_event_value_text(self, value: Any) -> str:
        if isinstance(value, RawConditionValue):
            return str(value)
        if isinstance(value, UDMFieldAccess):
            return value.full_path
        if isinstance(value, UDMFieldPath):
            return value.path
        if isinstance(value, EventVariable):
            return value.name
        if isinstance(value, ReferenceList):
            return f"%{value.name}%"
        if isinstance(value, RegexPattern):
            return value.as_string
        if isinstance(value, FunctionCall):
            arguments = ", ".join(self._format_event_value_text(arg) for arg in value.arguments)
            return f"{value.function}({arguments})"
        return format_literal(value)

    def _is_event_function_call_value_start(self) -> bool:
        next_token = self._peek_ahead(1)
        if next_token is None:
            return False
        if next_token.type == BaseTokenType.LPAREN:
            return True
        if next_token.type != BaseTokenType.DOT:
            return False
        function_token = self._peek_ahead(2)
        open_paren = self._peek_ahead(3)
        return (
            function_token is not None
            and function_token.type == BaseTokenType.IDENTIFIER
            and open_paren is not None
            and open_paren.type == BaseTokenType.LPAREN
        )

    def _parse_event_function_call_value(self) -> FunctionCall:
        function_name = str(self._advance().value)
        if self._check(BaseTokenType.DOT):
            self._advance()
            function_part = self._consume(BaseTokenType.IDENTIFIER, "Expected function name").value
            function_name = f"{function_name}.{function_part}"

        self._consume(BaseTokenType.LPAREN, f"Expected '(' after {function_name}")
        arguments = []
        if not self._check(BaseTokenType.RPAREN):
            arguments.append(self._parse_event_value())
            while self._check(BaseTokenType.COMMA):
                self._advance()
                arguments.append(self._parse_event_value())

        self._consume(BaseTokenType.RPAREN, f"Expected ')' after {function_name} arguments")
        return FunctionCall(function=function_name, arguments=arguments)

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
            return self._parse_regex_word_modifiers(
                RegexPattern(pattern=pattern, flags=list(modifiers))
            )

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

        return self._parse_regex_word_modifiers(
            RegexPattern(pattern=pattern, flags=list(modifiers))
        )

    def _parse_regex_word_modifiers(self, pattern: RegexPattern) -> RegexPattern:
        if self._check_keyword("nocase"):
            self._advance()
            if "nocase" not in pattern.flags:
                pattern.flags.append("nocase")
        return pattern

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
