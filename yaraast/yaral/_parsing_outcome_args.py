"""Outcome argument parsing helpers for YARA-L."""

from __future__ import annotations

from typing import Any

from yaraast.lexer.tokens import TokenType as BaseTokenType
from yaraast.regex_literals import escape_regex_delimiter

from ._shared import (
    EXPECTED_FIELD_NAME_ERROR,
    YaraLParserError,
    parse_numeric_token_value,
    split_regex_token_value,
)
from .ast_nodes import (
    AggregationFunction,
    ArithmeticExpression,
    ConditionalExpression,
    EventVariable,
    FunctionCall,
    RawOutcomeExpression,
    RegexPattern,
    UDMFieldAccess,
    UDMFieldPath,
)
from .generator_helpers import quote_string_literal
from .tokens import YaraLTokenType

_BARE_UDM_YARAL_TYPES = {
    YaraLTokenType.METADATA,
    YaraLTokenType.PRINCIPAL,
    YaraLTokenType.TARGET,
    YaraLTokenType.NETWORK,
    YaraLTokenType.SECURITY_RESULT,
    YaraLTokenType.UDM,
    YaraLTokenType.ADDITIONAL,
}


class OutcomeArgumentParsingMixin:
    """Mixin for parsing outcome arguments and field paths."""

    def _parse_outcome_argument_basic(self) -> Any:
        """Parse basic outcome argument without comparison handling."""
        if self._check_keyword("if"):
            return self._parse_outcome_expression()

        if self._check(BaseTokenType.LPAREN):
            self._advance()
            expr = self._parse_outcome_condition()
            self._consume(BaseTokenType.RPAREN, "Expected ')' after expression")
            return RawOutcomeExpression(f"({self._format_outcome_argument_source(expr)})")

        if self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
            BaseTokenType.STRING_IDENTIFIER
        ):
            event_token = self._advance()
            var_name = event_token.value

            if self._check(BaseTokenType.DOT):
                self._advance()
                field_parts = self._parse_outcome_field_path()
                return f"{var_name}.{UDMFieldPath(parts=field_parts).path}"
            return var_name

        if self._check(BaseTokenType.STRING):
            return self._advance().value

        if self._check(BaseTokenType.BOOLEAN_TRUE):
            self._advance()
            return True
        if self._check(BaseTokenType.BOOLEAN_FALSE):
            self._advance()
            return False

        if self._check(BaseTokenType.INTEGER) or self._check(BaseTokenType.DOUBLE):
            return parse_numeric_token_value(self._advance().value)

        if self._check(BaseTokenType.IDENTIFIER):
            ident = self._advance().value
            if self._check(BaseTokenType.LPAREN):
                return self._parse_function_call_args(ident)
            if ident in ("true", "false"):
                return ident == "true"
            return ident

        msg = f"Unexpected token in outcome: {self._peek()}"
        raise YaraLParserError(
            msg,
            self._peek(),
        )

    def _parse_outcome_argument(self) -> Any:
        """Parse outcome argument (field access, literal, expression, etc.)."""
        if self._check_keyword("if"):
            return self._parse_outcome_expression()

        if self._check(BaseTokenType.LPAREN):
            self._advance()
            expr = self._parse_outcome_arithmetic_expression()
            self._consume(BaseTokenType.RPAREN, "Expected ')' after expression")
            return RawOutcomeExpression(f"({self._format_outcome_argument_source(expr)})")

        if self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
            BaseTokenType.STRING_IDENTIFIER
        ):
            return self._parse_outcome_event_var()

        if self._check(BaseTokenType.STRING):
            return self._advance().value

        if self._check(BaseTokenType.BOOLEAN_TRUE):
            self._advance()
            return True
        if self._check(BaseTokenType.BOOLEAN_FALSE):
            self._advance()
            return False

        if self._check(BaseTokenType.INTEGER) or self._check(BaseTokenType.DOUBLE):
            return self._parse_outcome_integer()

        if self._check(BaseTokenType.IDENTIFIER):
            return self._parse_outcome_identifier()

        if self._check(BaseTokenType.REGEX):
            pattern_token = self._advance()
            pattern, flags = split_regex_token_value(pattern_token.value)
            return RegexPattern(pattern=pattern, flags=flags)

        msg = f"Unexpected token in outcome: {self._peek()}"
        raise YaraLParserError(
            msg,
            self._peek(),
        )

    def _parse_outcome_event_var(self) -> Any:
        """Parse an event variable with optional field access and operator."""
        event_token = self._advance()
        var_name = event_token.value

        if self._check(BaseTokenType.DOT):
            event = EventVariable(name=var_name)
            self._advance()
            field_parts = self._parse_outcome_field_path()
            field = UDMFieldPath(parts=field_parts)

            if self._check_any_operator():
                op_token = self._advance()
                right_value = self._parse_outcome_argument()
                return (
                    f"{var_name}.{field.path} {op_token.value} "
                    f"{self._format_outcome_argument_source(right_value, quote_strings=True)}"
                )

            return UDMFieldAccess(event=event, field=field)

        if self._check_any_operator():
            op_token = self._advance()
            right_value = self._parse_outcome_argument()
            return (
                f"{var_name} {op_token.value} "
                f"{self._format_outcome_argument_source(right_value, quote_strings=True)}"
            )
        return var_name

    def _parse_outcome_integer(self) -> Any:
        """Parse an integer literal with optional arithmetic operator."""
        num_value = parse_numeric_token_value(self._advance().value)
        if self._check_any_operator(arithmetic_only=True):
            op_token = self._advance()
            right_value = self._parse_outcome_argument()
            return (
                f"{num_value} {op_token.value} {self._format_outcome_argument_source(right_value)}"
            )
        return num_value

    def _parse_outcome_identifier(self) -> Any:
        """Parse an identifier, possibly a function call or binary expression."""
        token = self._advance()
        ident = str(token.value)
        if self._check(BaseTokenType.LPAREN):
            return self._parse_function_call_args(ident)
        if ident in ("true", "false"):
            return ident == "true"
        if getattr(token, "yaral_type", None) in _BARE_UDM_YARAL_TYPES:
            field_parts = self._parse_outcome_field_path_continuation(ident.split("."))
            return UDMFieldAccess(event=None, field=UDMFieldPath(parts=field_parts))

        if self._check_any_operator(arithmetic_only=True):
            op_token = self._advance()
            right_value = self._parse_outcome_argument()
            return f"{ident} {op_token.value} {self._format_outcome_argument_source(right_value)}"
        return ident

    def _parse_function_call_args(self, func_name: str) -> FunctionCall:
        """Parse function call arguments."""
        self._advance()  # consume LPAREN
        arguments: list[Any] = []
        if not self._check(BaseTokenType.RPAREN):
            arguments.append(self._parse_outcome_argument())
            while self._check(BaseTokenType.COMMA):
                self._advance()
                arguments.append(self._parse_outcome_argument())
        self._consume(BaseTokenType.RPAREN, f"Expected ')' after {func_name} arguments")
        return FunctionCall(function=func_name, arguments=arguments)

    def _format_outcome_argument_source(self, value: Any, *, quote_strings: bool = False) -> str:
        if isinstance(value, AggregationFunction):
            args = ", ".join(
                self._format_outcome_argument_source(arg, quote_strings=True)
                for arg in value.arguments
            )
            return f"{value.function}({args})"
        if isinstance(value, ArithmeticExpression):
            left = self._format_outcome_argument_source(value.left)
            right = self._format_outcome_argument_source(value.right)
            return f"{left} {value.operator} {right}"
        if isinstance(value, ConditionalExpression):
            condition = self._format_outcome_argument_source(value.condition)
            true_value = self._format_outcome_argument_source(
                value.true_value,
                quote_strings=True,
            )
            if value.false_value is None:
                return f"if({condition}, {true_value})"
            false_value = self._format_outcome_argument_source(
                value.false_value,
                quote_strings=True,
            )
            return f"if({condition}, {true_value}, {false_value})"
        if isinstance(value, FunctionCall):
            args = ", ".join(
                self._format_outcome_argument_source(arg, quote_strings=True)
                for arg in value.arguments
            )
            return f"{value.function}({args})"
        if isinstance(value, UDMFieldAccess):
            field = value.field.path
            if value.event is None:
                return field
            return f"{value.event.name}.{field}"
        if isinstance(value, RegexPattern):
            flags = "".join(value.flags) if value.flags else ""
            return f"/{escape_regex_delimiter(value.pattern)}/{flags}"
        if isinstance(value, EventVariable):
            return value.name
        if isinstance(value, RawOutcomeExpression):
            return str(value)
        if isinstance(value, str) and quote_strings and not value.startswith(("$", "%", "(")):
            return quote_string_literal(value)
        return str(value)

    def _parse_outcome_field_path(self) -> list[str]:
        field_parts = []
        field_parts.append(
            self._consume(BaseTokenType.IDENTIFIER, EXPECTED_FIELD_NAME_ERROR).value,
        )

        return self._parse_outcome_field_path_continuation(field_parts)

    def _parse_outcome_field_path_continuation(self, field_parts: list[str]) -> list[str]:
        while self._check(BaseTokenType.DOT) or self._check(BaseTokenType.LBRACKET):
            if self._check(BaseTokenType.DOT):
                self._advance()
                if self._check(BaseTokenType.IDENTIFIER):
                    field_parts.append(self._advance().value)
                elif self._check(BaseTokenType.LBRACKET):
                    self._advance()
                    if self._check(BaseTokenType.STRING):
                        key = self._advance().value
                        field_parts.append(f'["{key}"]')
                    elif self._check(BaseTokenType.INTEGER):
                        index = self._advance().value
                        field_parts.append(f"[{index}]")
                    self._consume(BaseTokenType.RBRACKET, "Expected ']'")
            elif self._check(BaseTokenType.LBRACKET):
                self._advance()
                if self._check(BaseTokenType.STRING):
                    key = self._advance().value
                    field_parts.append(f'["{key}"]')
                elif self._check(BaseTokenType.INTEGER):
                    index = self._advance().value
                    field_parts.append(f"[{index}]")
                self._consume(BaseTokenType.RBRACKET, "Expected ']'")

        return field_parts

    def _check_any_operator(self, *, arithmetic_only: bool = False) -> bool:
        operators = (
            BaseTokenType.GT,
            BaseTokenType.LT,
            BaseTokenType.GE,
            BaseTokenType.LE,
            BaseTokenType.EQ,
            BaseTokenType.NEQ,
            BaseTokenType.IN,
            BaseTokenType.PLUS,
            BaseTokenType.MINUS,
            BaseTokenType.MULTIPLY,
            BaseTokenType.DIVIDE,
        )
        if arithmetic_only:
            operators = (
                BaseTokenType.GT,
                BaseTokenType.LT,
                BaseTokenType.GE,
                BaseTokenType.LE,
                BaseTokenType.EQ,
                BaseTokenType.NEQ,
                BaseTokenType.PLUS,
                BaseTokenType.MINUS,
                BaseTokenType.MULTIPLY,
                BaseTokenType.DIVIDE,
            )
        return any(self._check(op) for op in operators)
