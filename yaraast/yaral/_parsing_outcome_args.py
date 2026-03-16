"""Outcome argument parsing helpers for YARA-L."""

from __future__ import annotations

from typing import Any

from yaraast.lexer.tokens import TokenType as BaseTokenType

from ._shared import EXPECTED_FIELD_NAME_ERROR, YaraLParserError
from .ast_nodes import EventVariable, RegexPattern, UDMFieldAccess, UDMFieldPath
from .tokens import YaraLTokenType


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
            return f"({expr})"

        if self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
            BaseTokenType.STRING_IDENTIFIER
        ):
            event_token = self._advance()
            var_name = event_token.value

            if self._check(BaseTokenType.DOT):
                self._advance()
                field_parts = self._parse_outcome_field_path()
                return f"{var_name}.{'.'.join(field_parts)}"
            return var_name

        if self._check(BaseTokenType.STRING):
            return self._advance().value

        if self._check(BaseTokenType.INTEGER):
            return int(self._advance().value)

        if self._check(BaseTokenType.IDENTIFIER):
            ident = self._advance().value
            if self._check(BaseTokenType.LPAREN):
                self._advance()
                arguments = []
                if not self._check(BaseTokenType.RPAREN):
                    arguments.append(self._parse_outcome_argument())
                    while self._check(BaseTokenType.COMMA):
                        self._advance()
                        arguments.append(self._parse_outcome_argument())
                self._consume(BaseTokenType.RPAREN, f"Expected ')' after {ident} arguments")
                args_str = ", ".join(str(arg) for arg in arguments)
                return f"{ident}({args_str})"
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
            return f"({expr})"

        if self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
            BaseTokenType.STRING_IDENTIFIER
        ):
            event_token = self._advance()
            var_name = event_token.value

            if self._check(BaseTokenType.DOT):
                event = EventVariable(name=var_name)
                self._advance()
                field_parts = self._parse_outcome_field_path()
                field = UDMFieldPath(parts=field_parts)

                if self._check_any_operator():
                    op_token = self._advance()
                    op = op_token.value
                    right_value = self._parse_outcome_argument()
                    return f"{var_name}.{'.'.join(field_parts)} {op} {right_value}"

                return UDMFieldAccess(event=event, field=field)

            if self._check_any_operator():
                op_token = self._advance()
                op = op_token.value
                right_value = self._parse_outcome_argument()
                return f"{var_name} {op} {right_value}"
            return var_name

        if self._check(BaseTokenType.STRING):
            return self._advance().value

        if self._check(BaseTokenType.INTEGER):
            num_value = int(self._advance().value)
            if self._check_any_operator(arithmetic_only=True):
                op_token = self._advance()
                op = op_token.value
                right_value = self._parse_outcome_argument()
                return f"{num_value} {op} {right_value}"
            return num_value

        if self._check(BaseTokenType.IDENTIFIER):
            ident = self._advance().value
            if self._check(BaseTokenType.LPAREN):
                self._advance()
                arguments = []
                if not self._check(BaseTokenType.RPAREN):
                    arguments.append(self._parse_outcome_argument())
                    while self._check(BaseTokenType.COMMA):
                        self._advance()
                        arguments.append(self._parse_outcome_argument())
                self._consume(BaseTokenType.RPAREN, f"Expected ')' after {ident} arguments")
                args_str = ", ".join(str(arg) for arg in arguments)
                return f"{ident}({args_str})"

            if self._check_any_operator(arithmetic_only=True):
                op_token = self._advance()
                op = op_token.value
                right_value = self._parse_outcome_argument()
                return f"{ident} {op} {right_value}"
            return ident

        if self._check(BaseTokenType.REGEX):
            pattern_token = self._advance()
            return RegexPattern(pattern=pattern_token.value)

        msg = f"Unexpected token in outcome: {self._peek()}"
        raise YaraLParserError(
            msg,
            self._peek(),
        )

    def _parse_outcome_field_path(self) -> list[str]:
        field_parts = []
        field_parts.append(
            self._consume(BaseTokenType.IDENTIFIER, EXPECTED_FIELD_NAME_ERROR).value,
        )

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
