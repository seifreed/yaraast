"""Parsing routines for YARA-L rules."""

from __future__ import annotations

from yaraast.lexer.tokens import TokenType as BaseTokenType

from ._shared import YaraLParserError, parse_numeric_token_value, split_regex_token_value
from .ast_nodes import (
    BinaryCondition,
    ConditionExpression,
    ConditionSection,
    EventCountCondition,
    EventExistsCondition,
    FunctionCall,
    NOfCondition,
    NullCheckCondition,
    RawConditionValue,
    ReferenceList,
    RegexPattern,
    UnaryCondition,
    VariableComparisonCondition,
)
from .generator_helpers import quote_string_literal
from .tokens import YaraLTokenType


class YaraLConditionParsingMixin:
    """Mixin providing YARA-L parse routines."""

    def _parse_condition_section(self) -> ConditionSection:
        """Parse condition section."""
        self._consume_keyword("condition")
        self._consume(BaseTokenType.COLON, "Expected ':' after 'condition'")

        expression = self._parse_condition_expression()

        return ConditionSection(expression=expression)

    def _parse_condition_expression(self) -> ConditionExpression:
        """Parse condition expression."""
        return self._parse_or_condition()

    def _parse_or_condition(self) -> ConditionExpression:
        """Parse OR condition."""
        left = self._parse_and_condition()

        while self._check_keyword("or"):
            self._advance()
            right = self._parse_and_condition()
            left = BinaryCondition(operator="or", left=left, right=right)

        return left

    def _parse_and_condition(self) -> ConditionExpression:
        """Parse AND condition."""
        left = self._parse_unary_condition()

        while self._check_keyword("and"):
            self._advance()
            right = self._parse_unary_condition()
            left = BinaryCondition(operator="and", left=left, right=right)

        return left

    def _parse_unary_condition(self) -> ConditionExpression:
        """Parse unary condition."""
        if self._check_keyword("not"):
            self._advance()
            operand = self._parse_unary_condition()
            return UnaryCondition(operator="not", operand=operand)

        return self._parse_primary_condition()

    def _parse_primary_condition(self) -> ConditionExpression:
        """Parse primary condition."""
        # Parenthesized expression
        if self._check(BaseTokenType.LPAREN):
            return self._parse_parenthesized_condition()

        # Event count: #e > 5
        if self._check(BaseTokenType.STRING_COUNT):
            return self._parse_event_count_condition()

        if self._check(BaseTokenType.INTEGER) and self._token_ahead_value(1) == "of":
            return self._parse_n_of_condition()

        # Variable or event reference: $var or $e1
        if self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
            BaseTokenType.STRING_IDENTIFIER
        ):
            return self._parse_variable_condition()

        # Fallback: treat as exists condition
        if self._check(BaseTokenType.IDENTIFIER):
            return self._parse_identifier_condition()

        msg = f"Unexpected token in condition: {self._peek()}"
        raise YaraLParserError(
            msg,
            self._peek(),
        )

    def _parse_parenthesized_condition(self) -> ConditionExpression:
        """Parse a parenthesized condition expression."""
        self._advance()
        expr = self._parse_condition_expression()
        self._consume(BaseTokenType.RPAREN, "Expected ')' after expression")
        return expr

    def _parse_event_count_condition(self) -> EventCountCondition:
        """Parse an event count condition: #e > 5."""
        self._advance()
        event_name = self._consume(
            BaseTokenType.IDENTIFIER,
            "Expected event name after '#'",
        ).value

        operator = self._consume_comparison_operator()
        count = int(
            self._consume(
                BaseTokenType.INTEGER,
                "Expected number after operator",
            ).value,
        )

        return EventCountCondition(event=event_name, operator=operator, count=count)

    def _parse_n_of_condition(self) -> NOfCondition:
        count = int(self._advance().value)
        self._consume_keyword("of")
        self._consume(BaseTokenType.LPAREN, "Expected '(' after 'of'")

        events = []
        while not self._check(BaseTokenType.RPAREN) and not self._is_at_end():
            if self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
                BaseTokenType.STRING_IDENTIFIER
            ):
                events.append(str(self._advance().value))
            else:
                raise YaraLParserError("Expected event variable in N-of condition", self._peek())

            if self._check(BaseTokenType.COMMA):
                self._advance()
            elif not self._check(BaseTokenType.RPAREN):
                raise YaraLParserError("Expected ',' or ')' in N-of condition", self._peek())

        self._consume(BaseTokenType.RPAREN, "Expected ')' after event list")
        return NOfCondition(count=count, events=events)

    def _consume_comparison_operator(self) -> str:
        """Consume and return a comparison operator token."""
        operator_map = {
            BaseTokenType.IEQUALS: "==",
            BaseTokenType.GT: ">",
            BaseTokenType.LT: "<",
            BaseTokenType.GE: ">=",
            BaseTokenType.LE: "<=",
            BaseTokenType.EQ: "==",
            BaseTokenType.NEQ: "!=",
        }
        for token_type, op in operator_map.items():
            if self._check(token_type):
                self._advance()
                return op

        msg = "Expected comparison operator"
        raise YaraLParserError(msg, self._peek())

    def _parse_comparison_value(self):
        """Parse the value on the right side of a comparison."""
        if self._check(BaseTokenType.LPAREN):
            value = self._parse_parenthesized_comparison_value()
            return self._parse_condition_arithmetic_value(value)
        if self._check(BaseTokenType.BOOLEAN_TRUE):
            self._advance()
            return True
        if self._check(BaseTokenType.BOOLEAN_FALSE):
            self._advance()
            return False
        if self._check(BaseTokenType.INTEGER) or self._check(BaseTokenType.DOUBLE):
            value = parse_numeric_token_value(self._advance().value)
            return self._parse_condition_arithmetic_value(value)
        if self._check_yaral_type(YaraLTokenType.REFERENCE_LIST):
            return ReferenceList(name=self._advance().value.strip("%"))
        if self._check(BaseTokenType.REGEX) or self._check(BaseTokenType.DIVIDE):
            return self._parse_condition_regex_pattern()
        if self._check(BaseTokenType.STRING):
            return self._advance().value
        if self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
            BaseTokenType.STRING_IDENTIFIER
        ):
            value = RawConditionValue(
                self._parse_condition_reference_text(str(self._advance().value))
            )
            return self._parse_condition_arithmetic_value(value)
        if self._check(BaseTokenType.IDENTIFIER):
            value = self._parse_condition_identifier_value()
            return self._parse_condition_arithmetic_value(value)

        msg = "Expected value after comparison operator"
        raise YaraLParserError(msg, self._peek())

    def _parse_condition_regex_pattern(self) -> RegexPattern:
        if self._check(BaseTokenType.REGEX):
            pattern, flags = split_regex_token_value(self._advance().value)
            return self._parse_condition_regex_word_modifiers(
                RegexPattern(pattern=pattern, flags=flags)
            )

        self._consume(BaseTokenType.DIVIDE, "Expected '/' for regex")
        pattern_parts = []
        while not self._check(BaseTokenType.DIVIDE) and not self._is_at_end():
            pattern_parts.append(str(self._advance().value))

        self._consume(BaseTokenType.DIVIDE, "Expected '/' to close regex")
        flags = []
        if self._check(BaseTokenType.IDENTIFIER):
            token_value = str(self._peek().value)
            if len(token_value) <= 3 and all(char in "igms" for char in token_value):
                flags = list(str(self._advance().value))

        return self._parse_condition_regex_word_modifiers(
            RegexPattern(pattern="".join(pattern_parts), flags=flags)
        )

    def _parse_condition_regex_word_modifiers(self, pattern: RegexPattern) -> RegexPattern:
        if self._check_keyword("nocase"):
            self._advance()
            if "nocase" not in pattern.flags:
                pattern.flags.append("nocase")
        return pattern

    def _parse_condition_identifier_value(self):
        value = self._parse_condition_reference_text(str(self._advance().value))
        if self._check(BaseTokenType.LPAREN):
            return self._parse_function_call_args(value)
        return RawConditionValue(value)

    def _parse_parenthesized_comparison_value(self) -> RawConditionValue:
        self._advance()
        value = self._parse_comparison_value()
        self._consume(BaseTokenType.RPAREN, "Expected ')' after comparison value")
        return RawConditionValue(f"({self._format_condition_raw_value(value)})")

    def _check_comparison_operator(self) -> bool:
        """Check if the current token is a comparison operator."""
        return (
            self._check(BaseTokenType.GT)
            or self._check(BaseTokenType.LT)
            or self._check(BaseTokenType.GE)
            or self._check(BaseTokenType.LE)
            or self._check(BaseTokenType.EQ)
            or self._check(BaseTokenType.IEQUALS)
            or self._check(BaseTokenType.NEQ)
        )

    def _check_condition_operator(self) -> bool:
        return (
            self._check_comparison_operator()
            or self._check(BaseTokenType.MATCHES)
            or self._check(BaseTokenType.IN)
            or self._check_keyword("in")
            or self._check_keyword("matches")
            or self._check_keyword("regex")
            or (self._check_keyword("not") and self._token_ahead_value(1) == "matches")
        )

    def _consume_condition_operator(self) -> str:
        if self._check_comparison_operator():
            return self._consume_comparison_operator()
        if self._check(BaseTokenType.MATCHES):
            return str(self._advance().value)
        if self._check(BaseTokenType.IN) or self._check_keyword("in"):
            self._advance()
            return "in"
        if self._check_keyword("matches"):
            self._advance()
            return "=~"
        if self._check_keyword("regex"):
            self._advance()
            return "regex"
        if self._check_keyword("not") and self._token_ahead_value(1) == "matches":
            self._advance()
            self._advance()
            return "!~"

        msg = "Expected comparison operator"
        raise YaraLParserError(msg, self._peek())

    def _check_null_check_operator(self) -> bool:
        return self._check_yaral_type(YaraLTokenType.IS) or self._check_keyword("is")

    def _parse_null_check_condition(self, field_name: str) -> NullCheckCondition:
        self._advance()
        negated = False
        if self._check_keyword("not"):
            self._advance()
            negated = True
        if not self._check_yaral_type(YaraLTokenType.NULL) and not self._check_keyword("null"):
            raise YaraLParserError("Expected 'null' after 'is'", self._peek())
        self._advance()
        return NullCheckCondition(field=field_name, negated=negated)

    def _token_ahead_value(self, offset: int) -> object | None:
        position = self.current + offset
        if position >= len(self.tokens):
            return None
        return self.tokens[position].value

    def _parse_condition_reference_text(self, name: str) -> str:
        parts = [name]
        while self._check(BaseTokenType.DOT) or self._check(BaseTokenType.LBRACKET):
            if self._check(BaseTokenType.DOT):
                self._advance()
                if self._check(BaseTokenType.IDENTIFIER):
                    parts.append(str(self._advance().value))
                elif self._check(BaseTokenType.LBRACKET):
                    self._advance()
                    parts.append(self._parse_condition_bracket_part())
                else:
                    raise YaraLParserError("Expected field name", self._peek())
            else:
                self._advance()
                parts.append(self._parse_condition_bracket_part())
        return self._format_condition_reference_parts(parts)

    def _parse_condition_bracket_part(self) -> str:
        if self._check(BaseTokenType.STRING):
            key = self._advance().value
            self._consume(BaseTokenType.RBRACKET, "Expected ']'")
            return f'["{key}"]'
        if self._check(BaseTokenType.INTEGER):
            index = self._advance().value
            self._consume(BaseTokenType.RBRACKET, "Expected ']'")
            return f"[{index}]"
        raise YaraLParserError("Expected field key or index", self._peek())

    def _format_condition_reference_parts(self, parts: list[str]) -> str:
        reference = parts[0]
        for part in parts[1:]:
            if part.startswith("["):
                reference += part
            else:
                reference += f".{part}"
        return reference

    def _parse_condition_arithmetic_value(self, value):
        if not self._check_condition_arithmetic_operator():
            return value
        left = self._format_condition_raw_value(value)
        return RawConditionValue(self._parse_condition_arithmetic_text(left))

    def _parse_condition_arithmetic_text(self, left: str) -> str:
        expression = left
        while self._check_condition_arithmetic_operator():
            operator = str(self._advance().value)
            right = self._parse_condition_arithmetic_operand_text()
            expression = f"{expression} {operator} {right}"
        return expression

    def _parse_condition_arithmetic_operand_text(self) -> str:
        if self._check(BaseTokenType.INTEGER) or self._check(BaseTokenType.DOUBLE):
            return str(parse_numeric_token_value(self._advance().value))
        if self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
            BaseTokenType.STRING_IDENTIFIER
        ):
            return self._parse_condition_reference_text(str(self._advance().value))
        if self._check(BaseTokenType.IDENTIFIER):
            value = self._parse_condition_identifier_value()
            return self._format_condition_raw_value(value)
        raise YaraLParserError("Expected arithmetic operand", self._peek())

    def _check_condition_arithmetic_operator(self) -> bool:
        return (
            self._check(BaseTokenType.PLUS)
            or self._check(BaseTokenType.MINUS)
            or self._check(BaseTokenType.MULTIPLY)
            or self._check(BaseTokenType.DIVIDE)
        )

    def _format_condition_raw_value(self, value) -> str:
        if isinstance(value, FunctionCall):
            args = ", ".join(self._format_condition_raw_value(arg) for arg in value.arguments)
            return f"{value.function}({args})"
        if isinstance(value, RegexPattern):
            return value.as_string
        if isinstance(value, ReferenceList):
            return f"%{value.name.strip('%')}%"
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, str):
            if isinstance(value, RawConditionValue) or value.startswith(("$", "%")):
                return str(value)
            return quote_string_literal(value)
        if hasattr(value, "full_path"):
            return str(value.full_path)
        return str(value)

    def _parse_variable_condition(self) -> ConditionExpression:
        """Parse a condition starting with a variable ($var or $e1)."""
        var_token = self._advance()
        var_name = self._parse_condition_reference_text(str(var_token.value))
        var_name = self._parse_condition_arithmetic_text(var_name)

        if self._check_null_check_operator():
            return self._parse_null_check_condition(var_name)

        # Check if followed by comparison operator
        if self._check_condition_operator():
            operator = self._consume_condition_operator()
            value = self._parse_comparison_value()
            return VariableComparisonCondition(variable=var_name, operator=operator, value=value)

        # Just a variable reference (event exists)
        event_name = var_name.lstrip("$")
        return EventExistsCondition(event=event_name)

    def _parse_identifier_condition(self) -> ConditionExpression:
        """Parse a condition starting with an identifier."""
        name = self._parse_condition_reference_text(str(self._advance().value))
        name = self._parse_condition_arithmetic_text(name)

        if self._check_null_check_operator():
            return self._parse_null_check_condition(name)

        # Check if followed by comparison operator
        if self._check_condition_operator():
            operator = self._consume_condition_operator()
            value = self._parse_comparison_value()
            return VariableComparisonCondition(variable=name, operator=operator, value=value)

        return EventExistsCondition(event=name)
