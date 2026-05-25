"""Parsing routines for YARA-L rules."""

from __future__ import annotations

from typing import Any

from yaraast.lexer.tokens import TokenType as BaseTokenType

from ._shared import (
    EXPECTED_FIELD_NAME_ERROR,
    YaraLParserError,
    parse_numeric_token_value,
    split_regex_token_value,
)
from .ast_nodes import (
    EventAssignment,
    EventsSection,
    EventStatement,
    EventVariable,
    ReferenceList,
    RegexPattern,
    UDMFieldAccess,
    UDMFieldPath,
)
from .tokens import YaraLTokenType

_RAW_EVENT_MODULES = frozenset({"arrays", "math", "net", "re", "strings"})


class YaraLEventsParsingMixin:
    """Mixin providing YARA-L parse routines."""

    def _parse_events_section(self) -> EventsSection:
        """Parse events section."""
        self._consume_keyword("events")
        self._consume(BaseTokenType.COLON, "Expected ':' after 'events'")

        statements = []

        while (
            not self._is_at_end()
            and not self._check_section_keyword()
            and not self._check(BaseTokenType.RBRACE)
        ):
            # Parse event statement
            stmt = self._parse_event_statement()
            if stmt:
                statements.append(stmt)

        return EventsSection(statements=statements)

    def _parse_event_statement(self) -> EventStatement | None:
        """Parse a single event statement."""
        # Check for parenthesized boolean expressions: (expr or expr or ...)
        if self._check(BaseTokenType.LPAREN):
            return self._parse_boolean_expression()

        # Check for function calls like re.regex()
        if self._check(BaseTokenType.IDENTIFIER):
            result = self._try_parse_function_call_start()
            if result is not None:
                return result

        # Check for integer literal starting a comparison statement
        if self._check(BaseTokenType.INTEGER) or self._check(BaseTokenType.DOUBLE):
            return self._parse_integer_comparison_statement()

        # Look for event variable ($e, $e1, etc.) or placeholder variable ($var)
        if not self._check_yaral_type(YaraLTokenType.EVENT_VAR) and not self._check(
            BaseTokenType.STRING_IDENTIFIER
        ):
            # Try to skip to next statement
            self._advance()
            return None

        event_token = self._advance()
        event_var = EventVariable(name=event_token.value)

        # Check if this is a variable assignment (e.g., $var = re.capture(...))
        if self._check(BaseTokenType.EQ):
            return self._parse_event_assignment(event_var)

        # Check if this is a comparison expression: $var != $other_var or $var in %list%
        if self._check_comparison_or_in():
            return self._parse_event_var_comparison(event_var)

        # Expect dot for field access
        self._consume(BaseTokenType.DOT, "Expected '.' after event variable")

        # Parse field path
        field_path = self._parse_field_path()

        # Check if we're at a section keyword or end of events section
        if self._check_section_keyword() or self._check(BaseTokenType.RBRACE):
            return EventStatement()

        # Parse operator
        operator = self._parse_event_operator()

        # Parse value
        value = self._parse_event_value()

        # Check for modifiers
        modifiers = []
        if self._check_keyword("nocase"):
            modifiers.append("nocase")
            self._advance()

        return EventAssignment(
            event_var=event_var,
            field_path=field_path,
            operator=operator,
            value=value,
            modifiers=modifiers,
        )

    def _try_parse_function_call_start(self) -> EventStatement | None:
        """Try to parse a function call statement if the identifier matches a known pattern."""
        identifier = self._peek().value
        if identifier in _RAW_EVENT_MODULES or (
            "." in identifier and identifier.split(".", 1)[0] in _RAW_EVENT_MODULES
        ):
            return self._parse_function_call_statement()
        return None

    def _check_comparison_or_in(self) -> bool:
        """Check if the current token is a comparison operator or 'in' keyword."""
        return (
            self._check(BaseTokenType.NEQ)
            or self._check(BaseTokenType.GT)
            or self._check(BaseTokenType.LT)
            or self._check(BaseTokenType.GE)
            or self._check(BaseTokenType.LE)
            or self._check_keyword("in")
        )

    def _parse_event_var_comparison(self, event_var: EventVariable) -> EventStatement:
        """Parse a comparison expression starting after an event variable."""
        tokens = [self._advance()]
        tokens.extend(self._collect_rhs_expression_tokens())
        return EventStatement(text=_join_prefixed_event_statement(event_var.name, tokens))

    def _parse_integer_comparison_statement(self) -> EventStatement:
        """Parse a statement starting with an integer literal (e.g., 604800 <= $field1 - $field2)."""
        tokens = [self._advance()]

        # Expect comparison operator
        if self._check_comparison_operator():
            tokens.append(self._advance())
            tokens.extend(self._collect_rhs_expression_tokens())
            return EventStatement(text=_join_event_statement_tokens(tokens))

        # Not a comparison, unexpected
        return EventStatement(text=_join_event_statement_tokens(tokens))

    def _check_comparison_operator(self) -> bool:
        """Check if current token is a comparison operator."""
        return (
            self._check(BaseTokenType.LE)
            or self._check(BaseTokenType.GE)
            or self._check(BaseTokenType.LT)
            or self._check(BaseTokenType.GT)
            or self._check(BaseTokenType.EQ)
            or self._check(BaseTokenType.NEQ)
        )

    def _skip_to_next_statement(self) -> None:
        """Consume tokens until the start of a new statement or section boundary."""
        start_line = self._peek().line if not self._is_at_end() else -1

        while not self._is_at_end():
            current_token = self._peek()

            # Stop if we hit a section keyword or closing brace
            if self._check_section_keyword() or self._check(BaseTokenType.RBRACE):
                break

            # Stop if we see a new line with a new statement pattern
            if (
                current_token.line > start_line
                and (
                    self._check_yaral_type(YaraLTokenType.EVENT_VAR)
                    or self._check(BaseTokenType.STRING_IDENTIFIER)
                    or self._check(BaseTokenType.INTEGER)
                    or self._check(BaseTokenType.DOUBLE)
                    or self._check(BaseTokenType.LPAREN)
                )
                and self._looks_like_new_statement()
            ):
                break

            self._advance()

    def _looks_like_new_statement(self) -> bool:
        """Check if the next token suggests a new statement."""
        next_pos = self.current + 1
        if next_pos < len(self.tokens):
            next_token = self.tokens[next_pos]
            return next_token.type in (
                BaseTokenType.EQ,
                BaseTokenType.DOT,
                BaseTokenType.LE,
                BaseTokenType.GE,
                BaseTokenType.LT,
                BaseTokenType.GT,
                BaseTokenType.NEQ,
            )
        return False

    def _parse_event_assignment(self, event_var: EventVariable) -> EventStatement:
        """Parse an event assignment: $var = expression."""
        self._advance()  # Consume '='
        prefix = f"{event_var.name} ="

        # Check if it's a function call
        if self._check(BaseTokenType.IDENTIFIER):
            identifier = self._peek().value
            if identifier in _RAW_EVENT_MODULES or (
                "." in identifier and identifier.split(".", 1)[0] in _RAW_EVENT_MODULES
            ):
                return _prefix_event_statement(prefix, self._parse_function_call_statement())

        # Handle field access on right side: $var = $event.field.path
        if self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
            BaseTokenType.STRING_IDENTIFIER
        ):
            return EventStatement(
                text=_join_prefixed_event_statement(
                    prefix,
                    self._collect_rhs_expression_tokens(),
                ),
            )

        # Otherwise skip this statement (not fully supported yet)
        return EventStatement(
            text=_join_prefixed_event_statement(
                prefix,
                self._collect_rhs_expression_tokens(),
            ),
        )

    def _skip_rhs_expression(self) -> None:
        """Skip the right-hand side of an assignment by consuming tokens until end of statement."""
        self._collect_rhs_expression_tokens()

    def _collect_rhs_expression_tokens(self) -> list[Any]:
        """Collect right-hand side tokens until the next event statement boundary."""
        start_line = self._peek().line if not self._is_at_end() else -1
        tokens = []

        while not self._is_at_end():
            current_token = self._peek()

            # Stop if we hit a section keyword or closing brace
            if self._check_section_keyword() or self._check(BaseTokenType.RBRACE):
                break

            # Stop if we see a new line starting with a $ variable (potential new statement)
            if current_token.line > start_line and (
                self._check_yaral_type(YaraLTokenType.EVENT_VAR)
                or self._check(BaseTokenType.STRING_IDENTIFIER)
            ):
                next_pos = self.current + 1
                if next_pos < len(self.tokens):
                    next_token = self.tokens[next_pos]
                    if next_token.type == BaseTokenType.EQ or next_token.type == BaseTokenType.DOT:
                        break

            tokens.append(self._advance())
        return tokens

    def _parse_field_path(self) -> UDMFieldPath:
        """Parse UDM field path."""
        expected_field = EXPECTED_FIELD_NAME_ERROR
        field_parts = []
        field_parts.append(
            self._consume(BaseTokenType.IDENTIFIER, expected_field).value,
        )

        # Continue parsing path components (dots and brackets)
        while self._check(BaseTokenType.DOT) or self._check(BaseTokenType.LBRACKET):
            if self._check(BaseTokenType.DOT):
                self._advance()  # Consume dot
                if self._check(BaseTokenType.IDENTIFIER):
                    field_parts.append(self._advance().value)
                elif self._check(BaseTokenType.LBRACKET):
                    # Handle array/map access after dot: .fields["key"] or .fields[0]
                    self._advance()  # [
                    if self._check(BaseTokenType.STRING):
                        key = self._advance().value
                        field_parts.append(f'["{key}"]')
                    elif self._check(BaseTokenType.INTEGER):
                        index = self._advance().value
                        field_parts.append(f"[{index}]")
                    self._consume(BaseTokenType.RBRACKET, "Expected ']'")
            elif self._check(BaseTokenType.LBRACKET):
                # Handle array/map access directly: fields["key"] or fields[0]
                self._advance()  # [
                if self._check(BaseTokenType.STRING):
                    key = self._advance().value
                    field_parts.append(f'["{key}"]')
                elif self._check(BaseTokenType.INTEGER):
                    index = self._advance().value
                    field_parts.append(f"[{index}]")
                self._consume(BaseTokenType.RBRACKET, "Expected ']'")

        return UDMFieldPath(parts=field_parts)

    def _parse_event_operator(self) -> str:
        """Parse event operator."""
        operator_map = {
            BaseTokenType.EQ: "=",
            BaseTokenType.NEQ: "!=",
            BaseTokenType.GT: ">",
            BaseTokenType.LT: "<",
            BaseTokenType.GE: ">=",
            BaseTokenType.LE: "<=",
        }

        for token_type, op in operator_map.items():
            if self._check(token_type):
                self._advance()
                return op

        if self._check_keyword("in"):
            self._advance()
            return "in"
        if self._check_keyword("regex"):
            self._advance()
            return "regex"

        msg = f"Expected operator, got {self._peek()}"
        raise YaraLParserError(msg, self._peek())

    def _parse_event_value(self) -> Any:
        """Parse event value."""
        if self._check(BaseTokenType.STRING):
            return self._advance().value
        if self._check(BaseTokenType.INTEGER) or self._check(BaseTokenType.DOUBLE):
            return parse_numeric_token_value(self._advance().value)
        if self._check_yaral_type(YaraLTokenType.EVENT_VAR):
            event = EventVariable(name=self._advance().value)
            if self._check(BaseTokenType.DOT):
                self._advance()
                return UDMFieldAccess(event=event, field=self._parse_field_path())
            return event
        if self._check_yaral_type(YaraLTokenType.REFERENCE_LIST):
            # Reference list like %suspicious_ips%
            return ReferenceList(name=self._advance().value.strip("%"))
        if self._check(BaseTokenType.REGEX):
            # Regex pattern
            pattern_token = self._advance()
            pattern, flags = split_regex_token_value(pattern_token.value)
            return RegexPattern(pattern=pattern, flags=flags)
        # Could be another field reference
        return self._advance().value

    def _parse_function_call_statement(self) -> EventStatement:
        """Parse function call statement like re.regex($e.field, `pattern`) nocase."""
        # Parse module.function identifier (could be "re.regex" as single token or separate tokens)
        raw_tokens = [self._advance()]
        function_name = raw_tokens[0].value

        # If it's not a compound name like "re.regex", check for dot and function name
        if "." not in function_name and self._check(BaseTokenType.DOT):
            raw_tokens.append(self._advance())
            # Parse function name
            if self._check(BaseTokenType.IDENTIFIER):
                raw_tokens.append(self._advance())
                function_part = raw_tokens[-1].value
                function_name = f"{function_name}.{function_part}"

        # Consume opening parenthesis
        raw_tokens.append(self._consume(BaseTokenType.LPAREN, "Expected '(' after function name"))

        # Parse arguments - skip all tokens until we find the closing paren
        # For now, just consume all tokens to skip the arguments
        paren_depth = 1
        while paren_depth > 0 and not self._is_at_end():
            if self._check(BaseTokenType.LPAREN):
                paren_depth += 1
            elif self._check(BaseTokenType.RPAREN):
                paren_depth -= 1
                if paren_depth == 0:
                    break
            raw_tokens.append(self._advance())

        # Consume closing parenthesis
        if self._check(BaseTokenType.RPAREN):
            raw_tokens.append(self._advance())

        # Check for assignment: function(...) = $variable
        if self._check(BaseTokenType.EQ):
            raw_tokens.append(self._advance())  # Consume '='
            # The right-hand side should be a variable - just consume it
            if self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
                BaseTokenType.STRING_IDENTIFIER,
            ):
                raw_tokens.append(self._advance())  # Consume the variable

        # Check for modifiers like 'nocase'
        if self._check_keyword("nocase"):
            raw_tokens.append(self._advance())

        return EventStatement(text=_join_event_statement_tokens(raw_tokens))

    def _parse_boolean_expression(self) -> EventStatement:
        """Parse a parenthesized boolean expression like (expr or expr or ...)."""
        # Consume opening parenthesis
        raw_tokens = [self._consume(BaseTokenType.LPAREN, "Expected '('")]

        # Consume all tokens until matching closing parenthesis
        paren_depth = 1
        while paren_depth > 0 and not self._is_at_end():
            if self._check(BaseTokenType.LPAREN):
                paren_depth += 1
            elif self._check(BaseTokenType.RPAREN):
                paren_depth -= 1
                if paren_depth == 0:
                    break
            raw_tokens.append(self._advance())

        # Consume closing parenthesis
        if self._check(BaseTokenType.RPAREN):
            raw_tokens.append(self._advance())

        return EventStatement(text=_join_event_statement_tokens(raw_tokens))


def _join_event_statement_tokens(tokens: list[Any]) -> str:
    text = ""
    for token in tokens:
        piece = _event_statement_token_text(token)
        if not piece:
            continue
        if piece == ",":
            text = f"{text.rstrip()}, "
        elif piece in {".", ")", "]", "}", "(", "[", "{"}:
            text = f"{text.rstrip()}{piece}"
        elif piece in {"=", "!=", "<", ">", "<=", ">=", "and", "or", "in"}:
            text = f"{text.rstrip()} {piece} "
        else:
            if text and not text.endswith((" ", "(", "[", "{", ".")):
                text += " "
            text += piece
    return text.strip()


def _prefix_event_statement(prefix: str, statement: EventStatement) -> EventStatement:
    statement.text = f"{prefix} {statement.text}".strip()
    return statement


def _join_prefixed_event_statement(prefix: str, tokens: list[Any]) -> str:
    rhs = _join_event_statement_tokens(tokens)
    if rhs:
        return f"{prefix} {rhs}"
    return prefix


def _event_statement_token_text(token: Any) -> str:
    value = token.value
    if value is None:
        return ""
    if token.type == BaseTokenType.STRING:
        escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return str(value)
