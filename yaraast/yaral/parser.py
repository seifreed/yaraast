"""YARA-L parser implementation."""

from typing import Any

from yaraast.lexer.tokens import TokenType as BaseTokenType

from .ast_nodes import (
    AggregationFunction,
    BinaryCondition,
    ConditionalExpression,
    ConditionExpression,
    ConditionSection,
    EventAssignment,
    EventCountCondition,
    EventExistsCondition,
    EventsSection,
    EventStatement,
    EventVariable,
    MatchSection,
    MatchVariable,
    MetaEntry,
    MetaSection,
    OptionsSection,
    OutcomeAssignment,
    OutcomeExpression,
    OutcomeSection,
    ReferenceList,
    RegexPattern,
    TimeWindow,
    UDMFieldAccess,
    UDMFieldPath,
    UnaryCondition,
    VariableComparisonCondition,
    YaraLFile,
    YaraLRule,
)
from .lexer import YaraLLexer, YaraLToken
from .tokens import YaraLTokenType

# Constants
EXPECTED_FIELD_NAME_ERROR = "Expected field name"


class YaraLParserError(Exception):
    """YARA-L parser error."""

    def __init__(self, message: str, token: YaraLToken | None = None) -> None:
        if token:
            super().__init__(f"Parser error at {token.line}:{token.column}: {message}")
            self.token = token
        else:
            super().__init__(f"Parser error: {message}")
            self.token = None


class YaraLParser:
    """Parser for YARA-L 2.0 rules."""

    def __init__(self, text: str) -> None:
        self.lexer = YaraLLexer(text)
        self.tokens = self.lexer.tokenize()
        self.current = 0

    def parse(self) -> YaraLFile:
        """Parse YARA-L file."""
        rules = []

        while not self._is_at_end():
            if self._check_keyword("rule"):
                rules.append(self._parse_rule())
            else:
                # Skip unknown tokens
                self._advance()

        return YaraLFile(rules=rules)

    def _parse_rule(self) -> YaraLRule:
        """Parse a YARA-L rule."""
        self._consume_keyword("rule")

        # Get rule name
        name_token = self._consume(BaseTokenType.IDENTIFIER, "Expected rule name")
        rule_name = name_token.value

        self._consume(BaseTokenType.LBRACE, "Expected '{' after rule name")

        # Parse sections
        meta = None
        events = None
        match = None
        condition = None
        outcome = None
        options = None

        while not self._check(BaseTokenType.RBRACE) and not self._is_at_end():
            if self._check_keyword("meta"):
                meta = self._parse_meta_section()
            elif self._check_keyword("events"):
                events = self._parse_events_section()
            elif self._check_keyword("match"):
                match = self._parse_match_section()
            elif self._check_keyword("condition"):
                condition = self._parse_condition_section()
            elif self._check_keyword("outcome"):
                outcome = self._parse_outcome_section()
            elif self._check_keyword("options"):
                options = self._parse_options_section()
            else:
                # Skip unknown sections
                self._advance()

        self._consume(BaseTokenType.RBRACE, "Expected '}' after rule body")

        return YaraLRule(
            name=rule_name,
            meta=meta,
            events=events,
            match=match,
            condition=condition,
            outcome=outcome,
            options=options,
        )

    def _parse_meta_section(self) -> MetaSection:
        """Parse meta section."""
        self._consume_keyword("meta")
        self._consume(BaseTokenType.COLON, "Expected ':' after 'meta'")

        entries = []

        while not self._check_section_keyword() and not self._check(
            BaseTokenType.RBRACE,
        ):
            # Parse meta entry
            key_token = self._consume(BaseTokenType.IDENTIFIER, "Expected meta key")
            key = key_token.value

            self._consume(BaseTokenType.EQ, "Expected '=' after meta key")

            # Parse value
            value = None
            if self._check(BaseTokenType.STRING):
                value = self._advance().value
            elif self._check(BaseTokenType.INTEGER):
                value = int(self._advance().value)
            elif self._check(BaseTokenType.BOOLEAN_TRUE):
                self._advance()
                value = True
            elif self._check(BaseTokenType.BOOLEAN_FALSE):
                self._advance()
                value = False
            else:
                value = self._advance().value

            entries.append(MetaEntry(key=key, value=value))

        return MetaSection(entries=entries)

    def _parse_events_section(self) -> EventsSection:
        """Parse events section."""
        self._consume_keyword("events")
        self._consume(BaseTokenType.COLON, "Expected ':' after 'events'")

        statements = []

        while not self._check_section_keyword() and not self._check(
            BaseTokenType.RBRACE,
        ):
            # Save position to detect infinite loops
            current_pos = self.current

            # Parse event statement
            stmt = self._parse_event_statement()
            if stmt:
                statements.append(stmt)

            # Guard against infinite loop: if position didn't advance, force skip
            if self.current == current_pos:
                if not self._is_at_end():
                    self._advance()
                else:
                    break

        return EventsSection(statements=statements)

    def _parse_event_statement(self) -> EventStatement | None:
        """Parse a single event statement."""
        # Check for parenthesized boolean expressions: (expr or expr or ...)
        if self._check(BaseTokenType.LPAREN):
            return self._parse_boolean_expression()

        # Check for function calls like re.regex()
        if self._check(BaseTokenType.IDENTIFIER):
            identifier = self._peek().value
            # Check if it's a function call pattern: module.function or re.regex keyword
            if identifier in ["re.regex", "re.capture", "strings", "net", "arrays"] or (
                "." in identifier and identifier.split(".")[0] in ["re", "strings", "net", "arrays"]
            ):
                return self._parse_function_call_statement()

        # Check for integer literal starting a comparison statement: 604800 <= $var - $other
        if self._check(BaseTokenType.INTEGER):
            # Parse the entire comparison expression and skip it
            # This handles cases like: 604800 <= $field1 - $field2
            self._advance()  # Consume integer

            # Expect comparison operator
            if (
                self._check(BaseTokenType.LE)
                or self._check(BaseTokenType.GE)
                or self._check(BaseTokenType.LT)
                or self._check(BaseTokenType.GT)
                or self._check(BaseTokenType.EQ)
                or self._check(BaseTokenType.NEQ)
            ):
                self._advance()  # Consume operator

                # Now consume the right-hand side expression
                # This could be complex: $var.field.path - $other.field.path
                # We'll consume tokens until we hit a new statement or section
                start_line = self._peek().line if not self._is_at_end() else -1

                while not self._is_at_end():
                    current_token = self._peek()

                    # Stop if we hit a section keyword or closing brace
                    if self._check_section_keyword() or self._check(BaseTokenType.RBRACE):
                        break

                    # Stop if we see a new line with a new statement pattern
                    if current_token.line > start_line and (
                        self._check_yaral_type(YaraLTokenType.EVENT_VAR)
                        or self._check(BaseTokenType.STRING_IDENTIFIER)
                        or self._check(BaseTokenType.INTEGER)
                        or self._check(BaseTokenType.LPAREN)
                    ):
                        # Check if this looks like a new statement
                        next_pos = self.current + 1
                        if next_pos < len(self.tokens):
                            next_token = self.tokens[next_pos]
                            if (
                                next_token.type == BaseTokenType.EQ
                                or next_token.type == BaseTokenType.DOT
                                or next_token.type == BaseTokenType.LE
                                or next_token.type == BaseTokenType.GE
                                or next_token.type == BaseTokenType.LT
                                or next_token.type == BaseTokenType.GT
                                or next_token.type == BaseTokenType.NEQ
                            ):
                                break

                    self._advance()

                return EventStatement()
            else:
                # Not a comparison, unexpected
                return EventStatement()

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
        # or a field filter (e.g., $e.field = value)
        if self._check(BaseTokenType.EQ):
            # Variable assignment: $var = expression
            self._advance()  # Consume '='

            # Parse the right-hand side expression
            # This could be a function call, event field, or other expression

            # Check if it's a function call
            if self._check(BaseTokenType.IDENTIFIER):
                # Could be a function call or start of field access
                identifier = self._peek().value
                # Check if it's a function call pattern (module.function or known function names)
                if identifier in ["re.regex", "re.capture", "strings", "net", "arrays"] or (
                    identifier.startswith("strings.")
                    or identifier.startswith("re.")
                    or identifier.startswith("net.")
                    or identifier.startswith("arrays.")
                    or identifier.startswith("math.")
                ):
                    return self._parse_function_call_statement()

            # Handle field access on right side: $var = $event.field.path
            if self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
                BaseTokenType.STRING_IDENTIFIER
            ):
                # Skip the entire right-hand side by consuming tokens until end of statement
                # We consume tokens until we see another variable assignment pattern or section keyword
                # Look ahead to determine when the statement ends
                start_line = self._peek().line if not self._is_at_end() else -1

                while not self._is_at_end():
                    current_token = self._peek()

                    # Stop if we hit a section keyword or closing brace
                    if self._check_section_keyword() or self._check(BaseTokenType.RBRACE):
                        break

                    # Stop if we see a new line starting with a $ variable (potential new statement)
                    # Only stop if it's on a different line AND appears to be a new statement
                    if current_token.line > start_line and (
                        self._check_yaral_type(YaraLTokenType.EVENT_VAR)
                        or self._check(BaseTokenType.STRING_IDENTIFIER)
                    ):
                        # Peek ahead one more token to see if there's a . or =
                        # If there's an =, it's definitely a new assignment statement
                        # If there's a ., it could be $event.field which is also a new statement
                        next_pos = self.current + 1
                        if next_pos < len(self.tokens):
                            next_token = self.tokens[next_pos]
                            if (
                                next_token.type == BaseTokenType.EQ
                                or next_token.type == BaseTokenType.DOT
                            ):
                                # This is a new statement
                                break

                    self._advance()
                return EventStatement()

            # Otherwise skip this statement (not fully supported yet)
            return EventStatement()

        # Check if this is a comparison expression: $var != $other_var or $var in %list%
        if (
            self._check(BaseTokenType.NEQ)
            or self._check(BaseTokenType.GT)
            or self._check(BaseTokenType.LT)
            or self._check(BaseTokenType.GE)
            or self._check(BaseTokenType.LE)
            or self._check_keyword("in")
        ):
            # Skip the comparison operator
            self._advance()
            # Skip the right-hand side value (could be variable, reference list, etc.)
            if not self._is_at_end():
                self._advance()
            return EventStatement()

        # Expect dot for field access
        self._consume(BaseTokenType.DOT, "Expected '.' after event variable")

        # Parse field path
        field_path = self._parse_field_path()

        # Check if we're at a section keyword or end of events section
        # This handles cases where field access appears in complex expressions
        # without an operator (e.g., arithmetic expressions that span the field)
        if self._check_section_keyword() or self._check(BaseTokenType.RBRACE):
            # We've reached the end of the events section
            # Return a generic EventStatement to allow the section parser to exit
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
        if self._check(BaseTokenType.INTEGER):
            return int(self._advance().value)
        if self._check_yaral_type(YaraLTokenType.EVENT_VAR):
            # Reference to another event variable
            return EventVariable(name=self._advance().value)
        if self._check_yaral_type(YaraLTokenType.REFERENCE_LIST):
            # Reference list like %suspicious_ips%
            return ReferenceList(name=self._advance().value)
        if self._check(BaseTokenType.REGEX):
            # Regex pattern
            pattern_token = self._advance()
            return RegexPattern(pattern=pattern_token.value)
        # Could be another field reference
        return self._advance().value

    def _parse_match_section(self) -> MatchSection:
        """Parse match section."""
        self._consume_keyword("match")
        self._consume(BaseTokenType.COLON, "Expected ':' after 'match'")

        variables = []

        while not self._check_section_keyword() and not self._check(
            BaseTokenType.RBRACE,
        ):
            # Parse match variables: each can be on its own line with its own time window
            if self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
                BaseTokenType.STRING_IDENTIFIER,
            ):
                var_token = self._advance()
                var_name = var_token.value.lstrip("$")  # Remove $ prefix

                # Check for comma separator (old syntax: $var1, $var2 over 5m)
                if self._check(BaseTokenType.COMMA):
                    # Collect all comma-separated variables for backward compatibility
                    var_names = [var_name]
                    while self._check(BaseTokenType.COMMA):
                        self._advance()
                        if self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
                            BaseTokenType.STRING_IDENTIFIER,
                        ):
                            var_token = self._advance()
                            var_names.append(var_token.value.lstrip("$"))

                    # Now consume 'over' keyword and parse shared time window
                    self._consume_keyword("over", "Expected 'over' after match variable list")

                    # Check for 'every' modifier
                    modifier = None
                    if self._check_keyword("every"):
                        modifier = "every"
                        self._advance()

                    # Parse time window once for all comma-separated variables
                    time_window = self._parse_time_window(modifier)

                    # Create MatchVariable objects with shared time window
                    for vname in var_names:
                        variables.append(MatchVariable(variable=vname, time_window=time_window))
                else:
                    # New syntax: each variable has its own 'over' clause
                    # Expect 'over' keyword
                    self._consume_keyword("over", f"Expected 'over' after variable ${var_name}")

                    # Check for 'every' modifier
                    modifier = None
                    if self._check_keyword("every"):
                        modifier = "every"
                        self._advance()

                    # Parse time window for this variable
                    time_window = self._parse_time_window(modifier)

                    # Create MatchVariable for this single variable
                    variables.append(MatchVariable(variable=var_name, time_window=time_window))
            else:
                # Skip unknown tokens
                self._advance()

        return MatchSection(variables=variables)

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
            self._advance()
            expr = self._parse_condition_expression()
            self._consume(BaseTokenType.RPAREN, "Expected ')' after expression")
            return expr

        # Event count: #e > 5
        if self._check(BaseTokenType.STRING_COUNT):
            self._advance()
            event_name = self._consume(
                BaseTokenType.IDENTIFIER,
                "Expected event name after '#'",
            ).value

            # Parse comparison operator
            operator = None
            if self._check(BaseTokenType.GT):
                operator = ">"
                self._advance()
            elif self._check(BaseTokenType.LT):
                operator = "<"
                self._advance()
            elif self._check(BaseTokenType.GE):
                operator = ">="
                self._advance()
            elif self._check(BaseTokenType.LE):
                operator = "<="
                self._advance()
            elif self._check(BaseTokenType.EQ):
                operator = "=="
                self._advance()
            elif self._check(BaseTokenType.NEQ):
                operator = "!="
                self._advance()
            else:
                msg = "Expected comparison operator"
                raise YaraLParserError(msg, self._peek())

            count = int(
                self._consume(
                    BaseTokenType.INTEGER,
                    "Expected number after operator",
                ).value,
            )

            return EventCountCondition(event=event_name, operator=operator, count=count)

        # Variable or event reference: $var or $e1
        if self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
            BaseTokenType.STRING_IDENTIFIER
        ):
            var_token = self._advance()
            var_name = var_token.value

            # Check if followed by comparison operator
            if (
                self._check(BaseTokenType.GT)
                or self._check(BaseTokenType.LT)
                or self._check(BaseTokenType.GE)
                or self._check(BaseTokenType.LE)
                or self._check(BaseTokenType.EQ)
                or self._check(BaseTokenType.NEQ)
            ):

                # Parse comparison operator
                operator = None
                if self._check(BaseTokenType.GT):
                    operator = ">"
                    self._advance()
                elif self._check(BaseTokenType.LT):
                    operator = "<"
                    self._advance()
                elif self._check(BaseTokenType.GE):
                    operator = ">="
                    self._advance()
                elif self._check(BaseTokenType.LE):
                    operator = "<="
                    self._advance()
                elif self._check(BaseTokenType.EQ):
                    operator = "=="
                    self._advance()
                elif self._check(BaseTokenType.NEQ):
                    operator = "!="
                    self._advance()

                # Parse comparison value
                value = None
                if self._check(BaseTokenType.INTEGER):
                    value = int(self._advance().value)
                elif (
                    self._check(BaseTokenType.STRING)
                    or self._check_yaral_type(YaraLTokenType.EVENT_VAR)
                    or self._check(BaseTokenType.STRING_IDENTIFIER)
                    or self._check(BaseTokenType.IDENTIFIER)
                ):
                    value = self._advance().value
                else:
                    msg = "Expected value after comparison operator"
                    raise YaraLParserError(msg, self._peek())

                return VariableComparisonCondition(
                    variable=var_name, operator=operator, value=value
                )
            else:
                # Just a variable reference (event exists)
                event_name = var_name.lstrip("$")
                return EventExistsCondition(event=event_name)

        # Fallback: treat as exists condition
        if self._check(BaseTokenType.IDENTIFIER):
            name = self._advance().value

            # Check if followed by comparison operator
            if (
                self._check(BaseTokenType.GT)
                or self._check(BaseTokenType.LT)
                or self._check(BaseTokenType.GE)
                or self._check(BaseTokenType.LE)
                or self._check(BaseTokenType.EQ)
                or self._check(BaseTokenType.NEQ)
            ):

                # Parse comparison operator
                operator = None
                if self._check(BaseTokenType.GT):
                    operator = ">"
                    self._advance()
                elif self._check(BaseTokenType.LT):
                    operator = "<"
                    self._advance()
                elif self._check(BaseTokenType.GE):
                    operator = ">="
                    self._advance()
                elif self._check(BaseTokenType.LE):
                    operator = "<="
                    self._advance()
                elif self._check(BaseTokenType.EQ):
                    operator = "=="
                    self._advance()
                elif self._check(BaseTokenType.NEQ):
                    operator = "!="
                    self._advance()

                # Parse comparison value
                value = None
                if self._check(BaseTokenType.INTEGER):
                    value = int(self._advance().value)
                elif (
                    self._check(BaseTokenType.STRING)
                    or self._check_yaral_type(YaraLTokenType.EVENT_VAR)
                    or self._check(BaseTokenType.STRING_IDENTIFIER)
                    or self._check(BaseTokenType.IDENTIFIER)
                ):
                    value = self._advance().value
                else:
                    msg = "Expected value after comparison operator"
                    raise YaraLParserError(msg, self._peek())

                return VariableComparisonCondition(variable=name, operator=operator, value=value)
            else:
                return EventExistsCondition(event=name)

        msg = f"Unexpected token in condition: {self._peek()}"
        raise YaraLParserError(
            msg,
            self._peek(),
        )

    def _parse_outcome_section(self) -> OutcomeSection:
        """Parse outcome section."""
        self._consume_keyword("outcome")
        self._consume(BaseTokenType.COLON, "Expected ':' after 'outcome'")

        assignments = []

        while not self._check_section_keyword() and not self._check(
            BaseTokenType.RBRACE,
        ):
            # Parse outcome assignment: $var = expression
            if self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
                BaseTokenType.STRING_IDENTIFIER,
            ):
                var_token = self._advance()
                var_name = var_token.value

                self._consume(BaseTokenType.EQ, "Expected '=' after outcome variable")

                expression = self._parse_outcome_arithmetic_expression()

                assignments.append(
                    OutcomeAssignment(variable=var_name, expression=expression),
                )
            else:
                self._advance()

        return OutcomeSection(assignments=assignments)

    def _parse_outcome_expression(self) -> OutcomeExpression:
        """Parse outcome expression."""
        # Check for aggregation functions
        if self._check(BaseTokenType.IDENTIFIER):
            token = self._peek()
            if token.value in [
                "count",
                "count_distinct",
                "sum",
                "min",
                "max",
                "avg",
                "array",
                "array_distinct",
                "earliest",
                "latest",
            ]:
                func_name = self._advance().value
                self._consume(BaseTokenType.LPAREN, f"Expected '(' after {func_name}")

                # Parse arguments
                arguments = []
                if not self._check(BaseTokenType.RPAREN):
                    arguments.append(self._parse_outcome_arithmetic_expression())

                    while self._check(BaseTokenType.COMMA):
                        self._advance()
                        arguments.append(self._parse_outcome_arithmetic_expression())

                self._consume(
                    BaseTokenType.RPAREN,
                    f"Expected ')' after {func_name} arguments",
                )

                return AggregationFunction(function=func_name, arguments=arguments)

        # Check for conditional expression: if(condition, true_val, false_val) or if(condition, true_val)
        if self._check_keyword("if"):
            self._advance()
            self._consume(BaseTokenType.LPAREN, "Expected '(' after 'if'")

            condition = self._parse_outcome_condition()
            self._consume(BaseTokenType.COMMA, "Expected ',' after condition")

            true_value = self._parse_outcome_argument()

            # Check if there's a third argument (false value)
            false_value = None
            if self._check(BaseTokenType.COMMA):
                self._advance()  # Consume comma
                false_value = self._parse_outcome_argument()

            self._consume(BaseTokenType.RPAREN, "Expected ')' after if expression")

            return ConditionalExpression(
                condition=condition,
                true_value=true_value,
                false_value=false_value,
            )

        # Default: parse as simple value
        return self._parse_outcome_argument()

    def _parse_outcome_arithmetic_expression(self) -> Any:
        """Parse arithmetic expression in outcome (handles +, -, *, /)."""
        left = self._parse_outcome_expression()

        # Check for arithmetic operators
        while (
            self._check(BaseTokenType.PLUS)
            or self._check(BaseTokenType.MINUS)
            or self._check(BaseTokenType.MULTIPLY)
            or self._check(BaseTokenType.DIVIDE)
        ):
            operator = self._advance().value
            right = self._parse_outcome_expression()
            # Return as string representation for now
            left = f"{left} {operator} {right}"

        return left

    def _parse_outcome_condition(self) -> Any:
        """Parse logical condition in outcome context (handles and, or, not)."""
        return self._parse_outcome_or_condition()

    def _parse_outcome_or_condition(self) -> Any:
        """Parse OR condition in outcome context."""
        left = self._parse_outcome_and_condition()

        while self._check_keyword("or"):
            self._advance()
            right = self._parse_outcome_and_condition()
            left = f"{left} or {right}"

        return left

    def _parse_outcome_and_condition(self) -> Any:
        """Parse AND condition in outcome context."""
        left = self._parse_outcome_not_condition()

        while self._check_keyword("and"):
            self._advance()
            right = self._parse_outcome_not_condition()
            left = f"{left} and {right}"

        return left

    def _parse_outcome_not_condition(self) -> Any:
        """Parse NOT condition in outcome context."""
        if self._check_keyword("not"):
            self._advance()
            operand = self._parse_outcome_not_condition()
            return f"not {operand}"

        return self._parse_outcome_comparison()

    def _parse_outcome_comparison(self) -> Any:
        """Parse comparison expressions in outcome context."""
        # Parse left-hand side with arithmetic support
        # This handles: $field1 - $field2 > value or function() >= value
        left = self._parse_outcome_arithmetic_term()

        # Check for comparison operators
        if (
            self._check(BaseTokenType.EQ)
            or self._check(BaseTokenType.NEQ)
            or self._check(BaseTokenType.GT)
            or self._check(BaseTokenType.LT)
            or self._check(BaseTokenType.GE)
            or self._check(BaseTokenType.LE)
            or self._check(BaseTokenType.IN)
        ):
            op_token = self._advance()
            op = op_token.value

            # Parse right-hand side with arithmetic support
            right = self._parse_outcome_arithmetic_term()

            # Check for nocase modifier after comparison (especially for regex)
            modifier = ""
            if self._check_keyword("nocase"):
                modifier = " nocase"
                self._advance()

            # Return as string representation
            return f"{left} {op} {right}{modifier}"

        return left

    def _parse_outcome_arithmetic_term(self) -> Any:
        """Parse arithmetic term in outcome condition (handles +, -, *, / for comparisons)."""
        left = self._parse_outcome_primary()

        # Check for arithmetic operators
        while (
            self._check(BaseTokenType.PLUS)
            or self._check(BaseTokenType.MINUS)
            or self._check(BaseTokenType.MULTIPLY)
            or self._check(BaseTokenType.DIVIDE)
        ):
            operator = self._advance().value
            right = self._parse_outcome_primary()
            # Return as string representation
            left = f"{left} {operator} {right}"

        return left

    def _parse_outcome_primary(self) -> Any:
        """Parse primary outcome expression (field, literal, variable, etc.)."""
        # Check for regex pattern
        if self._check(BaseTokenType.REGEX):
            pattern_token = self._advance()
            return f"/{pattern_token.value}/"

        # Delegate to existing argument parsing for other types
        return self._parse_outcome_argument_basic()

    def _parse_outcome_argument_basic(self) -> Any:
        """Parse basic outcome argument without comparison handling."""
        # Check for nested conditional expression: if(...)
        if self._check_keyword("if"):
            return self._parse_outcome_expression()

        # Parenthesized expression
        if self._check(BaseTokenType.LPAREN):
            self._advance()  # Consume (
            # Parse as full condition to handle boolean logic (and/or) inside parens
            # Try condition first, fall back to arithmetic if no boolean operators
            expr = self._parse_outcome_condition()
            self._consume(BaseTokenType.RPAREN, "Expected ')' after expression")
            return f"({expr})"

        # Event field access or variable: $e.field.path or $variable
        if self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
            BaseTokenType.STRING_IDENTIFIER
        ):
            event_token = self._advance()
            var_name = event_token.value

            if self._check(BaseTokenType.DOT):
                # It's a field access: $e.field.path
                self._advance()
                field_parts = []
                field_parts.append(
                    self._consume(BaseTokenType.IDENTIFIER, EXPECTED_FIELD_NAME_ERROR).value,
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

                # Return as string representation for comparison context
                return f"{var_name}.{'.'.join(field_parts)}"
            else:
                # Just a variable reference
                return var_name

        # String literal
        if self._check(BaseTokenType.STRING):
            return self._advance().value

        # Number literal
        if self._check(BaseTokenType.INTEGER):
            return int(self._advance().value)

        # Identifier (might be outcome variable, field name, or namespace/function)
        if self._check(BaseTokenType.IDENTIFIER):
            ident = self._advance().value

            # Check if this dotted identifier is followed by parenthesis (function call)
            if self._check(BaseTokenType.LPAREN):
                self._advance()  # Consume (

                # Parse function arguments
                arguments = []
                if not self._check(BaseTokenType.RPAREN):
                    arguments.append(self._parse_outcome_argument())

                    while self._check(BaseTokenType.COMMA):
                        self._advance()  # Consume comma
                        arguments.append(self._parse_outcome_argument())

                self._consume(BaseTokenType.RPAREN, f"Expected ')' after {ident} arguments")

                # Return as string representation
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
        # Check for nested conditional expression: if(...)
        if self._check_keyword("if"):
            return self._parse_outcome_expression()

        # Parenthesized arithmetic expression
        if self._check(BaseTokenType.LPAREN):
            self._advance()  # Consume (
            expr = self._parse_outcome_arithmetic_expression()
            self._consume(BaseTokenType.RPAREN, "Expected ')' after expression")
            return f"({expr})"

        # Event field access or variable: $e.field.path or $variable
        if self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
            BaseTokenType.STRING_IDENTIFIER
        ):
            event_token = self._advance()
            var_name = event_token.value

            if self._check(BaseTokenType.DOT):
                # It's a field access: $e.field.path
                event = EventVariable(name=var_name)
                self._advance()
                field_parts = []
                field_parts.append(
                    self._consume(BaseTokenType.IDENTIFIER, EXPECTED_FIELD_NAME_ERROR).value,
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

                field = UDMFieldPath(parts=field_parts)

                # Check for comparison or arithmetic operator to build expression
                if (
                    self._check(BaseTokenType.GT)
                    or self._check(BaseTokenType.LT)
                    or self._check(BaseTokenType.GE)
                    or self._check(BaseTokenType.LE)
                    or self._check(BaseTokenType.EQ)
                    or self._check(BaseTokenType.NEQ)
                    or self._check(BaseTokenType.IN)
                    or self._check(BaseTokenType.PLUS)
                    or self._check(BaseTokenType.MINUS)
                    or self._check(BaseTokenType.MULTIPLY)
                    or self._check(BaseTokenType.DIVIDE)
                ):
                    # It's a comparison or arithmetic expression
                    op_token = self._advance()
                    op = op_token.value
                    right_value = self._parse_outcome_argument()
                    # Return as simple representation (string for now)
                    return f"{var_name}.{'.'.join(field_parts)} {op} {right_value}"

                return UDMFieldAccess(event=event, field=field)
            elif (
                self._check(BaseTokenType.GT)
                or self._check(BaseTokenType.LT)
                or self._check(BaseTokenType.GE)
                or self._check(BaseTokenType.LE)
                or self._check(BaseTokenType.EQ)
                or self._check(BaseTokenType.NEQ)
                or self._check(BaseTokenType.IN)
                or self._check(BaseTokenType.PLUS)
                or self._check(BaseTokenType.MINUS)
                or self._check(BaseTokenType.MULTIPLY)
                or self._check(BaseTokenType.DIVIDE)
            ):
                # It's a comparison or arithmetic expression
                op_token = self._advance()
                op = op_token.value
                right_value = self._parse_outcome_argument()
                # Return as simple representation
                return f"{var_name} {op} {right_value}"
            else:
                # Just a variable reference
                return var_name

        # String literal
        if self._check(BaseTokenType.STRING):
            return self._advance().value

        # Number literal
        if self._check(BaseTokenType.INTEGER):
            num_value = int(self._advance().value)

            # Check for comparison or arithmetic operator after integer
            if (
                self._check(BaseTokenType.GT)
                or self._check(BaseTokenType.LT)
                or self._check(BaseTokenType.GE)
                or self._check(BaseTokenType.LE)
                or self._check(BaseTokenType.EQ)
                or self._check(BaseTokenType.NEQ)
                or self._check(BaseTokenType.PLUS)
                or self._check(BaseTokenType.MINUS)
                or self._check(BaseTokenType.MULTIPLY)
                or self._check(BaseTokenType.DIVIDE)
            ):
                op_token = self._advance()
                op = op_token.value
                right_value = self._parse_outcome_argument()
                return f"{num_value} {op} {right_value}"

            return num_value

        # Identifier (might be outcome variable, field name, or namespace/function)
        if self._check(BaseTokenType.IDENTIFIER):
            ident = self._advance().value

            # Check if this dotted identifier is followed by parenthesis (function call)
            # The lexer combines namespace.function into a single identifier token
            if self._check(BaseTokenType.LPAREN):
                self._advance()  # Consume (

                # Parse function arguments
                arguments = []
                if not self._check(BaseTokenType.RPAREN):
                    arguments.append(self._parse_outcome_argument())

                    while self._check(BaseTokenType.COMMA):
                        self._advance()  # Consume comma
                        arguments.append(self._parse_outcome_argument())

                self._consume(BaseTokenType.RPAREN, f"Expected ')' after {ident} arguments")

                # Return as string representation for now
                args_str = ", ".join(str(arg) for arg in arguments)
                return f"{ident}({args_str})"

            # Check for comparison or arithmetic operator
            if (
                self._check(BaseTokenType.GT)
                or self._check(BaseTokenType.LT)
                or self._check(BaseTokenType.GE)
                or self._check(BaseTokenType.LE)
                or self._check(BaseTokenType.EQ)
                or self._check(BaseTokenType.NEQ)
                or self._check(BaseTokenType.PLUS)
                or self._check(BaseTokenType.MINUS)
                or self._check(BaseTokenType.MULTIPLY)
                or self._check(BaseTokenType.DIVIDE)
            ):
                op_token = self._advance()
                op = op_token.value
                right_value = self._parse_outcome_argument()
                return f"{ident} {op} {right_value}"

            return ident

        # Regex pattern (e.g., /pattern/ in outcome expressions)
        if self._check(BaseTokenType.REGEX):
            pattern_token = self._advance()
            return RegexPattern(pattern=pattern_token.value)

        msg = f"Unexpected token in outcome: {self._peek()}"
        raise YaraLParserError(
            msg,
            self._peek(),
        )

    def _parse_options_section(self) -> OptionsSection:
        """Parse options section."""
        self._consume_keyword("options")
        self._consume(BaseTokenType.COLON, "Expected ':' after 'options'")

        options = {}

        while not self._check_section_keyword() and not self._check(
            BaseTokenType.RBRACE,
        ):
            # Parse option: key = value
            if self._check(BaseTokenType.IDENTIFIER):
                key = self._advance().value
                self._consume(BaseTokenType.EQ, "Expected '=' after option key")

                # Parse value
                value = None
                if self._check(BaseTokenType.STRING):
                    value = self._advance().value
                elif self._check(BaseTokenType.INTEGER):
                    value = int(self._advance().value)
                elif self._check(BaseTokenType.BOOLEAN_TRUE):
                    self._advance()
                    value = True
                elif self._check(BaseTokenType.BOOLEAN_FALSE):
                    self._advance()
                    value = False
                else:
                    value = self._advance().value

                options[key] = value
            else:
                self._advance()

        return OptionsSection(options=options)

    def _parse_function_call_statement(self) -> EventStatement:
        """Parse function call statement like re.regex($e.field, `pattern`) nocase."""
        # Parse module.function identifier (could be "re.regex" as single token or separate tokens)
        function_name = self._advance().value

        # If it's not a compound name like "re.regex", check for dot and function name
        if "." not in function_name and self._check(BaseTokenType.DOT):
            self._advance()
            # Parse function name
            if self._check(BaseTokenType.IDENTIFIER):
                function_part = self._advance().value
                function_name = f"{function_name}.{function_part}"

        # Consume opening parenthesis
        self._consume(BaseTokenType.LPAREN, "Expected '(' after function name")

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
            self._advance()

        # Consume closing parenthesis
        if self._check(BaseTokenType.RPAREN):
            self._advance()

        # Check for assignment: function(...) = $variable
        if self._check(BaseTokenType.EQ):
            self._advance()  # Consume '='
            # The right-hand side should be a variable - just consume it
            if self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
                BaseTokenType.STRING_IDENTIFIER,
            ):
                self._advance()  # Consume the variable

        # Check for modifiers like 'nocase'
        modifiers = []
        if self._check_keyword("nocase"):
            modifiers.append("nocase")
            self._advance()

        # Return a generic EventStatement for now
        # In a full implementation, you'd parse the arguments properly
        return EventStatement()

    def _parse_boolean_expression(self) -> EventStatement:
        """Parse a parenthesized boolean expression like (expr or expr or ...)."""
        # Consume opening parenthesis
        self._consume(BaseTokenType.LPAREN, "Expected '('")

        # Consume all tokens until matching closing parenthesis
        paren_depth = 1
        while paren_depth > 0 and not self._is_at_end():
            if self._check(BaseTokenType.LPAREN):
                paren_depth += 1
            elif self._check(BaseTokenType.RPAREN):
                paren_depth -= 1
                if paren_depth == 0:
                    break
            self._advance()

        # Consume closing parenthesis
        if self._check(BaseTokenType.RPAREN):
            self._advance()

        # Return a generic EventStatement
        # In a full implementation, you'd parse the boolean logic properly
        return EventStatement()

    # Helper methods

    def _check_section_keyword(self) -> bool:
        """Check if current token is a section keyword."""
        return any(
            self._check_keyword(kw)
            for kw in ["meta", "events", "match", "condition", "outcome", "options"]
        )

    def _check_keyword(self, keyword: str) -> bool:
        """Check if current token is a specific keyword."""
        if self._is_at_end():
            return False
        token = self._peek()
        return token.value and token.value.lower() == keyword.lower()

    def _check_yaral_type(self, yaral_type: YaraLTokenType) -> bool:
        """Check if current token has specific YARA-L type."""
        if self._is_at_end():
            return False
        token = self._peek()
        return hasattr(token, "yaral_type") and token.yaral_type == yaral_type

    def _consume_keyword(self, keyword: str, message: str | None = None) -> YaraLToken:
        """Consume a specific keyword."""
        if not self._check_keyword(keyword):
            msg = message or f"Expected '{keyword}'"
            raise YaraLParserError(msg, self._peek())
        return self._advance()

    def _check(self, token_type: BaseTokenType) -> bool:
        """Check if current token is of given type."""
        if self._is_at_end():
            return False
        return self._peek().type == token_type

    def _consume(self, token_type: BaseTokenType, message: str) -> YaraLToken:
        """Consume token of given type."""
        if not self._check(token_type):
            raise YaraLParserError(message, self._peek())
        return self._advance()

    def _advance(self) -> YaraLToken:
        """Advance to next token."""
        if not self._is_at_end():
            self.current += 1
        return self._previous()

    def _peek(self) -> YaraLToken:
        """Peek at current token."""
        return self.tokens[self.current]

    def _previous(self) -> YaraLToken:
        """Get previous token."""
        return self.tokens[self.current - 1]

    def _is_at_end(self) -> bool:
        """Check if at end of tokens."""
        return self.current >= len(self.tokens) or self._peek().type == BaseTokenType.EOF
