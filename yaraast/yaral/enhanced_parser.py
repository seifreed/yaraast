"""Enhanced YARA-L parser with full support."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from yaraast.lexer.tokens import TokenType as BaseTokenType
from yaraast.yaral.ast_nodes import (
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
    JoinCondition,
    MatchSection,
    MatchVariable,
    OptionsSection,
    OutcomeExpression,
    OutcomeSection,
    ReferenceList,
    RegexPattern,
    TimeWindow,
    UDMFieldAccess,
    UDMFieldPath,
    UnaryCondition,
    YaraLFile,
    YaraLRule,
)
from yaraast.yaral.lexer import YaraLLexer, YaraLToken
from yaraast.yaral.tokens import YaraLTokenType

if TYPE_CHECKING:
    pass


class EnhancedYaraLParser:
    """Enhanced parser for YARA-L 2.0 with full feature support."""

    def __init__(self, text: str) -> None:
        """Initialize enhanced parser.

        Args:
            text: YARA-L source code to parse
        """
        self.lexer = YaraLLexer(text)
        self.tokens = self.lexer.tokenize()
        self.current = 0
        self.errors = []

    def parse(self) -> YaraLFile:
        """Parse YARA-L file with error recovery.

        Returns:
            Parsed YARA-L AST
        """
        rules = []
        max_iterations = 10000  # Safety limit to prevent infinite loops

        iteration = 0
        while not self._is_at_end() and iteration < max_iterations:
            try:
                if self._check_keyword("rule"):
                    rules.append(self._parse_rule())
                else:
                    # Skip unknown tokens with error recovery
                    self._advance()
            except Exception as e:
                self.errors.append(str(e))
                # Try to recover by finding next rule
                self._recover_to_next_rule()
            iteration += 1

        if iteration >= max_iterations:
            self.errors.append(f"Parser exceeded maximum iterations ({max_iterations})")

        return YaraLFile(rules=rules)

    def _parse_rule(self) -> YaraLRule:
        """Parse a complete YARA-L rule."""
        self._consume_keyword("rule")

        # Get rule name
        name_token = self._consume(BaseTokenType.IDENTIFIER, "Expected rule name")
        rule_name = name_token.value

        self._consume(BaseTokenType.LBRACE, "Expected '{' after rule name")

        # Parse all sections
        meta = None
        events = None
        match = None
        condition = None
        outcome = None
        options = None

        # Keep parsing sections until we hit the closing brace
        while not self._check(BaseTokenType.RBRACE) and not self._is_at_end():
            section_parsed = False

            if self._check_keyword("meta"):
                meta = self._parse_meta_section()
                section_parsed = True
            elif self._check_keyword("events"):
                events = self._parse_events_section()
                section_parsed = True
            elif self._check_keyword("match"):
                match = self._parse_match_section()
                section_parsed = True
            elif self._check_keyword("condition"):
                condition = self._parse_condition_section()
                section_parsed = True
            elif self._check_keyword("outcome"):
                outcome = self._parse_outcome_section()
                section_parsed = True
            elif self._check_keyword("options"):
                options = self._parse_options_section()
                section_parsed = True

            if not section_parsed:
                # Skip unknown content
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

    def _parse_events_section(self) -> EventsSection:
        """Parse enhanced events section with joins and complex conditions."""
        self._consume_keyword("events")
        self._consume(BaseTokenType.COLON, "Expected ':' after 'events'")

        statements = []

        while not self._check_section_keyword() and not self._check(BaseTokenType.RBRACE):
            # Parse event statement or join
            if self._check_yaral_type(YaraLTokenType.EVENT_VAR):
                stmt = self._parse_event_statement()
                statements.append(stmt)
            elif self._check_keyword("join"):
                join = self._parse_join_statement()
                statements.append(join)
            else:
                # Try to parse complex event patterns
                stmt = self._parse_complex_event_pattern()
                if stmt:
                    statements.append(stmt)
                else:
                    self._advance()

        return EventsSection(statements=statements)

    def _parse_event_statement(self) -> EventStatement:
        """Parse enhanced event statement with multiple conditions."""
        event = None
        assignments = []

        # Parse event variable ($e, $e1, etc.)
        if self._check_yaral_type(YaraLTokenType.EVENT_VAR):
            event_token = self._advance()
            event = EventVariable(name=event_token.value)

        # Parse field assignments
        while self._check(BaseTokenType.DOT) or (
            self._check(BaseTokenType.IDENTIFIER) and not self._check_section_keyword()
        ):
            if self._check(BaseTokenType.DOT):
                self._advance()

            # Parse UDM field path
            field_path = self._parse_udm_field_path()

            # Parse operator
            operator = self._parse_comparison_operator()

            # Parse value (can be literal, reference, or another field)
            value = self._parse_event_value()

            assignments.append(
                EventAssignment(
                    field_path=field_path,
                    operator=operator,
                    value=value,
                )
            )

            # Check for AND continuation
            if self._check_keyword("and"):
                self._advance()
            elif not self._check(BaseTokenType.DOT):
                break

        return EventStatement(event=event, assignments=assignments)

    def _parse_join_statement(self) -> JoinCondition:
        """Parse join statement for correlating events."""
        self._consume_keyword("join")

        # Parse left event
        left_event = self._consume(BaseTokenType.IDENTIFIER, "Expected left event").value

        self._consume_keyword("on")

        # Parse join condition
        condition = self._parse_join_condition()

        self._consume_keyword("with")

        # Parse right event
        right_event = self._consume(BaseTokenType.IDENTIFIER, "Expected right event").value

        return JoinCondition(
            left_event=left_event,
            right_event=right_event,
            condition=condition,
        )

    def _parse_complex_event_pattern(self) -> EventStatement | None:
        """Parse complex event patterns with temporal operators."""
        # Handle patterns like:
        # $e1 followed by $e2 within 5m
        # $e1 before $e2
        # all $e1 having same principal.hostname

        if self._check_keyword("all"):
            return self._parse_all_pattern()
        if self._check_keyword("any"):
            return self._parse_any_pattern()
        if self._check(BaseTokenType.IDENTIFIER):
            # Check for temporal operators
            peek_ahead = self._peek_ahead(1)
            if peek_ahead and peek_ahead.value in ["followed", "before", "after"]:
                return self._parse_temporal_pattern()

        return None

    def _parse_match_section(self) -> MatchSection:
        """Parse enhanced match section with grouping and windows."""
        self._consume_keyword("match")
        self._consume(BaseTokenType.COLON, "Expected ':' after 'match'")

        variables = []
        time_window = None

        while not self._check_section_keyword() and not self._check(BaseTokenType.RBRACE):
            # Parse match variables or time window
            if self._check_keyword("over"):
                time_window = self._parse_time_window()
            elif self._check(BaseTokenType.IDENTIFIER):
                var = self._parse_match_variable()
                variables.append(var)
            else:
                self._advance()

        return MatchSection(variables=variables, time_window=time_window)

    def _parse_match_variable(self) -> MatchVariable:
        """Parse match variable with grouping conditions."""
        name = self._consume(BaseTokenType.IDENTIFIER, "Expected variable name").value

        self._consume(BaseTokenType.EQ, "Expected '=' after match variable")

        # Parse field or aggregation
        field = None
        if self._check(BaseTokenType.IDENTIFIER):
            field = self._parse_udm_field_access()

        # Parse optional condition
        condition = None
        if self._check_keyword("over"):
            self._advance()
            condition = self._parse_time_duration()

        return MatchVariable(name=name, field=field, condition=condition)

    def _parse_condition_section(self) -> ConditionSection:
        """Parse enhanced condition section with complex logic."""
        self._consume_keyword("condition")
        self._consume(BaseTokenType.COLON, "Expected ':' after 'condition'")

        # Parse complex condition expression
        expression = self._parse_condition_expression()

        return ConditionSection(expression=expression)

    def _parse_condition_expression(self) -> ConditionExpression:
        """Parse complex condition expressions with full boolean logic."""
        return self._parse_or_condition()

    def _parse_or_condition(self) -> ConditionExpression:
        """Parse OR conditions."""
        left = self._parse_and_condition()

        while self._check_keyword("or"):
            self._advance()
            right = self._parse_and_condition()
            left = BinaryCondition(left=left, operator="or", right=right)

        return left

    def _parse_and_condition(self) -> ConditionExpression:
        """Parse AND conditions."""
        left = self._parse_not_condition()

        while self._check_keyword("and"):
            self._advance()
            right = self._parse_not_condition()
            left = BinaryCondition(left=left, operator="and", right=right)

        return left

    def _parse_not_condition(self) -> ConditionExpression:
        """Parse NOT conditions."""
        if self._check_keyword("not"):
            self._advance()
            operand = self._parse_not_condition()
            return UnaryCondition(operator="not", operand=operand)

        return self._parse_primary_condition()

    def _parse_primary_condition(self) -> ConditionExpression:
        """Parse primary condition expressions."""
        # Parentheses
        if self._check(BaseTokenType.LPAREN):
            self._advance()
            expr = self._parse_condition_expression()
            self._consume(BaseTokenType.RPAREN, "Expected ')' after expression")
            return expr

        # Event count: #e > 5
        if self._check(BaseTokenType.HASH):
            return self._parse_event_count_condition()

        # Event exists: $e1
        if self._check_yaral_type(YaraLTokenType.EVENT_VAR):
            event_name = self._advance().value
            return EventExistsCondition(event=event_name)

        # Field comparison
        if self._check(BaseTokenType.IDENTIFIER):
            return self._parse_field_comparison()

        # Reference list check: ip in %suspicious_ips
        if self._check(BaseTokenType.PERCENT):
            return self._parse_reference_check()

        raise self._error("Expected condition expression")

    def _parse_outcome_section(self) -> OutcomeSection:
        """Parse enhanced outcome section with conditionals."""
        self._consume_keyword("outcome")
        self._consume(BaseTokenType.COLON, "Expected ':' after 'outcome'")

        variables = {}
        conditional_expressions = []

        while not self._check_section_keyword() and not self._check(BaseTokenType.RBRACE):
            # Check for conditional expression
            if self._check_keyword("if"):
                cond_expr = self._parse_conditional_expression()
                conditional_expressions.append(cond_expr)
            # Parse outcome variable assignment
            elif self._check_yaral_type(YaraLTokenType.EVENT_VAR) or self._check(
                BaseTokenType.STRING_IDENTIFIER
            ):
                var_name = self._advance().value
                self._consume(BaseTokenType.EQ, "Expected '=' after outcome variable")
                expression = self._parse_outcome_expression()
                variables[var_name] = expression
            else:
                self._advance()

        return OutcomeSection(
            variables=variables,
            conditional_expressions=conditional_expressions,
        )

    def _parse_outcome_expression(self) -> OutcomeExpression:
        """Parse enhanced outcome expression with aggregations."""
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
                "string_concat",
            ]:
                return self._parse_aggregation_function()

        # Check for field access
        if (
            self._check(BaseTokenType.IDENTIFIER)
            and self._peek_ahead(1)
            and self._peek_ahead(1).type == BaseTokenType.DOT
        ):
            field = self._parse_udm_field_access()
            return OutcomeExpression(field=field)

        # Check for literal
        if self._check(BaseTokenType.STRING):
            literal = self._advance().value
            return OutcomeExpression(literal=literal)
        if self._check(BaseTokenType.NUMBER):
            literal = int(self._advance().value)
            return OutcomeExpression(literal=literal)

        raise self._error("Expected outcome expression")

    def _parse_aggregation_function(self) -> OutcomeExpression:
        """Parse aggregation function."""
        func_name = self._advance().value

        self._consume(BaseTokenType.LPAREN, f"Expected '(' after {func_name}")

        arguments = []
        while not self._check(BaseTokenType.RPAREN):
            # Parse argument (field or literal)
            if self._check(BaseTokenType.IDENTIFIER):
                arg = self._parse_udm_field_access()
                arguments.append(arg)
            elif self._check(BaseTokenType.STRING) or self._check(BaseTokenType.NUMBER):
                arg = self._advance().value
                arguments.append(arg)

            if self._check(BaseTokenType.COMMA):
                self._advance()
            else:
                break

        self._consume(BaseTokenType.RPAREN, f"Expected ')' after {func_name} arguments")

        aggregation = AggregationFunction(function=func_name, arguments=arguments)
        return OutcomeExpression(aggregation=aggregation)

    # Helper methods
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

        # Check for event variable prefix
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
        if self._check(BaseTokenType.GTE):
            self._advance()
            return ">="
        if self._check(BaseTokenType.LTE):
            self._advance()
            return "<="
        if self._check_keyword("matches"):
            self._advance()
            return "=~"
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

        duration = int(self._consume(BaseTokenType.NUMBER, "Expected duration").value)
        unit = self._consume(BaseTokenType.IDENTIFIER, "Expected time unit").value

        return TimeWindow(duration=duration, unit=unit)

    def _check_keyword(self, keyword: str) -> bool:
        """Check if current token is a keyword."""
        if self._is_at_end():
            return False
        token = self._peek()
        return token.type == BaseTokenType.IDENTIFIER and token.value == keyword

    def _consume_keyword(self, keyword: str) -> YaraLToken:
        """Consume a keyword token."""
        if not self._check_keyword(keyword):
            raise self._error(f"Expected keyword '{keyword}'")
        return self._advance()

    def _check_yaral_type(self, token_type: YaraLTokenType) -> bool:
        """Check if current token is a YARA-L specific type."""
        if self._is_at_end():
            return False
        token = self._peek()
        return hasattr(token, "yaral_type") and token.yaral_type == token_type

    def _check_section_keyword(self) -> bool:
        """Check if current token is a section keyword."""
        section_keywords = [
            "meta",
            "events",
            "match",
            "condition",
            "outcome",
            "options",
        ]
        return any(self._check_keyword(kw) for kw in section_keywords)

    def _peek(self) -> YaraLToken:
        """Get current token without advancing."""
        if self._is_at_end():
            return self.tokens[-1]
        return self.tokens[self.current]

    def _peek_ahead(self, n: int) -> YaraLToken | None:
        """Peek ahead n tokens."""
        index = self.current + n
        if index < len(self.tokens):
            return self.tokens[index]
        return None

    def _advance(self) -> YaraLToken:
        """Consume and return current token."""
        if not self._is_at_end():
            self.current += 1
        return self.tokens[self.current - 1]

    def _check(self, token_type: BaseTokenType) -> bool:
        """Check if current token is of given type."""
        if self._is_at_end():
            return False
        return self._peek().type == token_type

    def _consume(self, token_type: BaseTokenType, message: str) -> YaraLToken:
        """Consume token of given type or raise error."""
        if self._check(token_type):
            return self._advance()
        raise self._error(message)

    def _is_at_end(self) -> bool:
        """Check if at end of tokens."""
        return self.current >= len(self.tokens) or self._peek().type == BaseTokenType.EOF

    def _error(self, message: str) -> Exception:
        """Create parser error."""
        token = self._peek() if not self._is_at_end() else None
        if token:
            return ValueError(f"Parser error at {token.line}:{token.column}: {message}")
        return ValueError(f"Parser error: {message}")

    def _recover_to_next_rule(self) -> None:
        """Recover parser to next rule for error recovery."""
        while not self._is_at_end():
            if self._check_keyword("rule"):
                break
            self._advance()

    def _parse_event_value(self) -> Any:
        """Parse event value (literal, reference, or field)."""
        if self._check(BaseTokenType.STRING):
            return self._advance().value
        if self._check(BaseTokenType.NUMBER):
            return int(self._advance().value)
        if self._check(BaseTokenType.PERCENT):
            # Reference list
            self._advance()
            name = self._consume(BaseTokenType.IDENTIFIER, "Expected reference list name").value
            return ReferenceList(name=name)
        if self._check_yaral_type(YaraLTokenType.EVENT_VAR):
            # Event variable reference
            return self._parse_udm_field_access()
        if self._check(BaseTokenType.IDENTIFIER):
            # Could be field path or boolean
            token = self._peek()
            if token.value in ["true", "false"]:
                self._advance()
                return token.value == "true"
            return self._parse_udm_field_path()
        if self._check(BaseTokenType.DIV):
            # Regex pattern
            return self._parse_regex_pattern()
        raise self._error("Expected value")

    def _parse_regex_pattern(self) -> RegexPattern:
        """Parse regex pattern like /pattern/modifiers."""
        self._consume(BaseTokenType.DIV, "Expected '/' for regex")

        # Collect pattern until closing /
        pattern_parts = []
        while not self._check(BaseTokenType.DIV) and not self._is_at_end():
            pattern_parts.append(str(self._advance().value))

        pattern = "".join(pattern_parts)

        self._consume(BaseTokenType.DIV, "Expected '/' to close regex")

        # Check for modifiers
        modifiers = ""
        if self._check(BaseTokenType.IDENTIFIER):
            token = self._peek()
            if len(token.value) <= 3 and all(c in "igms" for c in token.value):
                modifiers = self._advance().value

        return RegexPattern(pattern=pattern, modifiers=modifiers)

    def _parse_event_count_condition(self) -> EventCountCondition:
        """Parse event count condition like #e > 5."""
        self._consume(BaseTokenType.HASH, "Expected '#'")

        event_name = self._consume(BaseTokenType.IDENTIFIER, "Expected event name").value
        operator = self._parse_comparison_operator()
        count = int(self._consume(BaseTokenType.NUMBER, "Expected count").value)

        return EventCountCondition(event=event_name, operator=operator, count=count)

    def _parse_field_comparison(self) -> ConditionExpression:
        """Parse field comparison condition."""
        field = self._parse_udm_field_access()
        operator = self._parse_comparison_operator()
        value = self._parse_event_value()

        return BinaryCondition(left=field, operator=operator, right=value)

    def _parse_reference_check(self) -> ConditionExpression:
        """Parse reference list check like: ip in %suspicious_ips."""
        field = self._parse_udm_field_access()

        self._consume_keyword("in")

        self._consume(BaseTokenType.PERCENT, "Expected '%' for reference list")
        list_name = self._consume(BaseTokenType.IDENTIFIER, "Expected reference list name").value

        ref_list = ReferenceList(name=list_name)
        return BinaryCondition(left=field, operator="in", right=ref_list)

    def _parse_conditional_expression(self) -> ConditionalExpression:
        """Parse conditional expression in outcome section."""
        self._consume_keyword("if")

        condition = self._parse_condition_expression()

        self._consume_keyword("then")

        then_expr = self._parse_outcome_expression()

        else_expr = None
        if self._check_keyword("else"):
            self._advance()
            else_expr = self._parse_outcome_expression()

        return ConditionalExpression(
            condition=condition,
            then_expression=then_expr,
            else_expression=else_expr,
        )

    def _parse_options_section(self) -> OptionsSection:
        """Parse options section."""
        self._consume_keyword("options")
        self._consume(BaseTokenType.COLON, "Expected ':' after 'options'")

        options = {}

        while not self._check_section_keyword() and not self._check(BaseTokenType.RBRACE):
            # Parse option key = value
            if self._check(BaseTokenType.IDENTIFIER):
                key = self._advance().value
                self._consume(BaseTokenType.EQ, "Expected '=' after option key")

                # Parse value
                value = self._parse_option_value()

                options[key] = value
            else:
                self._advance()

        return OptionsSection(options=options)

    def _parse_option_value(self) -> str | int | bool:
        """Parse an option value (string, number, or boolean)."""
        if self._check(BaseTokenType.STRING):
            return self._advance().value
        if self._check(BaseTokenType.NUMBER):
            return int(self._advance().value)
        if self._check(BaseTokenType.IDENTIFIER):
            token = self._advance()
            if token.value in ["true", "false"]:
                return token.value == "true"
            return token.value
        raise self._error("Expected option value")

    def _parse_all_pattern(self) -> EventStatement | None:
        """Parse 'all' pattern for events."""
        self._consume_keyword("all")
        # Implementation for 'all' patterns
        # This would be expanded based on specific YARA-L requirements
        return None

    def _parse_any_pattern(self) -> EventStatement | None:
        """Parse 'any' pattern for events."""
        self._consume_keyword("any")
        # Implementation for 'any' patterns
        # This would be expanded based on specific YARA-L requirements
        return None

    def _parse_temporal_pattern(self) -> EventStatement | None:
        """Parse temporal patterns like 'followed by', 'before', 'after'."""
        # Implementation for temporal patterns
        # This would be expanded based on specific YARA-L requirements
        return None

    def _parse_join_condition(self) -> ConditionExpression:
        """Parse join condition for event correlation."""
        # Parse field equality or other join conditions
        return self._parse_condition_expression()

    def _parse_time_duration(self) -> str:
        """Parse time duration like '5m', '1h', '30s'."""
        duration = self._consume(BaseTokenType.NUMBER, "Expected duration").value
        unit = self._consume(BaseTokenType.IDENTIFIER, "Expected time unit").value
        return f"{duration}{unit}"
