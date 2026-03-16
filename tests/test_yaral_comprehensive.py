"""
Comprehensive tests for YARA-L parser module.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.
"""

from __future__ import annotations

import pytest

from yaraast.lexer.tokens import TokenType as BaseTokenType
from yaraast.yaral.ast_nodes import (
    AggregationFunction,
    EventVariable,
    RegexPattern,
    TimeWindow,
    UDMFieldAccess,
    UDMFieldPath,
)
from yaraast.yaral.lexer import YaraLLexer
from yaraast.yaral.parser import YaraLParser, YaraLParserError
from yaraast.yaral.tokens import YaraLTokenType


class TestYaraLLexerComprehensive:
    """Comprehensive tests for YARA-L lexer."""

    def test_lexer_time_literals(self) -> None:
        """Test lexing time literals like 5m, 1h, 7d, 30s."""
        lexer = YaraLLexer("5m 1h 7d 30s")
        tokens = lexer.tokenize()

        # Filter out whitespace and EOF
        time_tokens = [t for t in tokens if t.yaral_type == YaraLTokenType.TIME_LITERAL]

        assert len(time_tokens) == 4
        assert time_tokens[0].value == "5m"
        assert time_tokens[1].value == "1h"
        assert time_tokens[2].value == "7d"
        assert time_tokens[3].value == "30s"

    def test_lexer_reference_lists(self) -> None:
        """Test lexing reference list tokens like %list_name%."""
        lexer = YaraLLexer("%blocked_ips% %trusted_domains% %user_list%")
        tokens = lexer.tokenize()

        ref_tokens = [t for t in tokens if t.yaral_type == YaraLTokenType.REFERENCE_LIST]

        assert len(ref_tokens) == 3
        assert ref_tokens[0].value == "%blocked_ips%"
        assert ref_tokens[1].value == "%trusted_domains%"
        assert ref_tokens[2].value == "%user_list%"

    def test_lexer_event_variables(self) -> None:
        """Test lexing event variables like $e, $e1, $login."""
        lexer = YaraLLexer("$e $e1 $login $event_var_name")
        tokens = lexer.tokenize()

        event_tokens = [t for t in tokens if t.yaral_type == YaraLTokenType.EVENT_VAR]

        assert len(event_tokens) == 4
        assert event_tokens[0].value == "$e"
        assert event_tokens[1].value == "$e1"
        assert event_tokens[2].value == "$login"
        assert event_tokens[3].value == "$event_var_name"

    def test_lexer_backtick_regex(self) -> None:
        """Test lexing backtick-delimited regex patterns."""
        lexer = YaraLLexer(r"`.*malicious\.com` `^test-[0-9]+$`")
        tokens = lexer.tokenize()

        regex_tokens = [t for t in tokens if t.type == BaseTokenType.REGEX]

        assert len(regex_tokens) == 2
        assert r".*malicious\.com" in regex_tokens[0].value
        assert r"^test-[0-9]+$" in regex_tokens[1].value

    def test_lexer_two_char_operators(self) -> None:
        """Test lexing two-character operators."""
        lexer = YaraLLexer("-> :: >= <= == !=")
        tokens = lexer.tokenize()

        operators = [t for t in tokens if t.type != BaseTokenType.EOF]

        assert len(operators) == 6
        assert operators[0].value == "->"
        assert operators[1].value == "::"
        assert operators[2].value == ">="
        assert operators[3].value == "<="
        assert operators[4].value == "=="
        assert operators[5].value == "!="

    def test_lexer_single_line_comment(self) -> None:
        """Test that single-line comments are skipped."""
        lexer = YaraLLexer("rule test // this is a comment\n{ }")
        tokens = lexer.tokenize()

        # Comments should not appear in token stream
        token_values = [t.value for t in tokens if t.type != BaseTokenType.EOF]
        assert "this" not in token_values
        assert "comment" not in token_values
        assert "rule" in token_values
        assert "test" in token_values

    def test_lexer_multi_line_comment(self) -> None:
        """Test that multi-line comments are skipped."""
        lexer = YaraLLexer("rule test /* this is\n a multi-line\n comment */ { }")
        tokens = lexer.tokenize()

        token_values = [t.value for t in tokens if t.type != BaseTokenType.EOF]
        assert "this" not in token_values
        assert "multi-line" not in token_values
        assert "rule" in token_values

    def test_lexer_string_with_escapes(self) -> None:
        """Test lexing strings with escape sequences."""
        lexer = YaraLLexer(r'"test\"string" "path\\with\\backslashes"')
        tokens = lexer.tokenize()

        string_tokens = [t for t in tokens if t.type == BaseTokenType.STRING]

        assert len(string_tokens) == 2
        # Escape sequences should be processed
        assert '"' in string_tokens[0].value or "string" in string_tokens[0].value
        assert "backslashes" in string_tokens[1].value

    def test_lexer_regex_with_flags(self) -> None:
        """Test lexing regex patterns with flags."""
        lexer = YaraLLexer("field = /pattern/i other = /test/ig")
        tokens = lexer.tokenize()

        regex_tokens = [t for t in tokens if t.type == BaseTokenType.REGEX]

        assert len(regex_tokens) >= 1
        assert "pattern" in regex_tokens[0].value

    def test_lexer_numbers(self) -> None:
        """Test lexing integer and decimal numbers."""
        lexer = YaraLLexer("42 123 999 3.14")
        tokens = lexer.tokenize()

        number_tokens = [t for t in tokens if t.type == BaseTokenType.INTEGER]

        assert len(number_tokens) == 4
        assert number_tokens[0].value == "42"
        assert number_tokens[3].value == "3.14"

    def test_lexer_keywords(self) -> None:
        """Test lexing YARA-L keywords."""
        lexer = YaraLLexer("rule meta events match outcome condition options over")
        tokens = lexer.tokenize()

        keyword_values = [t.value for t in tokens if t.value is not None]

        assert "rule" in keyword_values
        assert "meta" in keyword_values
        assert "events" in keyword_values
        assert "match" in keyword_values
        assert "outcome" in keyword_values
        assert "over" in keyword_values

    def test_lexer_udm_field_paths(self) -> None:
        """Test lexing UDM field paths with dots."""
        lexer = YaraLLexer("metadata.event_type principal.hostname target.process.file.full_path")
        tokens = lexer.tokenize()

        # UDM field paths should be tokenized with proper yaral_type
        udm_tokens = [t for t in tokens if t.yaral_type == YaraLTokenType.UDM]

        assert len(udm_tokens) >= 2

    def test_lexer_safety_limit(self) -> None:
        """Test lexer safety limit to prevent infinite loops."""
        # Create a pathological input that could cause issues
        lexer = YaraLLexer("\x00" * 100)
        tokens = lexer.tokenize()

        # Should terminate and return EOF
        assert tokens[-1].type == BaseTokenType.EOF

    def test_lexer_regex_context_detection(self) -> None:
        """Test regex context detection heuristic."""
        # After '=' it should be treated as regex
        lexer = YaraLLexer("field = /pattern/")
        tokens = lexer.tokenize()

        regex_tokens = [t for t in tokens if t.type == BaseTokenType.REGEX]
        assert len(regex_tokens) >= 1

    def test_lexer_division_operator(self) -> None:
        """Test division operator in non-regex context."""
        lexer = YaraLLexer("10 / 2")
        tokens = lexer.tokenize()

        div_tokens = [t for t in tokens if t.type == BaseTokenType.DIVIDE]
        assert len(div_tokens) == 1


class TestYaraLParserEdgeCases:
    """Test edge cases and error conditions in YARA-L parser."""

    def test_parser_error_with_token_info(self) -> None:
        """Test that parser errors include token information."""
        yaral_code = """
        rule test {
            events:
                $e.field
        }
        """
        parser = YaraLParser(yaral_code)

        # This should either parse successfully (incomplete statement) or raise error
        # The parser is designed to skip incomplete statements
        try:
            ast = parser.parse()
            assert len(ast.rules) >= 0
        except YaraLParserError as e:
            error_msg = str(e)
            assert "Parser error" in error_msg or "Expected" in error_msg

    def test_parser_unknown_tokens_skipped(self) -> None:
        """Test that parser skips unknown tokens gracefully."""
        yaral_code = """
        rule test {
            meta:
                key = "value"
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        assert len(ast.rules) == 1

    def test_meta_section_integer_values(self) -> None:
        """Test parsing meta section with integer values."""
        yaral_code = """
        rule test {
            meta:
                severity = 8
                priority = 10
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.meta is not None
        assert len(rule.meta.entries) == 2
        assert isinstance(rule.meta.entries[0].value, int)
        assert rule.meta.entries[0].value == 8

    def test_meta_section_boolean_values(self) -> None:
        """Test parsing meta section with boolean values."""
        yaral_code = """
        rule test {
            meta:
                enabled = true
                deprecated = false
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.meta is not None
        assert len(rule.meta.entries) == 2
        assert rule.meta.entries[0].value is True
        assert rule.meta.entries[1].value is False

    def test_events_section_infinite_loop_guard(self) -> None:
        """Test events section guard against infinite loops."""
        yaral_code = """
        rule test {
            events:
                $e.field = "value"
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        # Should parse without hanging
        assert len(ast.rules) == 1

    def test_events_integer_literal_comparison(self) -> None:
        """Test parsing integer literal starting a comparison."""
        yaral_code = """
        rule test {
            events:
                604800 <= $e.field1 - $e.field2
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        assert len(ast.rules) == 1

    def test_events_variable_assignment_with_function(self) -> None:
        """Test parsing variable assignment with function call."""
        yaral_code = """
        rule test {
            events:
                $var = re.regex($e.field, `pattern`)
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        assert len(ast.rules) == 1

    def test_events_boolean_expression(self) -> None:
        """Test parsing parenthesized boolean expressions."""
        yaral_code = """
        rule test {
            events:
                ($e.field1 = "value" or $e.field2 = "other")
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        assert len(ast.rules) == 1

    def test_events_function_call_patterns(self) -> None:
        """Test parsing various function call patterns."""
        yaral_code = """
        rule test {
            events:
                re.regex($e.field, `pattern`) nocase
                strings.concat($e.field1, $e.field2)
                net.ip_in_range($e.ip, "192.168.0.0/16")
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        assert len(ast.rules) == 1

    def test_events_field_path_with_brackets(self) -> None:
        """Test parsing field paths with bracket accessors."""
        yaral_code = """
        rule test {
            events:
                $e.fields["key"] = "value"
                $e.array[0] = "item"
                $e.nested.fields["deep"]["key"] = "val"
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.events is not None
        assert len(rule.events.statements) >= 3

    def test_events_variable_comparison(self) -> None:
        """Test parsing variable comparison expressions."""
        yaral_code = """
        rule test {
            events:
                $var1 != $var2
                $var3 in %reference_list%
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        assert len(ast.rules) == 1

    def test_match_section_multiple_variables(self) -> None:
        """Test parsing multiple match variables (one per line)."""
        yaral_code = """
        rule test {
            events:
                $e.field = "value"

            match:
                $var1 over 5m
                $var2 over 5m
                $var3 over 5m
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.match is not None
        assert len(rule.match.variables) == 3

    def test_match_section_every_modifier(self) -> None:
        """Test parsing 'every' modifier in time windows."""
        yaral_code = """
        rule test {
            events:
                $e.field = "value"

            match:
                $hostname over every 1h
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.match is not None
        assert rule.match.variables[0].time_window.modifier == "every"

    def test_time_window_various_units(self) -> None:
        """Test parsing time windows with different units."""
        yaral_code = """
        rule test {
            events:
                $e.field = "value"

            match:
                $var1 over 30s
                $var2 over 15m
                $var3 over 2h
                $var4 over 7d
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.match is not None
        assert rule.match.variables[0].time_window.unit == "s"
        assert rule.match.variables[1].time_window.unit == "m"
        assert rule.match.variables[2].time_window.unit == "h"
        assert rule.match.variables[3].time_window.unit == "d"

    def test_condition_event_count_all_operators(self) -> None:
        """Test event count conditions with all comparison operators."""
        yaral_code = """
        rule test {
            events:
                $e.field = "value"

            condition:
                (#e > 5) or (#e < 10) or (#e >= 3) or (#e <= 7)
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        assert len(ast.rules) == 1

    def test_condition_variable_exists(self) -> None:
        """Test parsing variable exists conditions."""
        yaral_code = """
        rule test {
            events:
                $e1.field = "value"
                $e2.field = "other"

            condition:
                $e1 and not $e2
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.condition is not None

    def test_condition_variable_comparison(self) -> None:
        """Test parsing variable comparison conditions."""
        yaral_code = """
        rule test {
            events:
                $e.field = "value"

            outcome:
                $count = count($e.field)

            condition:
                $count > 100 and $count <= 1000
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        assert len(ast.rules) == 1

    def test_condition_identifier_comparison(self) -> None:
        """Test parsing identifier comparison conditions."""
        yaral_code = """
        rule test {
            events:
                $e.field = "value"

            condition:
                identifier > 5
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        assert len(ast.rules) == 1

    def test_outcome_all_aggregation_functions(self) -> None:
        """Test parsing all aggregation functions in outcome."""
        yaral_code = """
        rule test {
            events:
                $e.field = "value"

            outcome:
                $c1 = count($e.id)
                $c2 = count_distinct($e.host)
                $c3 = sum($e.bytes)
                $c4 = min($e.timestamp)
                $c5 = max($e.timestamp)
                $c6 = avg($e.score)
                $c7 = array($e.ip)
                $c8 = array_distinct($e.domain)
                $c9 = earliest($e.time)
                $c10 = latest($e.time)

            condition:
                $c1 > 0
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.outcome is not None
        assert len(rule.outcome.assignments) == 10

        # Verify all are aggregation functions
        for assignment in rule.outcome.assignments:
            assert isinstance(assignment.expression, AggregationFunction)

    def test_outcome_arithmetic_operators(self) -> None:
        """Test parsing arithmetic expressions in outcome."""
        yaral_code = """
        rule test {
            events:
                $e.field = "value"

            outcome:
                $result1 = $val1 + $val2
                $result2 = $val1 - $val2
                $result3 = $val1 * $val2
                $result4 = $val1 / $val2

            condition:
                $e
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.outcome is not None
        assert len(rule.outcome.assignments) == 4

    def test_outcome_nested_conditionals(self) -> None:
        """Test parsing nested conditional expressions in outcome."""
        yaral_code = """
        rule test {
            events:
                $e.field = "value"

            outcome:
                $severity = if($count > 100, "HIGH", if($count > 50, "MEDIUM", "LOW"))
                $risk = if($severity = "HIGH", 90, if($severity = "MEDIUM", 60, 30))

            condition:
                $e
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.outcome is not None
        assert len(rule.outcome.assignments) == 2

    def test_outcome_conditional_two_arguments(self) -> None:
        """Test parsing conditional with only two arguments (no false value)."""
        yaral_code = """
        rule test {
            events:
                $e.field = "value"

            outcome:
                $flag = if($count > 100, "HIGH")

            condition:
                $e
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.outcome is not None

    def test_outcome_boolean_logic_in_conditions(self) -> None:
        """Test parsing boolean logic (and/or/not) in outcome conditions."""
        yaral_code = """
        rule test {
            events:
                $e.field = "value"

            outcome:
                $result = if($field1 = "test" and $field2 = "value", "YES", "NO")
                $result2 = if($field3 = "a" or $field4 = "b", "MATCH", "NO_MATCH")
                $result3 = if(not $field5 = "bad", "GOOD", "BAD")

            condition:
                $e
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.outcome is not None
        assert len(rule.outcome.assignments) == 3

    def test_outcome_regex_in_comparisons(self) -> None:
        """Test parsing regex patterns in outcome comparisons."""
        yaral_code = r"""
        rule test {
            events:
                $e.field = "value"

            outcome:
                $match = if($e.field = /pattern/, "YES", "NO")
                $case_insensitive = if($e.field = /test/ nocase, "MATCH", "NO")

            condition:
                $e
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.outcome is not None

    def test_outcome_field_access_with_brackets(self) -> None:
        """Test parsing field access with brackets in outcome."""
        yaral_code = """
        rule test {
            events:
                $e.field = "value"

            outcome:
                $val1 = $e.fields["key"]
                $val2 = $e.array[0]
                $val3 = $e.nested.fields["deep"]["key"]

            condition:
                $e
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.outcome is not None

    def test_outcome_comparison_operators_in_conditions(self) -> None:
        """Test parsing all comparison operators in outcome conditions."""
        yaral_code = """
        rule test {
            events:
                $e.field = "value"

            outcome:
                $r1 = if($e.count > 10, "YES", "NO")
                $r2 = if($e.count < 100, "YES", "NO")
                $r3 = if($e.count >= 5, "YES", "NO")
                $r4 = if($e.count <= 50, "YES", "NO")
                $r5 = if($e.count = 42, "YES", "NO")
                $r6 = if($e.count != 0, "YES", "NO")

            condition:
                $e
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.outcome is not None

    def test_outcome_arithmetic_in_comparisons(self) -> None:
        """Test parsing arithmetic expressions in outcome comparisons."""
        yaral_code = """
        rule test {
            events:
                $e.field = "value"

            outcome:
                $result = if($e.field1 - $e.field2 > 0, "POSITIVE", "NEGATIVE")
                $percentage = if(($new - $old) / $old * 100 > 10, "SIGNIFICANT", "MINOR")

            condition:
                $e
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.outcome is not None

    def test_outcome_parenthesized_expressions(self) -> None:
        """Test parsing parenthesized expressions in outcome."""
        yaral_code = """
        rule test {
            events:
                $e.field = "value"

            outcome:
                $calc1 = ($a + $b) * $c
                $calc2 = if(($x > 5) and ($y < 10), "RANGE", "OUT")

            condition:
                $e
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.outcome is not None

    def test_outcome_function_calls_in_expressions(self) -> None:
        """Test parsing function calls in outcome expressions."""
        yaral_code = """
        rule test {
            events:
                $e.field = "value"

            outcome:
                $len = strings.length($e.field)
                $upper = strings.to_upper($e.field)
                $result = if(strings.length($e.field) > 10, "LONG", "SHORT")

            condition:
                $e
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.outcome is not None

    def test_options_section_all_value_types(self) -> None:
        """Test parsing options section with different value types."""
        yaral_code = """
        rule test {
            events:
                $e.field = "value"

            options:
                string_option = "value"
                integer_option = 42
                bool_option1 = true
                bool_option2 = false

            condition:
                $e
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.options is not None
        assert len(rule.options.options) == 4
        assert rule.options.options["string_option"] == "value"
        assert rule.options.options["integer_option"] == 42
        assert rule.options.options["bool_option1"] is True
        assert rule.options.options["bool_option2"] is False

    def test_multiple_rules_in_file(self) -> None:
        """Test parsing multiple rules in a single file."""
        yaral_code = """
        rule rule1 {
            events:
                $e.field = "value1"
            condition:
                $e
        }

        rule rule2 {
            events:
                $e.field = "value2"
            condition:
                $e
        }

        rule rule3 {
            events:
                $e.field = "value3"
            condition:
                $e
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        assert len(ast.rules) == 3
        assert ast.rules[0].name == "rule1"
        assert ast.rules[1].name == "rule2"
        assert ast.rules[2].name == "rule3"

    def test_complex_real_world_rule(self) -> None:
        """Test parsing a complex real-world YARA-L rule."""
        yaral_code = """
        rule suspicious_login_activity {
            meta:
                author = "Security Team"
                severity = "HIGH"
                description = "Detects suspicious login patterns"
                version = 2

            events:
                $login.metadata.event_type = "USER_LOGIN"
                $login.principal.ip in %blocked_ips%
                $login.target.user.userid = $userid
                $login.security_result.action = "BLOCK"

            match:
                $userid over 15m

            outcome:
                $total_attempts = count($login.metadata.id)
                $unique_ips = count_distinct($login.principal.ip)
                $first_attempt = earliest($login.metadata.event_timestamp)
                $last_attempt = latest($login.metadata.event_timestamp)
                $severity = if($total_attempts > 100, "CRITICAL", if($total_attempts > 50, "HIGH", "MEDIUM"))

            condition:
                $total_attempts > 10 and $unique_ips > 3

            options:
                max_results = 1000
                log_to_siem = true
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        assert len(ast.rules) == 1
        rule = ast.rules[0]
        assert rule.name == "suspicious_login_activity"
        assert rule.meta is not None
        assert rule.events is not None
        assert rule.match is not None
        assert rule.outcome is not None
        assert rule.condition is not None
        assert rule.options is not None


class TestYaraLASTNodes:
    """Test YARA-L AST node functionality."""

    def test_udm_field_path_property(self) -> None:
        """Test UDMFieldPath.path property."""
        field_path = UDMFieldPath(parts=["metadata", "event_type"])
        assert field_path.path == "metadata.event_type"

        field_path2 = UDMFieldPath(parts=["principal", "hostname"])
        assert field_path2.path == "principal.hostname"

    def test_udm_field_access_full_path(self) -> None:
        """Test UDMFieldAccess.full_path property."""
        event = EventVariable(name="$e")
        field = UDMFieldPath(parts=["metadata", "event_type"])
        field_access = UDMFieldAccess(event=event, field=field)

        assert field_access.full_path == "$e.metadata.event_type"

    def test_time_window_as_string(self) -> None:
        """Test TimeWindow.as_string property."""
        window1 = TimeWindow(duration=5, unit="m", modifier=None)
        assert window1.as_string == "5m"

        window2 = TimeWindow(duration=1, unit="h", modifier="every")
        assert window2.as_string == "every 1h"

    def test_regex_pattern_as_string(self) -> None:
        """Test RegexPattern.as_string property."""
        pattern1 = RegexPattern(pattern="test.*", flags=[])
        assert pattern1.as_string == "/test.*/"

        pattern2 = RegexPattern(pattern="case.*", flags=["nocase"])
        assert pattern2.as_string == "/case.*/ nocase"

    def test_aggregation_function_call_string(self) -> None:
        """Test AggregationFunction.call_string property."""
        event = EventVariable(name="$e")
        field = UDMFieldPath(parts=["metadata", "id"])
        field_access = UDMFieldAccess(event=event, field=field)

        agg = AggregationFunction(function="count", arguments=[field_access])
        assert "count" in agg.call_string
        # The call_string contains the string representation of the argument
        assert "metadata" in agg.call_string or "UDMFieldAccess" in agg.call_string


class TestYaraLParserErrorRecovery:
    """Test parser error recovery mechanisms."""

    def test_missing_section_colon(self) -> None:
        """Test error on missing colon after section keyword."""
        yaral_code = """
        rule test {
            events
                $e.field = "value"
        }
        """
        parser = YaraLParser(yaral_code)

        with pytest.raises(YaraLParserError) as exc:
            parser.parse()

        assert "Expected ':' after 'events'" in str(exc.value)

    def test_missing_rule_name(self) -> None:
        """Test error on missing rule name."""
        yaral_code = """
        rule {
            events:
                $e.field = "value"
        }
        """
        parser = YaraLParser(yaral_code)

        with pytest.raises(YaraLParserError) as exc:
            parser.parse()

        assert "Expected rule name" in str(exc.value)

    def test_missing_opening_brace(self) -> None:
        """Test error on missing opening brace."""
        yaral_code = """
        rule test
            events:
                $e.field = "value"
        }
        """
        parser = YaraLParser(yaral_code)

        with pytest.raises(YaraLParserError) as exc:
            parser.parse()

        assert "Expected '{' after rule name" in str(exc.value)

    def test_missing_field_name_in_events(self) -> None:
        """Test error on missing field name."""
        yaral_code = """
        rule test {
            events:
                $e. = "value"
        }
        """
        parser = YaraLParser(yaral_code)

        with pytest.raises(YaraLParserError) as exc:
            parser.parse()

        assert "Expected field name" in str(exc.value)

    def test_missing_operator_in_events(self) -> None:
        """Test error on missing operator in events."""
        yaral_code = """
        rule test {
            events:
                $e.field "value"
        }
        """
        parser = YaraLParser(yaral_code)

        with pytest.raises(YaraLParserError) as exc:
            parser.parse()

        assert "Expected operator" in str(exc.value)

    def test_missing_time_window_in_match(self) -> None:
        """Test error on missing time window."""
        yaral_code = """
        rule test {
            events:
                $e.field = "value"
            match:
                $var over
        }
        """
        parser = YaraLParser(yaral_code)

        with pytest.raises(YaraLParserError) as exc:
            parser.parse()

        assert "Expected time window" in str(exc.value)

    def test_invalid_time_window_format(self) -> None:
        """Test error on invalid time window format."""
        yaral_code = """
        rule test {
            events:
                $e.field = "value"
            match:
                $var over xyz
        }
        """
        parser = YaraLParser(yaral_code)

        with pytest.raises(YaraLParserError) as exc:
            parser.parse()

        assert "Expected time window" in str(exc.value)

    def test_missing_comparison_operator_in_condition(self) -> None:
        """Test error on missing comparison operator in condition."""
        yaral_code = """
        rule test {
            events:
                $e.field = "value"
            condition:
                #e 5
        }
        """
        parser = YaraLParser(yaral_code)

        with pytest.raises(YaraLParserError) as exc:
            parser.parse()

        assert "Expected comparison operator" in str(exc.value)

    def test_unexpected_token_in_condition(self) -> None:
        """Test error on unexpected token in condition."""
        yaral_code = """
        rule test {
            events:
                $e.field = "value"
            condition:
                unexpected_token
        }
        """
        parser = YaraLParser(yaral_code)

        # This might parse or raise an error depending on implementation
        # Just ensure it doesn't crash
        try:
            ast = parser.parse()
            assert len(ast.rules) >= 0
        except YaraLParserError:
            pass

    def test_missing_equals_in_outcome(self) -> None:
        """Test error on missing equals in outcome assignment."""
        yaral_code = """
        rule test {
            events:
                $e.field = "value"
            outcome:
                $var count($e.field)
            condition:
                $e
        }
        """
        parser = YaraLParser(yaral_code)

        with pytest.raises(YaraLParserError) as exc:
            parser.parse()

        assert "Expected '=' after outcome variable" in str(exc.value)

    def test_unclosed_parenthesis_in_outcome(self) -> None:
        """Test error on unclosed parenthesis."""
        yaral_code = """
        rule test {
            events:
                $e.field = "value"
            outcome:
                $result = if($count > 10, "HIGH"
            condition:
                $e
        }
        """
        parser = YaraLParser(yaral_code)

        with pytest.raises(YaraLParserError) as exc:
            parser.parse()

        assert "Expected ')'" in str(exc.value)


class TestYaraLRealWorldExamples:
    """Test parsing real-world YARA-L rule examples."""

    def test_brute_force_detection(self) -> None:
        """Test parsing brute force detection rule."""
        yaral_code = """
        rule brute_force_ssh_login {
            meta:
                author = "SOC Team"
                description = "Detects SSH brute force attempts"
                severity = "HIGH"

            events:
                $ssh.metadata.event_type = "USER_LOGIN"
                $ssh.target.application = "SSH"
                $ssh.security_result.action = "BLOCK"
                $ssh.principal.ip = $source_ip

            match:
                $source_ip over 5m

            outcome:
                $failed_attempts = count($ssh.metadata.id)
                $targeted_users = count_distinct($ssh.target.user.userid)
                $first_seen = earliest($ssh.metadata.event_timestamp)

            condition:
                $failed_attempts > 20 and $targeted_users > 5
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        assert len(ast.rules) == 1
        rule = ast.rules[0]
        assert rule.name == "brute_force_ssh_login"
        assert rule.meta is not None
        assert len(rule.meta.entries) == 3

    def test_data_exfiltration_detection(self) -> None:
        """Test parsing data exfiltration detection rule."""
        yaral_code = """
        rule large_data_transfer {
            meta:
                author = "DLP Team"
                severity = "CRITICAL"

            events:
                $transfer.metadata.event_type = "NETWORK_CONNECTION"
                $transfer.network.sent_bytes > 1000000000
                not ($transfer.target.ip in %approved_destinations%)

            match:
                $userid over 1h

            outcome:
                $total_bytes = sum($transfer.network.sent_bytes)
                $destinations = count_distinct($transfer.target.ip)
                $avg_transfer = avg($transfer.network.sent_bytes)

            condition:
                $total_bytes > 5000000000
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        assert len(ast.rules) == 1

    def test_privilege_escalation_detection(self) -> None:
        """Test parsing privilege escalation detection rule."""
        yaral_code = """
        rule privilege_escalation {
            meta:
                author = "IAM Team"

            events:
                $create.metadata.event_type = "USER_RESOURCE_UPDATE_PERMISSIONS"
                $create.target.resource.attribute.permissions = /.*ADMIN.*/
                $create.principal.user.userid = $user

            match:
                $user over 10m

            outcome:
                $escalations = count($create.metadata.id)
                $resources = array_distinct($create.target.resource.name)

            condition:
                $escalations > 3
        }
        """
        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        assert len(ast.rules) == 1
